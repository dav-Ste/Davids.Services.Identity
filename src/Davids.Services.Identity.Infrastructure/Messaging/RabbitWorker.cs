using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using RabbitMQ.Client;
using RabbitMQ.Client.Events;
using Davids.Services.Identity.Application.Commands;
using Davids.Services.Identity.Application.Events.Rejected;
using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Core.Exceptions;
using Davids.Services.Identity.Infrastructure.Persistence;
namespace Davids.Services.Identity.Infrastructure.Messaging;
// At-least-once delivery. Consumers must deduplicate by the stable MessageId.
public sealed class RabbitWorker(IServiceScopeFactory scopes,IConfiguration configuration,ILogger<RabbitWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while(!stoppingToken.IsCancellationRequested)
        {
            try { await RunAsync(stoppingToken); }
            catch(OperationCanceledException) when(stoppingToken.IsCancellationRequested) { break; }
            catch(Exception ex) { logger.LogError(ex,"RabbitMQ worker disconnected; retrying."); await Task.Delay(TimeSpan.FromSeconds(5),stoppingToken); }
        }
    }
    private async Task RunAsync(CancellationToken ct)
    {
        var factory=new ConnectionFactory {Uri=new Uri(configuration.GetConnectionString("messaging") ?? throw new InvalidOperationException("Missing messaging connection."))};
        await using var connection=await factory.CreateConnectionAsync(ct);
        await using var publisher=await connection.CreateChannelAsync(new CreateChannelOptions(publisherConfirmationsEnabled:true,publisherConfirmationTrackingEnabled:true),ct);
        await using var consumerChannel=await connection.CreateChannelAsync(cancellationToken:ct);
        await publisher.ExchangeDeclareAsync("identity",ExchangeType.Topic,true,false,cancellationToken:ct);
        await consumerChannel.ExchangeDeclareAsync("identity.dead",ExchangeType.Topic,true,false,cancellationToken:ct);
        await consumerChannel.QueueDeclareAsync("identity-service.dead",true,false,false,cancellationToken:ct);
        await consumerChannel.QueueBindAsync("identity-service.dead","identity.dead","#",cancellationToken:ct);
        await consumerChannel.QueueDeclareAsync("identity-service/identity.sign_up",true,false,false,
            new Dictionary<string,object?> { ["x-dead-letter-exchange"]="identity.dead" },cancellationToken:ct);
        await consumerChannel.QueueBindAsync("identity-service/identity.sign_up","identity","sign_up",cancellationToken:ct);
        await consumerChannel.BasicQosAsync(0,1,false,ct);
        var consumer=new AsyncEventingBasicConsumer(consumerChannel);
        consumer.ReceivedAsync+=async (_,e)=>
        {
            try
            {
                var id=e.BasicProperties.MessageId;
                if(string.IsNullOrWhiteSpace(id)||id.Length>128) throw new InvalidDataException("A stable MessageId (max 128 characters) is required.");
                using var scope=scopes.CreateScope();
                var db=scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
                await using var tx=await db.Database.BeginTransactionAsync(ct);
                if(!await db.Inbox.AnyAsync(x=>x.Id==id,ct))
                {
                    var command=JsonSerializer.Deserialize<SignUp>(e.Body.Span,MessageBroker.JsonOptions) ?? throw new InvalidDataException("Missing command.");
                    try { await scope.ServiceProvider.GetRequiredService<IIdentityService>().SignUpAsync(command); }
                    catch(DomainException ex)
                    {
                        await scope.ServiceProvider.GetRequiredService<IMessageBroker>().PublishAsync(new SignUpRejected(command.Email,ex.Message,ex.Code));
                    }
                    db.Inbox.Add(new InboxMessage {Id=id,ReceivedAt=DateTime.UtcNow});
                    await db.SaveChangesAsync(ct);
                }
                await tx.CommitAsync(ct);
                await consumerChannel.BasicAckAsync(e.DeliveryTag,false,ct);
            }
            catch(Exception ex)
            {
                logger.LogError(ex,"Sign-up command failed; routing to dead-letter queue.");
                await consumerChannel.BasicNackAsync(e.DeliveryTag,false,false,ct);
            }
        };
        await consumerChannel.BasicConsumeAsync("identity-service/identity.sign_up",false,consumer,ct);
        while(!ct.IsCancellationRequested)
        {
            using var scope=scopes.CreateScope();
            var db=scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var messages=await db.Outbox.Where(x=>x.PublishedAt==null).OrderBy(x=>x.CreatedAt).Take(100).ToListAsync(ct);
            foreach(var m in messages)
            {
                var properties=new BasicProperties {Persistent=true,MessageId=m.Id.ToString(),ContentType="application/json",Type=m.Type};
                // Exchange consumers are provisioned separately; unrouted events remain valid publications.
                await publisher.BasicPublishAsync("identity",m.Type,false,properties,Encoding.UTF8.GetBytes(m.Payload),ct);
                m.PublishedAt=DateTime.UtcNow;
                await db.SaveChangesAsync(ct);
            }
            await Task.Delay(TimeSpan.FromSeconds(1),ct);
        }
    }
}
