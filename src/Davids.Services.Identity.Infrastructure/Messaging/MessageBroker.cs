using System.Text.Json;
using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Infrastructure.Persistence;
namespace Davids.Services.Identity.Infrastructure.Messaging;
public sealed class MessageBroker(IdentityDbContext db) : IMessageBroker
{
    public static readonly JsonSerializerOptions JsonOptions=new(JsonSerializerDefaults.Web);
    public async Task PublishAsync(params object[] events)
    {
        foreach(var e in events)
            db.Outbox.Add(new OutboxMessage {Id=Guid.NewGuid(),Type=JsonNamingPolicy.SnakeCaseLower.ConvertName(e.GetType().Name),Payload=JsonSerializer.Serialize(e,e.GetType(),JsonOptions),CreatedAt=DateTime.UtcNow});
        await db.SaveChangesAsync();
    }
}
