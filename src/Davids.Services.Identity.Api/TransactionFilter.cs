using Microsoft.EntityFrameworkCore;
using Davids.Services.Identity.Infrastructure.Persistence;
namespace Davids.Services.Identity.Api;
public sealed class TransactionFilter : IEndpointFilter
{
    public async ValueTask<object?> InvokeAsync(EndpointFilterInvocationContext context,EndpointFilterDelegate next)
    {
        var db=context.HttpContext.RequestServices.GetRequiredService<IdentityDbContext>();
        await using var tx=await db.Database.BeginTransactionAsync(context.HttpContext.RequestAborted);
        var result=await next(context);
        await tx.CommitAsync(context.HttpContext.RequestAborted);
        return result;
    }
}
