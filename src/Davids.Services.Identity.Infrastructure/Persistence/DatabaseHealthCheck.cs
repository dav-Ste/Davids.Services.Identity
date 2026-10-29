using Microsoft.Extensions.Diagnostics.HealthChecks;
namespace Davids.Services.Identity.Infrastructure.Persistence;
public sealed class DatabaseHealthCheck(IdentityDbContext db) : IHealthCheck
{
    public async Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context,CancellationToken cancellationToken=default)
    {
        try
        {
            return await db.Database.CanConnectAsync(cancellationToken)
                ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy("Identity database is unavailable.");
        }
        catch (OperationCanceledException)
        {
            return HealthCheckResult.Unhealthy("Health check canceled.");
        }
    }
}
