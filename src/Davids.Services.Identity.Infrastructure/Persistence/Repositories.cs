using System.Text.Json;
using Davids.Services.Identity.Core.Entities;
using Davids.Services.Identity.Core.Repositories;
using Davids.Services.Identity.Infrastructure.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Davids.Services.Identity.Infrastructure.Persistence;

public sealed class UserRepository(IdentityDbContext db) : IUserRepository
{
    public async Task<User?> GetAsync(Guid id)
        => Map(await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id));

    public async Task<User?> GetAsync(string email)
    {
        var normalized = email.ToLowerInvariant();
        return Map(await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Email == normalized));
    }

    public async Task AddAsync(User u)
    {
        db.Users.Add(new UserRow
        {
            Id = u.Id,
            Email = u.Email,
            Password = u.Password,
            Role = u.Role,
            CreatedAt = u.CreatedAt,
            PermissionsJson = JsonSerializer.Serialize(u.Permissions),
            FailedLoginCount = u.FailedLoginCount,
            LockoutEndUtc = u.LockoutEndUtc
        });
        await db.SaveChangesAsync();
    }

    public async Task UpdateAsync(User u)
    {
        var row = await db.Users.SingleOrDefaultAsync(x => x.Id == u.Id)
            ?? throw new InvalidOperationException($"User '{u.Id}' was not found.");
        row.FailedLoginCount = u.FailedLoginCount;
        row.LockoutEndUtc = u.LockoutEndUtc;
        await db.SaveChangesAsync();
    }

    private static User? Map(UserRow? u)
        => u is null
            ? null
            : new User(
                u.Id,
                u.Email,
                u.Password,
                u.Role,
                DateTime.SpecifyKind(u.CreatedAt, DateTimeKind.Utc),
                JsonSerializer.Deserialize<string[]>(u.PermissionsJson),
                u.FailedLoginCount,
                u.LockoutEndUtc.HasValue ? DateTime.SpecifyKind(u.LockoutEndUtc.Value, DateTimeKind.Utc) : null);
}

public sealed class LoginAuditRepository(
    IdentityDbContext db,
    ILoggerFactory? loggerFactory = null) : ILoginAuditRepository
{
    public async Task AddAsync(LoginAuditEntry entry)
    {
        db.CustomerLoginAuditLogs.Add(new CustomerLoginAuditLogRow
        {
            Id = entry.Id,
            OccurredAtUtc = entry.OccurredAtUtc,
            UserId = entry.UserId,
            Email = entry.Email,
            Succeeded = entry.Succeeded,
            Outcome = entry.Outcome,
            FailureReason = entry.FailureReason,
            ClientId = entry.ClientId,
            ClientIpAddress = entry.ClientIpAddress,
            UserAgent = entry.UserAgent,
            CorrelationId = entry.CorrelationId
        });
        await db.SaveChangesAsync();

        IdentitySecurityMetrics.RecordLoginAudit(entry.Outcome, entry.Succeeded);
        var auditLogger = loggerFactory?.CreateLogger("Davids.Security.Audit");
        if (entry.Succeeded)
        {
            auditLogger?.LogInformation(
                "Audit: recorded {AuthDomain} login outcome {Outcome} (Succeeded={Succeeded}, SecurityAuditEvent={SecurityAuditEvent}, ClientId={ClientId}, ClientIp={ClientIp}, CorrelationId={CorrelationId}).",
                "customer",
                entry.Outcome,
                true,
                "LoginAudit",
                entry.ClientId ?? "unknown",
                entry.ClientIpAddress ?? "unknown",
                entry.CorrelationId ?? "none");
        }
        else
        {
            auditLogger?.LogWarning(
                "Audit: recorded {AuthDomain} login failure {Outcome} (Succeeded={Succeeded}, SecurityAuditEvent={SecurityAuditEvent}, ClientId={ClientId}, ClientIp={ClientIp}, CorrelationId={CorrelationId}).",
                "customer",
                entry.Outcome,
                false,
                "LoginAudit",
                entry.ClientId ?? "unknown",
                entry.ClientIpAddress ?? "unknown",
                entry.CorrelationId ?? "none");
        }
    }

    public async Task<IReadOnlyList<LoginAuditEntry>> BrowseForUserAsync(Guid userId, int limit = 50)
    {
        var clamped = Math.Clamp(limit, 1, 200);
        var rows = await db.CustomerLoginAuditLogs.AsNoTracking()
            .Where(x => x.UserId == userId)
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(clamped)
            .ToListAsync();

        return rows.Select(Map).ToArray();
    }

    private static LoginAuditEntry Map(CustomerLoginAuditLogRow row)
        => new(
            row.Id,
            DateTime.SpecifyKind(row.OccurredAtUtc, DateTimeKind.Utc),
            row.UserId,
            row.Email,
            row.Succeeded,
            row.Outcome,
            row.FailureReason,
            row.ClientId,
            row.ClientIpAddress,
            row.UserAgent,
            row.CorrelationId);
}
