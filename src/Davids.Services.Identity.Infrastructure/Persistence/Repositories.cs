using System.Text.Json;
using Davids.Services.Identity.Core.Entities;
using Davids.Services.Identity.Core.Repositories;
using Davids.Services.Identity.Infrastructure.Auth;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Davids.Services.Identity.Infrastructure.Persistence;

public sealed class UserRepository(
    IdentityDbContext db,
    ILoggerFactory? loggerFactory = null) : IUserRepository
{
    public async Task<User?> GetAsync(Guid id)
        => Map(await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Id == id));

    public async Task<User?> GetAsync(string email)
    {
        var normalized = email.ToLowerInvariant();
        return Map(await db.Users.AsNoTracking().SingleOrDefaultAsync(x => x.Email == normalized));
    }

    public async Task AddAsync(User u, CustomerChangeAuditEntry? changeAudit = null)
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
        if (changeAudit is not null)
        {
            db.CustomerChangeAuditLogs.Add(ToRow(changeAudit));
        }

        await db.SaveChangesAsync();
        EmitChangeAuditTelemetry(changeAudit);
    }

    public async Task UpdateAsync(User u, CustomerChangeAuditEntry? changeAudit = null)
    {
        var row = await db.Users.SingleOrDefaultAsync(x => x.Id == u.Id.Value)
            ?? throw new InvalidOperationException($"User '{u.Id}' was not found.");
        row.Email = u.Email;
        row.Password = u.Password;
        row.FailedLoginCount = u.FailedLoginCount;
        row.LockoutEndUtc = u.LockoutEndUtc;
        if (changeAudit is not null)
        {
            db.CustomerChangeAuditLogs.Add(ToRow(changeAudit));
        }

        await db.SaveChangesAsync();
        EmitChangeAuditTelemetry(changeAudit);
    }

    private void EmitChangeAuditTelemetry(CustomerChangeAuditEntry? entry)
    {
        if (entry is null)
        {
            return;
        }

        IdentitySecurityMetrics.RecordChangeAudit(entry.Action, entry.ActorAuthority);
        loggerFactory?.CreateLogger("Davids.Security.Audit").LogInformation(
            "Audit: recorded customer-identity change {Action} on {TargetUserId} by {ActorAuthority} {ActorSub} (ActorRole={ActorRole}, SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
            entry.Action,
            entry.TargetUserId,
            entry.ActorAuthority,
            entry.ActorSub,
            entry.ActorRole,
            "ChangeAudit",
            entry.CorrelationId ?? "none");
    }

    private static CustomerChangeAuditLogRow ToRow(CustomerChangeAuditEntry entry)
        => new()
        {
            Id = entry.Id,
            OccurredAtUtc = entry.OccurredAtUtc,
            TargetUserId = entry.TargetUserId,
            TargetEmail = entry.TargetEmail,
            Action = entry.Action,
            ActorSub = entry.ActorSub,
            ActorEmail = entry.ActorEmail,
            ActorRole = entry.ActorRole,
            ActorAuthority = entry.ActorAuthority,
            ChangedFieldsJson = entry.ChangedFieldsJson,
            CorrelationId = entry.CorrelationId
        };

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

public sealed class CustomerChangeAuditRepository(IdentityDbContext db) : ICustomerChangeAuditRepository
{
    public Task<IReadOnlyList<CustomerChangeAuditEntry>> BrowseForUserAsync(Guid targetUserId, int limit = 50)
        => BrowseRecentAsync(limit, targetUserId, actorSub: null);

    public async Task<IReadOnlyList<CustomerChangeAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        Guid? targetUserId = null,
        string? actorSub = null)
    {
        var clamped = Math.Clamp(limit, 1, 500);
        IQueryable<CustomerChangeAuditLogRow> query = db.CustomerChangeAuditLogs.AsNoTracking();

        if (targetUserId.HasValue)
        {
            query = query.Where(x => x.TargetUserId == targetUserId.Value);
        }

        if (!string.IsNullOrWhiteSpace(actorSub))
        {
            var trimmed = actorSub.Trim();
            query = query.Where(x => x.ActorSub == trimmed);
        }

        var rows = await query
            .OrderByDescending(x => x.OccurredAtUtc)
            .ThenByDescending(x => x.Id)
            .Take(clamped)
            .ToListAsync();

        return rows.Select(row => new CustomerChangeAuditEntry(
            row.Id,
            DateTime.SpecifyKind(row.OccurredAtUtc, DateTimeKind.Utc),
            row.TargetUserId,
            row.TargetEmail,
            row.Action,
            row.ActorSub,
            row.ActorEmail,
            row.ActorRole,
            row.ActorAuthority,
            row.ChangedFieldsJson,
            row.CorrelationId)).ToArray();
    }
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
