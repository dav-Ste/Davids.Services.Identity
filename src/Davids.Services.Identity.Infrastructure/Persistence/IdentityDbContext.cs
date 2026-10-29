using Microsoft.EntityFrameworkCore;

namespace Davids.Services.Identity.Infrastructure.Persistence;

public sealed class IdentityDbContext(DbContextOptions<IdentityDbContext> options) : DbContext(options)
{
    public DbSet<UserRow> Users => Set<UserRow>();
    public DbSet<RevokedAccessToken> RevokedAccessTokens => Set<RevokedAccessToken>();
    public DbSet<IdentityDataProtectionKeyRow> DataProtectionKeys => Set<IdentityDataProtectionKeyRow>();
    public DbSet<CustomerLoginAuditLogRow> CustomerLoginAuditLogs => Set<CustomerLoginAuditLogRow>();
    public DbSet<OutboxMessage> Outbox => Set<OutboxMessage>();
    public DbSet<InboxMessage> Inbox => Set<InboxMessage>();

    protected override void OnModelCreating(ModelBuilder b)
    {
        base.OnModelCreating(b);
        b.UseOpenIddict();

        b.Entity<UserRow>().HasKey(x => x.Id);
        b.Entity<UserRow>().Property(x => x.Email).HasMaxLength(320);
        b.Entity<UserRow>().HasIndex(x => x.Email).IsUnique();
        b.Entity<UserRow>().Property(x => x.FailedLoginCount).HasDefaultValue(0);

        b.Entity<RevokedAccessToken>().HasKey(x => x.TokenId);
        b.Entity<RevokedAccessToken>().Property(x => x.TokenId).HasMaxLength(64);

        b.Entity<IdentityDataProtectionKeyRow>(entity =>
        {
            entity.ToTable("DataProtectionKeys");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.FriendlyName).HasMaxLength(256);
            entity.Property(x => x.Xml).IsRequired();
            entity.HasIndex(x => x.FriendlyName);
        });

        b.Entity<CustomerLoginAuditLogRow>(entity =>
        {
            entity.ToTable("CustomerLoginAuditLogs");
            entity.HasKey(x => x.Id);
            entity.Property(x => x.Email).IsRequired().HasMaxLength(320);
            entity.Property(x => x.Outcome).IsRequired().HasMaxLength(64);
            entity.Property(x => x.FailureReason).HasMaxLength(256);
            entity.Property(x => x.ClientId).HasMaxLength(128);
            entity.Property(x => x.ClientIpAddress).HasMaxLength(64);
            entity.Property(x => x.UserAgent).HasMaxLength(512);
            entity.Property(x => x.CorrelationId).HasMaxLength(128);
            entity.HasIndex(x => x.OccurredAtUtc);
            entity.HasIndex(x => new { x.Email, x.OccurredAtUtc });
            entity.HasIndex(x => new { x.UserId, x.OccurredAtUtc });
        });

        b.Entity<OutboxMessage>().HasKey(x => x.Id);
        b.Entity<OutboxMessage>().HasIndex(x => x.PublishedAt);

        b.Entity<InboxMessage>().HasKey(x => x.Id);
        b.Entity<InboxMessage>().Property(x => x.Id).HasMaxLength(128);
    }
}

public sealed class UserRow
{
    public Guid Id { get; set; }
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Role { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public string PermissionsJson { get; set; } = "[]";
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEndUtc { get; set; }
}

public sealed class RevokedAccessToken
{
    public string TokenId { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
}

public sealed class IdentityDataProtectionKeyRow
{
    public int Id { get; set; }
    public string? FriendlyName { get; set; }
    public string Xml { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; }
}

public sealed class CustomerLoginAuditLogRow
{
    public Guid Id { get; set; }
    public DateTime OccurredAtUtc { get; set; }
    public Guid? UserId { get; set; }
    public string Email { get; set; } = string.Empty;
    public bool Succeeded { get; set; }
    public string Outcome { get; set; } = string.Empty;
    public string? FailureReason { get; set; }
    public string? ClientId { get; set; }
    public string? ClientIpAddress { get; set; }
    public string? UserAgent { get; set; }
    public string? CorrelationId { get; set; }
}

public sealed class OutboxMessage
{
    public Guid Id { get; set; }
    public string Type { get; set; } = string.Empty;
    public string Payload { get; set; } = string.Empty;
    public DateTime CreatedAt { get; set; }
    public DateTime? PublishedAt { get; set; }
}

public sealed class InboxMessage
{
    public string Id { get; set; } = string.Empty;
    public DateTime ReceivedAt { get; set; }
}
