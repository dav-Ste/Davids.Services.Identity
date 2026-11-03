using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OpenIddict.Abstractions;
using StackExchange.Redis;

namespace Davids.Services.Identity.Infrastructure.Auth;

public interface IRevocationCache
{
    Task<bool> ContainsAsync(string id);
    Task AddAsync(string id, DateTime expiresAt);
}

public sealed class NoRevocationCache : IRevocationCache
{
    public Task<bool> ContainsAsync(string id) => Task.FromResult(false);
    public Task AddAsync(string id, DateTime expiresAt) => Task.CompletedTask;
}

// Cache only positive revocations. A cache miss or outage always falls back to SQL.
public sealed class RedisRevocationCache(IConnectionMultiplexer redis, ILogger<RedisRevocationCache> logger) : IRevocationCache
{
    private const string Prefix = "davids:identity:revoked:";

    public async Task<bool> ContainsAsync(string id)
    {
        try
        {
            return await redis.GetDatabase().KeyExistsAsync(Prefix + id);
        }
        catch (RedisException ex)
        {
            logger.LogWarning(ex, "Redis unavailable; checking SQL revocation store.");
            return false;
        }
    }

    public async Task AddAsync(string id, DateTime expiresAt)
    {
        var ttl = expiresAt.ToUniversalTime().AddMinutes(1) - DateTime.UtcNow;
        if (ttl <= TimeSpan.Zero)
        {
            return;
        }

        try
        {
            await redis.GetDatabase().StringSetAsync(Prefix + id, "1", ttl);
        }
        catch (RedisException ex)
        {
            logger.LogWarning(ex, "Could not cache revoked token. SQL remains authoritative.");
        }
    }
}

public sealed class RevocationStore(
    IdentityDbContext db,
    IRevocationCache cache,
    IOpenIddictTokenManager? tokenManager = null,
    IOpenIddictAuthorizationManager? authorizationManager = null) : ICustomerTokenRevocationService
{
    public async Task<bool> IsRevokedAsync(
        string? id,
        CancellationToken ct = default,
        string? openIddictTokenId = null,
        DateTime? tokenExpiresAtUtc = null)
    {
        if (string.IsNullOrWhiteSpace(id))
        {
            return true;
        }

        if (await cache.ContainsAsync(id))
        {
            return true;
        }

        var revoked = await db.RevokedAccessTokens.AsNoTracking().SingleOrDefaultAsync(x => x.TokenId == id, ct);
        if (revoked is not null)
        {
            await cache.AddAsync(id, revoked.ExpiresAt);
            return true;
        }

        if (!string.IsNullOrWhiteSpace(openIddictTokenId) && tokenManager is not null)
        {
            var oidcToken = await tokenManager.FindByIdAsync(openIddictTokenId, ct);
            if (oidcToken is not null)
            {
                var status = await tokenManager.GetStatusAsync(oidcToken, ct);
                if (!string.Equals(status, OpenIddictConstants.Statuses.Valid, StringComparison.OrdinalIgnoreCase))
                {
                    var expiresAt = tokenExpiresAtUtc is { } exp && exp > DateTime.UtcNow
                        ? exp
                        : DateTime.UtcNow.AddMinutes(60);
                    if (!await db.RevokedAccessTokens.AnyAsync(x => x.TokenId == id, ct))
                    {
                        db.RevokedAccessTokens.Add(new RevokedAccessToken
                        {
                            TokenId = id,
                            ExpiresAt = expiresAt
                        });
                        await db.SaveChangesAsync(ct);
                    }

                    await cache.AddAsync(id, expiresAt);
                    IdentitySecurityMetrics.RecordTokenRevocation("replay_cascade");
                    return true;
                }
            }
        }

        return false;
    }

    public async Task RevokeAllForSubjectAsync(
        Guid userId,
        string? currentAccessTokenJti = null,
        DateTime? currentAccessTokenExpiresAtUtc = null,
        CancellationToken cancellationToken = default)
    {
        var subjects = new[] { userId.ToString("N"), userId.ToString("D") };

        if (tokenManager is not null)
        {
            foreach (var sub in subjects)
            {
                await foreach (var token in tokenManager.FindBySubjectAsync(sub, cancellationToken))
                {
                    await tokenManager.TryRevokeAsync(token, cancellationToken);
                }
            }
        }

        if (authorizationManager is not null)
        {
            foreach (var sub in subjects)
            {
                await foreach (var authorization in authorizationManager.FindBySubjectAsync(sub, cancellationToken))
                {
                    await authorizationManager.TryRevokeAsync(authorization, cancellationToken);
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(currentAccessTokenJti))
        {
            var expiresAt = currentAccessTokenExpiresAtUtc is { } exp && exp > DateTime.UtcNow
                ? exp
                : DateTime.UtcNow.AddMinutes(60);
            if (!await db.RevokedAccessTokens.AnyAsync(x => x.TokenId == currentAccessTokenJti, cancellationToken))
            {
                db.RevokedAccessTokens.Add(new RevokedAccessToken
                {
                    TokenId = currentAccessTokenJti,
                    ExpiresAt = expiresAt
                });
                await db.SaveChangesAsync(cancellationToken);
            }

            await cache.AddAsync(currentAccessTokenJti, expiresAt);
            IdentitySecurityMetrics.RecordTokenRevocation("credential_change");
        }
    }
}
