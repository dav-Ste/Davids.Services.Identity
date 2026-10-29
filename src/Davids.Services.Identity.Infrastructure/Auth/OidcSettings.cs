using System.IdentityModel.Tokens.Jwt;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.Identity.Infrastructure.Auth;

public sealed class OidcSettings
{
    public string? Issuer { get; set; }
    public string Audience { get; set; } = "davids-services";
    public string ClientId { get; set; } = "davids-web";
    public int AccessTokenLifetimeMinutes { get; set; } = 60;
    public int RefreshTokenLifetimeDays { get; set; } = 14;
    public string? SigningKeyPem { get; set; }
    public string? EncryptionKeyPem { get; set; }
    public string[] AllowedRedirectUris { get; set; } =
    [
        "https://localhost/callback",
        "http://localhost/callback"
    ];
    public string[] AllowedPostLogoutRedirectUris { get; set; } =
    [
        "https://localhost/",
        "http://localhost/"
    ];

    public RsaSecurityKey PrivateSigningKey { get; private set; } = null!;
    public RsaSecurityKey PublicSigningSecurityKey { get; private set; } = null!;
    public RsaSecurityKey EncryptionSecurityKey { get; private set; } = null!;

    public Uri? NormalizedIssuerUri
        => string.IsNullOrWhiteSpace(Issuer)
            ? null
            : new Uri(Issuer.TrimEnd('/') + "/", UriKind.Absolute);

    public void InitializeKeys(bool requireExplicitEncryptionKey)
    {
        if (string.IsNullOrWhiteSpace(Audience) ||
            string.IsNullOrWhiteSpace(ClientId) ||
            AccessTokenLifetimeMinutes <= 0 ||
            RefreshTokenLifetimeDays <= 0)
        {
            throw new InvalidOperationException("Invalid Customer Identity OIDC configuration.");
        }

        if (!string.IsNullOrWhiteSpace(Issuer) &&
            (!Uri.TryCreate(Issuer, UriKind.Absolute, out var issuerUri) ||
             (issuerUri.Scheme != Uri.UriSchemeHttp && issuerUri.Scheme != Uri.UriSchemeHttps)))
        {
            throw new InvalidOperationException("Oidc:Issuer must be a valid absolute HTTP(S) URI when configured.");
        }

        if (string.IsNullOrWhiteSpace(SigningKeyPem))
        {
            throw new InvalidOperationException(
                "Oidc:SigningKeyPem (2048-bit+ RSA private key) is required. Configure it via user-secrets or Vault.");
        }

        var signingParams = LoadRsaParameters(SigningKeyPem, "Oidc:SigningKeyPem");
        var signingKeyId = ComputeKeyId(signingParams);
        PrivateSigningKey = new RsaSecurityKey(signingParams) { KeyId = signingKeyId };
        PublicSigningSecurityKey = new RsaSecurityKey(new RSAParameters
        {
            Modulus = signingParams.Modulus,
            Exponent = signingParams.Exponent
        })
        {
            KeyId = signingKeyId
        };

        RSAParameters encParams;
        if (!string.IsNullOrWhiteSpace(EncryptionKeyPem))
        {
            encParams = LoadRsaParameters(EncryptionKeyPem, "Oidc:EncryptionKeyPem");
        }
        else if (!requireExplicitEncryptionKey)
        {
            using var generated = RSA.Create(2048);
            encParams = generated.ExportParameters(includePrivateParameters: true);
        }
        else
        {
            throw new InvalidOperationException(
                "Oidc:EncryptionKeyPem (2048-bit+ RSA private key) is required in Production.");
        }

        EncryptionSecurityKey = new RsaSecurityKey(encParams)
        {
            KeyId = "enc-" + ComputeKeyId(encParams)
        };
    }

    public TokenValidationParameters CreateValidationParameters(bool validateLifetime = true)
    {
        var issuerUri = NormalizedIssuerUri;
        return new TokenValidationParameters
        {
            ValidateIssuer = issuerUri is not null,
            ValidIssuer = issuerUri?.AbsoluteUri,
            ValidateAudience = true,
            ValidAudience = Audience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = PublicSigningSecurityKey,
            ValidateLifetime = validateLifetime,
            RequireExpirationTime = true,
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
            ClockSkew = TimeSpan.FromSeconds(30),
            NameClaimType = Claims.Subject,
            RoleClaimType = Claims.Role
        };
    }

    public static string GenerateRsaPrivateKeyPem(int keySizeInBits = 2048)
    {
        using var rsa = RSA.Create(keySizeInBits);
        return rsa.ExportPkcs8PrivateKeyPem();
    }

    private static RSAParameters LoadRsaParameters(string value, string settingName)
    {
        using var rsa = RSA.Create();
        var trimmed = value.Trim();
        try
        {
            if (trimmed.Contains("-----BEGIN", StringComparison.Ordinal))
            {
                rsa.ImportFromPem(trimmed);
            }
            else
            {
                var raw = Convert.FromBase64String(trimmed);
                rsa.ImportPkcs8PrivateKey(raw, out _);
            }
        }
        catch (Exception ex) when (ex is CryptographicException or FormatException)
        {
            throw new InvalidOperationException($"{settingName} is not a valid RSA private key.", ex);
        }

        if (rsa.KeySize < 2048)
        {
            throw new InvalidOperationException($"{settingName} must be at least 2048 bits.");
        }

        return rsa.ExportParameters(includePrivateParameters: true);
    }

    private static string ComputeKeyId(RSAParameters parameters)
    {
        using var pub = RSA.Create();
        pub.ImportParameters(new RSAParameters
        {
            Modulus = parameters.Modulus,
            Exponent = parameters.Exponent
        });
        var spki = pub.ExportSubjectPublicKeyInfo();
        var hash = SHA256.HashData(spki);
        return Base64UrlEncoder.Encode(hash)[..16];
    }
}

public sealed class PasswordService : IPasswordService
{
    private readonly PasswordHasher<PasswordService> hasher = new();
    public string Hash(string password) => hasher.HashPassword(this, password);
    public bool IsValid(string hash, string password)
        => hasher.VerifyHashedPassword(this, hash, password) != PasswordVerificationResult.Failed;
}

public sealed class OidcLoginStateProtector(IDataProtectionProvider dataProtectionProvider)
{
    private readonly IDataProtector protector =
        dataProtectionProvider.CreateProtector("Davids.Services.Identity.OidcAuthorizeForm.v1");

    private sealed record Payload(
        string ClientId,
        string RedirectUri,
        string CodeChallenge,
        string State,
        long ExpiresUnixSeconds);

    public string Protect(string? clientId, string? redirectUri, string? codeChallenge, string? state)
    {
        var json = JsonSerializer.Serialize(new Payload(
            clientId ?? string.Empty,
            redirectUri ?? string.Empty,
            codeChallenge ?? string.Empty,
            state ?? string.Empty,
            DateTimeOffset.UtcNow.AddMinutes(10).ToUnixTimeSeconds()));
        return protector.Protect(json);
    }

    public bool TryValidate(
        string? token,
        string? clientId,
        string? redirectUri,
        string? codeChallenge,
        string? state)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            return false;
        }

        try
        {
            var json = protector.Unprotect(token);
            var payload = JsonSerializer.Deserialize<Payload>(json);
            if (payload is null || payload.ExpiresUnixSeconds < DateTimeOffset.UtcNow.ToUnixTimeSeconds())
            {
                return false;
            }

            return string.Equals(payload.ClientId, clientId ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(payload.RedirectUri, redirectUri ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(payload.CodeChallenge, codeChallenge ?? string.Empty, StringComparison.Ordinal) &&
                   string.Equals(payload.State, state ?? string.Empty, StringComparison.Ordinal);
        }
        catch (CryptographicException)
        {
            return false;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

public sealed class OidcRevocationSyncHandler(
    IServiceProvider serviceProvider,
    OidcSettings oidcSettings,
    IRevocationCache revocationCache)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyRevocationResponseContext>
{
    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ApplyRevocationResponseContext>()
            .UseSingletonHandler<OidcRevocationSyncHandler>()
            .SetOrder(int.MinValue + 100)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.ApplyRevocationResponseContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Request?.Token))
        {
            return;
        }

        // Only skip denylist synchronization when client authentication/authorization failed.
        // If OpenIddict flagged invalid_token (e.g., already marked non-valid after an auth-code replay),
        // we still persist the RS256 access_token JTI into RevokedAccessTokens + Redis.
        if (!string.IsNullOrEmpty(context.Error) &&
            !string.Equals(context.Error, Errors.InvalidToken, StringComparison.Ordinal))
        {
            return;
        }

        var handler = new JwtSecurityTokenHandler { MapInboundClaims = false };
        if (!handler.CanReadToken(context.Request.Token))
        {
            return;
        }

        try
        {
            handler.ValidateToken(
                context.Request.Token,
                oidcSettings.CreateValidationParameters(validateLifetime: false),
                out var validated);

            if (validated is not JwtSecurityToken jwt || string.IsNullOrWhiteSpace(jwt.Id))
            {
                return;
            }

            var expiresAt = jwt.ValidTo > DateTime.UtcNow ? jwt.ValidTo : DateTime.UtcNow.AddMinutes(5);
            await using var scope = serviceProvider.CreateAsyncScope();
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            if (!await db.RevokedAccessTokens.AnyAsync(x => x.TokenId == jwt.Id, context.CancellationToken))
            {
                db.RevokedAccessTokens.Add(new RevokedAccessToken
                {
                    TokenId = jwt.Id,
                    ExpiresAt = expiresAt
                });
                await db.SaveChangesAsync(context.CancellationToken);
            }

            await revocationCache.AddAsync(jwt.Id, expiresAt);
            IdentitySecurityMetrics.RecordTokenRevocation("rfc7009_revocation");
        }
        catch (SecurityTokenException)
        {
            // Token was an encrypted JWE refresh token rather than an RS256 access token; OpenIddict already revoked it in DB.
        }
    }
}

public sealed class OidcTokenErrorAuditHandler(IServiceProvider serviceProvider)
    : IOpenIddictServerHandler<OpenIddictServerEvents.ApplyTokenResponseContext>
{
    public const string AuditRecordedItemKey = "Davids.CustomerTokenAuditRecorded";

    public static OpenIddictServerHandlerDescriptor Descriptor { get; } =
        OpenIddictServerHandlerDescriptor.CreateBuilder<OpenIddictServerEvents.ApplyTokenResponseContext>()
            .UseSingletonHandler<OidcTokenErrorAuditHandler>()
            .SetOrder(int.MinValue + 100)
            .Build();

    public async ValueTask HandleAsync(OpenIddictServerEvents.ApplyTokenResponseContext context)
    {
        if (string.IsNullOrEmpty(context.Error))
        {
            return;
        }

        var httpContext = Microsoft.AspNetCore.OpenIddictServerAspNetCoreHelpers.GetHttpRequest(context.Transaction)?.HttpContext;
        if (httpContext?.Items.ContainsKey(AuditRecordedItemKey) == true)
        {
            return;
        }

        var ip = httpContext?.Connection.RemoteIpAddress;
        var clientIp = ip is null
            ? null
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        var correlationId = httpContext?.Request.Headers["X-Correlation-ID"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = httpContext?.TraceIdentifier;
        }

        var errorDescription = context.Response?.ErrorDescription;
        var entry = new Davids.Services.Identity.Core.Entities.LoginAuditEntry(
            Guid.NewGuid(),
            DateTime.UtcNow,
            userId: null,
            email: "[token-endpoint]",
            succeeded: false,
            outcome: "token_grant_rejected",
            failureReason: string.IsNullOrWhiteSpace(errorDescription)
                ? $"Token grant failed ({context.Error})."
                : $"{context.Error}: {errorDescription}",
            clientId: context.Request?.ClientId,
            clientIpAddress: clientIp,
            userAgent: httpContext?.Request.Headers.UserAgent.ToString(),
            correlationId: correlationId);

        await using var scope = serviceProvider.CreateAsyncScope();
        var repo = scope.ServiceProvider.GetRequiredService<Davids.Services.Identity.Core.Repositories.ILoginAuditRepository>();
        await repo.AddAsync(entry);
    }
}

public sealed class OidcApplicationSeeder(IServiceProvider serviceProvider, OidcSettings settings)
{
    private readonly SemaphoreSlim gate = new(1, 1);
    private volatile bool seeded;

    public async Task EnsureSeededAsync(CancellationToken cancellationToken = default)
    {
        if (seeded)
        {
            return;
        }

        await gate.WaitAsync(cancellationToken);
        try
        {
            if (seeded)
            {
                return;
            }

            await using var scope = serviceProvider.CreateAsyncScope();
            var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

            var descriptor = new OpenIddictApplicationDescriptor
            {
                ClientId = settings.ClientId,
                ClientType = ClientTypes.Public,
                DisplayName = "Davids Customer OIDC Public PKCE Client",
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Token,
                    Permissions.Endpoints.EndSession,
                    Permissions.Endpoints.Revocation,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    Permissions.Prefixes.Scope + Scopes.OfflineAccess,
                    Permissions.Prefixes.Scope + settings.Audience
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange
                }
            };

            foreach (var redirect in settings.AllowedRedirectUris.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                descriptor.RedirectUris.Add(new Uri(redirect, UriKind.Absolute));
            }

            foreach (var logoutRedirect in settings.AllowedPostLogoutRedirectUris.Where(u => !string.IsNullOrWhiteSpace(u)))
            {
                descriptor.PostLogoutRedirectUris.Add(new Uri(logoutRedirect, UriKind.Absolute));
            }

            var existing = await manager.FindByClientIdAsync(settings.ClientId, cancellationToken);
            if (existing is null)
            {
                await manager.CreateAsync(descriptor, cancellationToken);
            }
            else
            {
                await manager.UpdateAsync(existing, descriptor, cancellationToken);
            }

            seeded = true;
        }
        finally
        {
            gate.Release();
        }
    }
}
