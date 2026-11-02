using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Application.Services.Identity;
using Davids.Services.Identity.Core.Repositories;
using Davids.Services.Identity.Infrastructure.Auth;
using Davids.Services.Identity.Infrastructure.Messaging;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using StackExchange.Redis;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.Identity.Infrastructure;

public static class Extensions
{
    public static IServiceCollection AddIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var oidc = configuration.GetSection("Oidc").Get<OidcSettings>() ?? new OidcSettings();
        oidc.InitializeKeys(requireExplicitEncryptionKey: environment.IsProduction());
        services.AddSingleton(oidc);
        var lockout = configuration.GetSection("Lockout").Get<IdentityLockoutSettings>() ?? new IdentityLockoutSettings();
        services.AddSingleton(lockout);
        services.AddDataProtection();
        services.AddSingleton<OidcLoginStateProtector>();
        services.AddSingleton<OidcApplicationSeeder>();

        var connectionString = configuration.GetConnectionString("identitydb")
            ?? throw new InvalidOperationException("Missing identitydb connection.");
        services.AddDbContext<IdentityDbContext>(o =>
        {
            o.UseSqlServer(connectionString);
            o.UseOpenIddict();
        });

        services.AddScoped<IUserRepository, UserRepository>();
        services.AddScoped<ILoginAuditRepository, LoginAuditRepository>();
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddSingleton<IPasswordService, PasswordService>();
        services.AddScoped<RevocationStore>();

        if (configuration.GetValue<bool>("Redis:Enabled"))
        {
            var connection = configuration.GetConnectionString("cache")
                ?? throw new InvalidOperationException("Missing cache connection.");
            services.AddSingleton<IConnectionMultiplexer>(_ =>
            {
                var options = ConfigurationOptions.Parse(connection);
                options.AbortOnConnectFail = false;
                options.ConnectTimeout = 5000;
                options.AsyncTimeout = 5000;
                return ConnectionMultiplexer.Connect(options);
            });
            services.AddSingleton<IRevocationCache, RedisRevocationCache>();
        }
        else
        {
            services.AddSingleton<IRevocationCache, NoRevocationCache>();
        }

        services.AddScoped<IMessageBroker, MessageBroker>();
        if (configuration.GetValue("Messaging:Enabled", true))
        {
            services.AddHostedService<RabbitWorker>();
        }

        var allowInsecureTransport =
            !environment.IsProduction() &&
            (environment.IsDevelopment() ||
             environment.IsEnvironment("Testing") ||
             configuration.GetValue<bool>("Http:AllowInsecureDevelopment"));

        services.AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                    .UseDbContext<IdentityDbContext>();
            })
            .AddServer(options =>
            {
                if (oidc.NormalizedIssuerUri is not null)
                {
                    options.SetIssuer(oidc.NormalizedIssuerUri);
                }

                options.SetAuthorizationEndpointUris("connect/authorize")
                    .SetTokenEndpointUris("connect/token")
                    .SetUserInfoEndpointUris("connect/userinfo")
                    .SetEndSessionEndpointUris("connect/logout")
                    .SetRevocationEndpointUris("connect/revocation");

                options.AllowAuthorizationCodeFlow()
                    .RequireProofKeyForCodeExchange();
                options.AllowRefreshTokenFlow();

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(oidc.AccessTokenLifetimeMinutes));
                options.SetIdentityTokenLifetime(TimeSpan.FromMinutes(oidc.AccessTokenLifetimeMinutes));
                options.SetRefreshTokenLifetime(TimeSpan.FromDays(oidc.RefreshTokenLifetimeDays));
                options.SetRefreshTokenReuseLeeway(TimeSpan.Zero);

                // Downstream resource servers (APIGateway, Customers, Istio) verify RS256 signatures via public JWKS.
                options.DisableAccessTokenEncryption();

                options.AddSigningKey(oidc.PrivateSigningKey);
                options.AddEncryptionKey(oidc.EncryptionSecurityKey);

                options.RegisterScopes(
                    Scopes.OpenId,
                    Scopes.Email,
                    Scopes.Profile,
                    Scopes.Roles,
                    Scopes.OfflineAccess,
                    oidc.Audience);

                options.AddEventHandler(OidcRevocationSyncHandler.Descriptor);
                options.AddEventHandler(OidcTokenErrorAuditHandler.Descriptor);

                var aspNetCore = options.UseAspNetCore()
                    .EnableAuthorizationEndpointPassthrough()
                    .EnableTokenEndpointPassthrough()
                    .EnableUserInfoEndpointPassthrough()
                    .EnableEndSessionEndpointPassthrough();

                if (allowInsecureTransport)
                {
                    aspNetCore.DisableTransportSecurityRequirement();
                }
            });

        services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(o =>
            {
                o.MapInboundClaims = false;
                o.TokenValidationParameters = oidc.CreateValidationParameters();
                o.Events = new JwtBearerEvents
                {
                    OnTokenValidated = async context =>
                    {
                        var role = context.Principal?.FindFirst(Claims.Role)?.Value;
                        if (!string.Equals(role, "user", StringComparison.Ordinal))
                        {
                            context.Fail("Customer Identity accepts customer ('user') tokens only.");
                            return;
                        }

                        var id = context.Principal?.FindFirst(Claims.JwtId)?.Value;
                        var oiTokenId = context.Principal?.FindFirst(Claims.Private.TokenId)?.Value;
                        DateTime? expUtc = long.TryParse(
                            context.Principal?.FindFirst(Claims.ExpiresAt)?.Value,
                            out var expSeconds)
                            ? DateTimeOffset.FromUnixTimeSeconds(expSeconds).UtcDateTime
                            : null;
                        var store = context.HttpContext.RequestServices.GetRequiredService<RevocationStore>();
                        if (await store.IsRevokedAsync(id, context.HttpContext.RequestAborted, oiTokenId, expUtc))
                        {
                            context.Fail("Token has been revoked.");
                        }
                    }
                };
            });

        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("identity-database");
        services.AddAuthorization();
        return services;
    }
}
