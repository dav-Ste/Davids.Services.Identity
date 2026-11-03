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
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using StackExchange.Redis;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.Identity.Infrastructure;

public static class Extensions
{
    public const string CustomerScheme = JwtBearerDefaults.AuthenticationScheme;
    public const string AdminScheme = AdminOidcValidationSettings.SchemeName;

    public static IServiceCollection AddIdentityInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration,
        IHostEnvironment environment)
    {
        var oidc = configuration.GetSection("Oidc").Get<OidcSettings>() ?? new OidcSettings();
        oidc.InitializeKeys(requireExplicitEncryptionKey: environment.IsProduction());
        services.AddSingleton(oidc);

        var adminOidc = configuration.GetSection("AdminOidc").Get<AdminOidcValidationSettings>()
            ?? new AdminOidcValidationSettings();
        adminOidc.Audience = string.IsNullOrWhiteSpace(adminOidc.Audience) ? "davids-admin" : adminOidc.Audience;
        var adminStaticKey = adminOidc.ValidateAndResolveStaticPublicKey();
        services.AddSingleton(adminOidc);

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
        services.AddScoped<ICustomerChangeAuditRepository, CustomerChangeAuditRepository>();
        services.AddScoped<RevocationStore>();
        services.AddScoped<ICustomerTokenRevocationService>(sp => sp.GetRequiredService<RevocationStore>());
        services.AddScoped<IIdentityService, IdentityService>();
        services.AddSingleton<IPasswordService, PasswordService>();

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

        var authBuilder = services.AddAuthentication(CustomerScheme)
            .AddJwtBearer(CustomerScheme, o =>
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
                            context.Fail("Customer Identity accepts customer ('user') tokens only on CustomerBearer.");
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

        if (adminOidc.IsConfigured)
        {
            var requireHttpsAdminMetadata = adminOidc.RequireHttpsMetadata ?? environment.IsProduction();
            authBuilder.AddJwtBearer(AdminScheme, options =>
            {
                options.MapInboundClaims = false;
                options.RequireHttpsMetadata = requireHttpsAdminMetadata;
                if (!string.IsNullOrWhiteSpace(adminOidc.MetadataAddress))
                {
                    options.MetadataAddress = adminOidc.MetadataAddress;
                }

                options.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuer = !string.IsNullOrWhiteSpace(adminOidc.EffectiveIssuer),
                    ValidIssuer = adminOidc.EffectiveIssuer,
                    ValidateAudience = true,
                    ValidAudience = adminOidc.Audience,
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = adminStaticKey,
                    ValidateLifetime = true,
                    RequireExpirationTime = true,
                    RequireSignedTokens = true,
                    ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
                    ClockSkew = TimeSpan.FromSeconds(30),
                    NameClaimType = Claims.Subject,
                    RoleClaimType = Claims.Role
                };
                options.Events = new JwtBearerEvents
                {
                    OnTokenValidated = context =>
                    {
                        var role = context.Principal?.FindFirst(Claims.Role)?.Value;
                        if (role is not ("admin" or "support" or "auditor"))
                        {
                            context.Fail("AdminBearer accepts workforce roles (admin, support, auditor) only.");
                        }

                        return Task.CompletedTask;
                    }
                };
            });
        }

        string[] dualSchemes = adminOidc.IsConfigured ? [CustomerScheme, AdminScheme] : [CustomerScheme];
        string[] workforceSchemes = adminOidc.IsConfigured ? [AdminScheme] : [CustomerScheme];

        services.AddAuthorizationBuilder()
            .AddPolicy("CustomerOnly", policy =>
            {
                policy.AddAuthenticationSchemes(CustomerScheme);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.Role, "user");
            })
            .AddPolicy("CustomerOrWorkforceRead", policy =>
            {
                policy.AddAuthenticationSchemes(dualSchemes);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.Role, "user", "admin", "support", "auditor");
            })
            .AddPolicy("WorkforceSupport", policy =>
            {
                policy.AddAuthenticationSchemes(workforceSchemes);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.Role, "admin", "support");
            })
            .AddPolicy("WorkforceRead", policy =>
            {
                policy.AddAuthenticationSchemes(workforceSchemes);
                policy.RequireAuthenticatedUser();
                policy.RequireClaim(Claims.Role, "admin", "support", "auditor");
            });

        services.AddHealthChecks().AddCheck<DatabaseHealthCheck>("identity-database");
        return services;
    }
}
