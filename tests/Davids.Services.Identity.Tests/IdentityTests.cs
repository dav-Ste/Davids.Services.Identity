using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Davids.Services.Identity.Application.DTO;
using Davids.Services.Identity.Infrastructure.Auth;
using Davids.Services.Identity.Infrastructure.Messaging;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Davids.Services.Identity.Tests;

public sealed class IdentityFactory : WebApplicationFactory<Program>
{
    public static readonly string TestSigningKeyPem = OidcSettings.GenerateRsaPrivateKeyPem();
    public static readonly string TestEncryptionKeyPem = OidcSettings.GenerateRsaPrivateKeyPem();

    private readonly SqliteConnection connection = new("Data Source=:memory:");

    public IdentityFactory() => connection.Open();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Testing");
        builder.UseSetting("Oidc:Issuer", "https://localhost/");
        builder.UseSetting("Oidc:SigningKeyPem", TestSigningKeyPem);
        builder.UseSetting("Oidc:EncryptionKeyPem", TestEncryptionKeyPem);
        builder.UseSetting("ConnectionStrings:identitydb", "unused");
        builder.ConfigureServices(services =>
        {
            services.RemoveAll<DbContextOptions<IdentityDbContext>>();
            services.RemoveAll<IDbContextOptionsConfiguration<IdentityDbContext>>();
            services.RemoveAll<IdentityDbContext>();
            services.AddDbContext<IdentityDbContext>(o =>
            {
                o.UseSqlite(connection);
                o.UseOpenIddict();
            });
            foreach (var descriptor in services
                         .Where(x => x.ServiceType == typeof(IHostedService) && x.ImplementationType == typeof(RabbitWorker))
                         .ToArray())
            {
                services.Remove(descriptor);
            }
        });
    }

    public HttpClient CreateIdentityClient()
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using var scope = Services.CreateScope();
        scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        return client;
    }

    protected override void Dispose(bool disposing)
    {
        base.Dispose(disposing);
        if (disposing)
        {
            connection.Dispose();
        }
    }
}

public sealed record OidcTokenResponse(
    string AccessToken,
    string IdToken,
    string RefreshToken,
    int ExpiresIn,
    string TokenType);

[Trait("Category", "Integration")]
public sealed class IdentityTests
{
    private const string Password = "Correct-horse-123!";
    private const string RedirectUri = "https://localhost/callback";

    private static (string Verifier, string Challenge) CreatePkcePair()
    {
        var verifier = Base64UrlEncoder.Encode(RandomNumberGenerator.GetBytes(32));
        var challenge = Base64UrlEncoder.Encode(SHA256.HashData(Encoding.ASCII.GetBytes(verifier)));
        return (verifier, challenge);
    }

    private static string ExtractHiddenField(string html, string fieldName)
    {
        var match = Regex.Match(
            html,
            $"name=\"{Regex.Escape(fieldName)}\"\\s+value=\"([^\"]*)\"",
            RegexOptions.IgnoreCase);
        Assert.True(match.Success, $"Missing hidden input '{fieldName}' in authorize HTML.");
        return WebUtility.HtmlDecode(match.Groups[1].Value);
    }

    internal static async Task<OidcTokenResponse> RegisterAndSignInOidcAsync(HttpClient client, string email = "user@example.com")
    {
        var signUp = await client.PostAsJsonAsync("/sign-up", new { email, password = Password });
        Assert.Equal(HttpStatusCode.Created, signUp.StatusCode);

        var (verifier, challenge) = CreatePkcePair();
        var state = "state-" + Guid.NewGuid().ToString("N");
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles offline_access davids-services",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state
        });

        var getAuthorize = await client.GetAsync(authorizeUrl);
        Assert.Equal(HttpStatusCode.OK, getAuthorize.StatusCode);
        var html = await getAuthorize.Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");

        using var postAuthorize = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles offline_access davids-services",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state,
            ["request_token"] = requestToken,
            ["email"] = email,
            ["password"] = Password
        }));

        Assert.Equal(HttpStatusCode.Redirect, postAuthorize.StatusCode);
        var location = postAuthorize.Headers.Location!;
        var query = QueryHelpers.ParseQuery(location.Query);
        Assert.Equal(state, query["state"].ToString());
        var code = query["code"].ToString();
        Assert.False(string.IsNullOrWhiteSpace(code));

        using var tokenResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResponse.StatusCode);

        using var doc = JsonDocument.Parse(await tokenResponse.Content.ReadAsStringAsync());
        var root = doc.RootElement;
        return new OidcTokenResponse(
            root.GetProperty("access_token").GetString()!,
            root.GetProperty("id_token").GetString()!,
            root.GetProperty("refresh_token").GetString()!,
            root.GetProperty("expires_in").GetInt32(),
            root.GetProperty("token_type").GetString()!);
    }

    [Theory]
    [InlineData("user@example.com<script>alert(1)</script>")]
    [InlineData("not-an-email")]
    public async Task InvalidSignUpEmailIsRejectedWithoutReflectingSubmittedValue(string invalidEmail)
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();

        using var response = await client.PostAsJsonAsync("/sign-up", new { email = invalidEmail, password = Password });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = await response.Content.ReadAsStringAsync();
        Assert.DoesNotContain(invalidEmail, body, StringComparison.Ordinal);
        using var document = JsonDocument.Parse(body);
        Assert.Equal("invalid_email", document.RootElement.GetProperty("code").GetString());
        Assert.Equal("Invalid email address.", document.RootElement.GetProperty("reason").GetString());
        Assert.DoesNotContain(invalidEmail, document.RootElement.GetProperty("reason").GetString()!, StringComparison.Ordinal);
    }

    [Fact]
    public async Task DiscoveryAndJwksExposeRs256PublicKeyAndRequirePkceS256()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();

        using var discoveryDoc = JsonDocument.Parse(await client.GetStringAsync("/.well-known/openid-configuration"));
        var discovery = discoveryDoc.RootElement;
        Assert.Equal("https://localhost/", discovery.GetProperty("issuer").GetString());
        Assert.Equal("https://localhost/connect/authorize", discovery.GetProperty("authorization_endpoint").GetString());
        Assert.Equal("https://localhost/connect/token", discovery.GetProperty("token_endpoint").GetString());
        Assert.Equal("https://localhost/connect/revocation", discovery.GetProperty("revocation_endpoint").GetString());
        Assert.Contains(
            discovery.GetProperty("code_challenge_methods_supported").EnumerateArray().Select(x => x.GetString()),
            x => x == "S256");

        var jwksUri = new Uri(discovery.GetProperty("jwks_uri").GetString()!);
        using var jwksDoc = JsonDocument.Parse(await client.GetStringAsync(jwksUri.PathAndQuery));
        var keys = jwksDoc.RootElement.GetProperty("keys").EnumerateArray().ToArray();
        Assert.Contains(keys, k => k.GetProperty("kty").GetString() == "RSA" && k.GetProperty("use").GetString() == "sig");
    }

    [Fact]
    public async Task RegisterAuthorizationCodePkceSignInUserInfoAndMePreserveContract()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        var tokens = await RegisterAndSignInOidcAsync(client);

        Assert.Equal("Bearer", tokens.TokenType);
        Assert.False(string.IsNullOrWhiteSpace(tokens.IdToken));
        Assert.True(tokens.ExpiresIn > 0);

        var jwt = new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken);
        Assert.Equal(SecurityAlgorithms.RsaSha256, jwt.Header.Alg);
        Assert.Contains("davids-services", jwt.Audiences);
        Assert.Equal("user", jwt.Claims.Single(c => c.Type == "role").Value);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        var me = await client.GetFromJsonAsync<UserDto>("/me");
        Assert.Equal("user@example.com", me!.Email);
        Assert.Equal(me.Id.ToString("N"), jwt.Subject);

        using var userInfo = JsonDocument.Parse(await client.GetStringAsync("/connect/userinfo"));
        Assert.Equal(me.Id.ToString("N"), userInfo.RootElement.GetProperty("sub").GetString());
        Assert.Equal("user@example.com", userInfo.RootElement.GetProperty("email").GetString());
    }

    [Fact]
    public async Task AuthorizationWithoutPkceOrWithWrongVerifierIsRejected()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        await client.PostAsJsonAsync("/sign-up", new { email = "pkce@example.com", password = Password });

        var noPkce = await client.GetAsync(QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email"
        }));
        Assert.NotEqual(HttpStatusCode.OK, noPkce.StatusCode);

        var (_, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st1"
        });
        var html = await (await client.GetAsync(authorizeUrl)).Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");
        var postAuthorize = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st1",
            ["request_token"] = requestToken,
            ["email"] = "pkce@example.com",
            ["password"] = Password
        }));
        var code = QueryHelpers.ParseQuery(postAuthorize.Headers.Location!.Query)["code"].ToString();

        var wrongVerifier = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = "wrong-code-verifier-that-does-not-match-s256-challenge-value"
        }));
        Assert.Equal(HttpStatusCode.BadRequest, wrongVerifier.StatusCode);
    }

    [Fact]
    public async Task RefreshTokenRotatesOnUseAndRejectsReplayOrRevocation()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        var initial = await RegisterAndSignInOidcAsync(client);

        using var refreshResponse = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "davids-web",
            ["refresh_token"] = initial.RefreshToken
        }));
        Assert.Equal(HttpStatusCode.OK, refreshResponse.StatusCode);
        using var refreshedDoc = JsonDocument.Parse(await refreshResponse.Content.ReadAsStringAsync());
        var rotatedRefreshToken = refreshedDoc.RootElement.GetProperty("refresh_token").GetString()!;
        Assert.NotEqual(initial.RefreshToken, rotatedRefreshToken);

        // Replaying the already-redeemed refresh token must fail under OIDC rolling refresh rotation.
        var replay = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "davids-web",
            ["refresh_token"] = initial.RefreshToken
        }));
        Assert.Equal(HttpStatusCode.BadRequest, replay.StatusCode);

        // Explicit RFC 7009 revocation invalidates the active refresh token.
        var revoke = await client.PostAsync("/connect/revocation", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["token"] = rotatedRefreshToken,
            ["token_type_hint"] = "refresh_token"
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);

        var useRevoked = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["client_id"] = "davids-web",
            ["refresh_token"] = rotatedRefreshToken
        }));
        Assert.Equal(HttpStatusCode.BadRequest, useRevoked.StatusCode);
    }

    private sealed class RecordingRevocationCache : IRevocationCache
    {
        public HashSet<string> Entries { get; } = [];
        public Task<bool> ContainsAsync(string id) => Task.FromResult(Entries.Contains(id));
        public Task AddAsync(string id, DateTime expiresAt)
        {
            Entries.Add(id);
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task RevokedAccessTokenIsRejectedAndPopulatesSharedCache()
    {
        var cache = new RecordingRevocationCache();
        using var factory = new IdentityFactory().WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IRevocationCache>();
            services.AddSingleton<IRevocationCache>(cache);
        }));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var scope = factory.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        }

        var tokens = await RegisterAndSignInOidcAsync(client);
        var jti = new JwtSecurityTokenHandler().ReadJwtToken(tokens.AccessToken).Id;

        var revoke = await client.PostAsync("/connect/revocation", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["token"] = tokens.AccessToken,
            ["token_type_hint"] = "access_token"
        }));
        Assert.Equal(HttpStatusCode.OK, revoke.StatusCode);
        Assert.Contains(jti, cache.Entries);

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/connect/userinfo")).StatusCode);
    }

    [Fact]
    public async Task CredentialsAreHashedAndOutboxRecordsSignUpAndOidcSignIn()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        await RegisterAndSignInOidcAsync(client);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.NotEqual(Password, (await db.Users.SingleAsync()).Password);
        var outboxTypes = await db.Outbox.OrderBy(x => x.CreatedAt).Select(x => x.Type).ToListAsync();
        Assert.Equal(["signed_up", "signed_in"], outboxTypes);
    }

    [Fact]
    public async Task AnonymousUserLookupsAreRejected()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync($"/users/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task PublicRegistrationCannotGrantAdmin()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await client.PostAsJsonAsync("/sign-up", new { email = "admin@example.com", password = Password, role = "admin" })).StatusCode);

        using var scope = factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.Empty(await db.Users.ToListAsync());
        Assert.Empty(await db.Outbox.ToListAsync());
    }

    [Fact]
    public async Task WrongPasswordOrTamperedAuthorizeFormTokenIsRejected()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        await client.PostAsJsonAsync("/sign-up", new { email = "user@example.com", password = Password });

        var (_, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-bad"
        });
        var html = await (await client.GetAsync(authorizeUrl)).Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");

        var wrongPw = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-bad",
            ["request_token"] = requestToken,
            ["email"] = "user@example.com",
            ["password"] = "wrong-password"
        }));
        Assert.Equal(HttpStatusCode.BadRequest, wrongPw.StatusCode);

        var tamperedToken = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-bad",
            ["request_token"] = "tampered-token",
            ["email"] = "user@example.com",
            ["password"] = Password
        }));
        Assert.Equal(HttpStatusCode.BadRequest, tamperedToken.StatusCode);
    }

    [Fact]
    public async Task DuplicateEmailIsRejectedCaseInsensitively()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        await RegisterAndSignInOidcAsync(client);
        Assert.Equal(
            HttpStatusCode.BadRequest,
            (await client.PostAsJsonAsync("/sign-up", new { email = "USER@example.com", password = Password })).StatusCode);
    }

    [Fact]
    public async Task OtherUsersCannotBeRead()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        var tokens = await RegisterAndSignInOidcAsync(client);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.GetAsync($"/users/{Guid.NewGuid()}")).StatusCode);
    }

    [Fact]
    public async Task CustomerIdentityDomainAndBearerValidationRejectAdminRole()
    {
        Assert.False(Davids.Services.Identity.Core.Entities.Role.IsValid("admin"));
        Assert.Throws<Davids.Services.Identity.Core.Exceptions.InvalidRoleException>(() =>
            new Davids.Services.Identity.Core.Entities.User(Guid.NewGuid(), "admin@example.com", "hashed", "admin", DateTime.UtcNow));

        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        var oidc = factory.Services.GetRequiredService<OidcSettings>();
        var handler = new JwtSecurityTokenHandler();
        var forgedAdmin = handler.WriteToken(new JwtSecurityToken(
            issuer: "https://localhost/",
            audience: oidc.Audience,
            claims:
            [
                new Claim("sub", Guid.NewGuid().ToString("N")),
                new Claim("role", "admin"),
                new Claim("jti", Guid.NewGuid().ToString("N"))
            ],
            notBefore: DateTime.UtcNow.AddSeconds(-5),
            expires: DateTime.UtcNow.AddMinutes(5),
            signingCredentials: new SigningCredentials(oidc.PrivateSigningKey, SecurityAlgorithms.RsaSha256)));

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", forgedAdmin);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
    }

    [Fact]
    public async Task CustomerAuthorizeEnforcesPerClientIpRateLimitingAndPerAccountLockout()
    {
        using var baseFactory = new IdentityFactory();
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("RateLimiting:AuthPermitLimit", "2");
            b.UseSetting("Lockout:MaxFailedAccessAttempts", "3");
            b.UseSetting("Lockout:DurationMinutes", "15");
            b.ConfigureServices(services =>
            {
                services.AddSingleton<IStartupFilter>(new LoopbackGatewayIpStartupFilter());
            });
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var scope = factory.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        }

        using (var signUpMsg = new HttpRequestMessage(HttpMethod.Post, "/sign-up")
        {
            Content = JsonContent.Create(new { email = "lockout-user@example.com", password = Password })
        })
        {
            signUpMsg.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100.1");
            Assert.Equal(HttpStatusCode.Created, (await client.SendAsync(signUpMsg)).StatusCode);
        }

        var (_, challenge) = CreatePkcePair();
        var authUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = "https://localhost/callback",
            ["response_type"] = "code",
            ["scope"] = "openid email offline_access",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "lockout-state"
        });
        var formGet = await client.GetAsync(authUrl);
        var requestToken = ExtractHiddenField(await formGet.Content.ReadAsStringAsync(), "request_token");

        HttpRequestMessage BuildLogin(string email, string pw, string ip)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = "davids-web",
                    ["redirect_uri"] = "https://localhost/callback",
                    ["response_type"] = "code",
                    ["scope"] = "openid email offline_access",
                    ["code_challenge"] = challenge,
                    ["code_challenge_method"] = "S256",
                    ["state"] = "lockout-state",
                    ["request_token"] = requestToken,
                    ["email"] = email,
                    ["password"] = pw
                })
            };
            req.Headers.TryAddWithoutValidation("X-Forwarded-For", ip);
            return req;
        }

        // Per-IP isolation: 198.51.100.10 hits 429 on 3rd attempt while 198.51.100.20 remains unaffected.
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLogin("missing@example.com", "wrong", "198.51.100.10"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLogin("missing@example.com", "wrong", "198.51.100.10"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.SendAsync(BuildLogin("missing@example.com", "wrong", "198.51.100.10"))).StatusCode);

        // Distributed brute-force across 3 distinct client IPs locks lockout-user@example.com on 3rd bad password.
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLogin("lockout-user@example.com", "wrong-1", "198.51.100.20"))).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLogin("lockout-user@example.com", "wrong-2", "198.51.100.21"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.SendAsync(BuildLogin("lockout-user@example.com", "wrong-3", "198.51.100.22"))).StatusCode);
        Assert.Equal(HttpStatusCode.TooManyRequests, (await client.SendAsync(BuildLogin("lockout-user@example.com", Password, "198.51.100.23"))).StatusCode);
    }

    [Fact]
    public async Task DataProtectionKeysArePersistedAndEncryptedAtRestInIdentityDb()
    {
        using var baseFactory = new IdentityFactory();
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("DataProtection:MasterKey", "customer-identity-dp-master-key-at-least-32-chars!");
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var initScope = factory.Services.CreateScope())
        {
            initScope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        }

        var tokens = await RegisterAndSignInOidcAsync(client, "dp-customer@example.com");
        Assert.False(string.IsNullOrWhiteSpace(tokens.AccessToken));

        await using var scope = factory.Services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        var storedKeys = await db.DataProtectionKeys.AsNoTracking().ToListAsync();
        Assert.NotEmpty(storedKeys);
        foreach (var row in storedKeys)
        {
            Assert.Contains("encryptedKey", row.Xml, StringComparison.Ordinal);
            Assert.DoesNotContain("<masterKey", row.Xml, StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public async Task CustomerLoginAttemptsAreAuditedWithoutSecretsAndExposedOnlyToAccountOwner()
    {
        using var baseFactory = new IdentityFactory();
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("RateLimiting:AuthPermitLimit", "50");
            b.UseSetting("Lockout:MaxFailedAccessAttempts", "3");
            b.UseSetting("ForwardedHeaders:TrustLoopbackProxies", "true");
            b.ConfigureServices(services =>
                services.AddSingleton<IStartupFilter, LoopbackGatewayIpStartupFilter>());
        });

        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var initScope = factory.Services.CreateScope())
        {
            initScope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        }

        // Anonymous requests to /me/login-audits must be rejected.
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me/login-audits")).StatusCode);

        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/sign-up", new { email = "alice.audit@example.com", password = Password })).StatusCode);
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/sign-up", new { email = "bob.audit@example.com", password = Password })).StatusCode);

        var (verifier, challenge) = CreatePkcePair();
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles offline_access davids-services",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = "st-cust-audit"
        });
        var html = await (await client.GetAsync(authorizeUrl)).Content.ReadAsStringAsync();
        var requestToken = ExtractHiddenField(html, "request_token");

        HttpRequestMessage BuildLoginPost(string email, string pw, string token, string ip, string correlationId)
        {
            var req = new HttpRequestMessage(HttpMethod.Post, "/connect/authorize")
            {
                Content = new FormUrlEncodedContent(new Dictionary<string, string>
                {
                    ["client_id"] = "davids-web",
                    ["redirect_uri"] = RedirectUri,
                    ["response_type"] = "code",
                    ["scope"] = "openid email profile roles offline_access davids-services",
                    ["code_challenge"] = challenge,
                    ["code_challenge_method"] = "S256",
                    ["state"] = "st-cust-audit",
                    ["request_token"] = token,
                    ["email"] = email,
                    ["password"] = pw
                })
            };
            req.Headers.TryAddWithoutValidation("X-Forwarded-For", ip);
            req.Headers.TryAddWithoutValidation("X-Correlation-ID", correlationId);
            req.Headers.TryAddWithoutValidation("User-Agent", "DavidsCustomerAuditTest/1.0");
            return req;
        }

        const string wrongCustomerSecret = "Wrong-Customer-Password-Secret-777!";

        // 1. Tampered request_token -> invalid_request_token (UserId = null)
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLoginPost("alice.audit@example.com", Password, "tampered", "198.51.100.71", "corr-cust-1"))).StatusCode);

        // 2. Wrong password for Alice -> invalid_credentials (UserId = Alice)
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLoginPost("alice.audit@example.com", wrongCustomerSecret, requestToken, "198.51.100.72", "corr-cust-2"))).StatusCode);

        // 3. Wrong password for Bob -> invalid_credentials (UserId = Bob — must NOT appear in Alice's /me/login-audits!)
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(BuildLoginPost("bob.audit@example.com", wrongCustomerSecret, requestToken, "198.51.100.73", "corr-cust-3"))).StatusCode);

        // 4. Invalid refresh_token grant -> token_grant_rejected
        var badTokenGrant = new HttpRequestMessage(HttpMethod.Post, "/connect/token")
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["client_id"] = "davids-web",
                ["refresh_token"] = "revoked-or-forged-customer-refresh-token"
            })
        };
        badTokenGrant.Headers.TryAddWithoutValidation("X-Forwarded-For", "198.51.100.74");
        badTokenGrant.Headers.TryAddWithoutValidation("X-Correlation-ID", "corr-cust-4");
        Assert.Equal(HttpStatusCode.BadRequest, (await client.SendAsync(badTokenGrant)).StatusCode);

        // 5. Alice signs in with valid credentials -> succeeded
        var aliceLogin = await client.SendAsync(BuildLoginPost("alice.audit@example.com", Password, requestToken, "198.51.100.75", "corr-cust-5"));
        Assert.Equal(HttpStatusCode.Redirect, aliceLogin.StatusCode);
        var code = QueryHelpers.ParseQuery(aliceLogin.Headers.Location!.Query)["code"].ToString();
        var tokenResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        using var tokenDoc = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var aliceAccessToken = tokenDoc.RootElement.GetProperty("access_token").GetString()!;

        // Inspect identitydb CustomerLoginAuditLogs directly: all 5 attempts persisted with ZERO secrets.
        await using (var checkScope = factory.Services.CreateAsyncScope())
        {
            var db = checkScope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var rows = await db.CustomerLoginAuditLogs.AsNoTracking().ToListAsync();
            Assert.Equal(5, rows.Count);
            foreach (var row in rows)
            {
                var combined = $"{row.Email}|{row.Outcome}|{row.FailureReason}|{row.ClientId}|{row.ClientIpAddress}|{row.UserAgent}|{row.CorrelationId}";
                Assert.DoesNotContain(Password, combined, StringComparison.Ordinal);
                Assert.DoesNotContain(wrongCustomerSecret, combined, StringComparison.Ordinal);
                Assert.DoesNotContain("revoked-or-forged-customer-refresh-token", combined, StringComparison.Ordinal);
            }
        }

        // Alice calls GET /me/login-audits: sees ONLY her own 2 account-bound attempts (wrong password + succeeded), never Bob's!
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", aliceAccessToken);
        var aliceAudits = await client.GetFromJsonAsync<Davids.Services.Identity.Application.DTO.LoginAuditDto[]>("/me/login-audits");
        Assert.NotNull(aliceAudits);
        Assert.Equal(2, aliceAudits.Length);
        Assert.All(aliceAudits, a => Assert.Equal("alice.audit@example.com", a.Email));
        Assert.Contains(aliceAudits, a => a.Succeeded && a.Outcome == "succeeded" && a.ClientIpAddress == "198.51.100.75" && a.CorrelationId == "corr-cust-5");
        Assert.Contains(aliceAudits, a => !a.Succeeded && a.Outcome == "invalid_credentials" && a.ClientIpAddress == "198.51.100.72" && a.CorrelationId == "corr-cust-2");
    }

    [Fact]
    public async Task OpenApiContractAndFuzzingBoundariesEnforceStagingDastInvariants()
    {
        await using var baseFactory = new IdentityFactory();
        using var nonDevClient = baseFactory.CreateClient();

        // /openapi/v1.json is unmapped outside Development.
        Assert.Equal(HttpStatusCode.NotFound, (await nonDevClient.GetAsync("/openapi/v1.json")).StatusCode);

        // Percent-encoded null bytes (%00) in form-urlencoded /connect/token return 400 Bad Request, never 500.
        var nullByteForm = new StringContent(
            "grant_type=authorization_code&client_id=davids-web&code=%00&code_verifier=abc",
            Encoding.UTF8,
            "application/x-www-form-urlencoded");
        Assert.Equal(HttpStatusCode.BadRequest, (await nonDevClient.PostAsync("/connect/token", nullByteForm)).StatusCode);

        // Development exposes the OpenAPI 3.1.1 contract with RS256 BearerAuth scheme and explicit integer bounds.
        await using var devFactory = baseFactory.WithWebHostBuilder(wb => wb.UseEnvironment("Development"));
        using var devClient = devFactory.CreateClient();
        var openApiResp = await devClient.GetAsync("/openapi/v1.json");
        Assert.Equal(HttpStatusCode.OK, openApiResp.StatusCode);

        using var doc = JsonDocument.Parse(await openApiResp.Content.ReadAsStringAsync());
        Assert.Equal("3.1.1", doc.RootElement.GetProperty("openapi").GetString());
        Assert.True(doc.RootElement.GetProperty("components").GetProperty("securitySchemes").TryGetProperty("BearerAuth", out _));
        var limitSchema = doc.RootElement.GetProperty("paths").GetProperty("/me/login-audits").GetProperty("get")
            .GetProperty("parameters")[0].GetProperty("schema");
        Assert.Equal(1, limitSchema.GetProperty("minimum").GetInt32());
        Assert.Equal(200, limitSchema.GetProperty("maximum").GetInt32());
    }

    [Fact]
    public async Task RestlerQueryInjectionAndAuthCodeReplayCascadeRevocationAreEnforced()
    {
        var cache = new RecordingRevocationCache();
        using var baseFactory = new IdentityFactory();
        using var factory = baseFactory.WithWebHostBuilder(builder => builder.ConfigureServices(services =>
        {
            services.RemoveAll<IRevocationCache>();
            services.AddSingleton<IRevocationCache>(cache);
        }));
        using var client = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var scope = factory.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        }

        const string email = "release-replay@example.com";
        Assert.Equal(HttpStatusCode.Created, (await client.PostAsJsonAsync("/sign-up", new { email, password = Password })).StatusCode);

        // Elevate permissions to include 'users' so /users/{userId} reaches the endpoint handler.
        Guid userId;
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var userRow = await db.Users.SingleAsync(u => u.Email == email);
            userId = userRow.Id;
            userRow.PermissionsJson = "[\"users\"]";
            await db.SaveChangesAsync();
        }

        var (verifier, challenge) = CreatePkcePair();
        var state = "release-" + Guid.NewGuid().ToString("N");
        var authorizeUrl = QueryHelpers.AddQueryString("/connect/authorize", new Dictionary<string, string?>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles offline_access davids-services",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state
        });
        var getAuth = await client.GetAsync(authorizeUrl);
        var requestToken = ExtractHiddenField(await getAuth.Content.ReadAsStringAsync(), "request_token");

        using var postAuth = await client.PostAsync("/connect/authorize", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles offline_access davids-services",
            ["code_challenge"] = challenge,
            ["code_challenge_method"] = "S256",
            ["state"] = state,
            ["request_token"] = requestToken,
            ["email"] = email,
            ["password"] = Password
        }));
        var code = QueryHelpers.ParseQuery(postAuth.Headers.Location!.Query)["code"].ToString();

        using var tokenResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.OK, tokenResp.StatusCode);
        using var tokenDoc = JsonDocument.Parse(await tokenResp.Content.ReadAsStringAsync());
        var accessToken = tokenDoc.RootElement.GetProperty("access_token").GetString()!;
        var jti = new JwtSecurityTokenHandler().ReadJwtToken(accessToken).Id;

        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        Assert.Equal(HttpStatusCode.OK, (await client.GetAsync($"/users/{userId}")).StatusCode);

        // RESTler InvalidDynamicObjectChecker regression: unexpected query parameters on /users/{userId} return 400.
        var injectedQuery = await client.GetAsync($"/users/{userId}?injected_query_string=123");
        Assert.Equal(HttpStatusCode.BadRequest, injectedQuery.StatusCode);
        Assert.Contains("unexpected_query_parameters", await injectedQuery.Content.ReadAsStringAsync(), StringComparison.Ordinal);

        // RFC 6749 s10.5: replaying an already-redeemed authorization code rejects the grant (400) AND immediately cascade-revokes issued access_tokens.
        using var replayResp = await client.PostAsync("/connect/token", new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "davids-web",
            ["redirect_uri"] = RedirectUri,
            ["code"] = code,
            ["code_verifier"] = verifier
        }));
        Assert.Equal(HttpStatusCode.BadRequest, replayResp.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await client.GetAsync("/me")).StatusCode);
        Assert.Contains(jti, cache.Entries);
    }

    private sealed class LoopbackGatewayIpStartupFilter : IStartupFilter
    {
        public Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> Configure(
            Action<Microsoft.AspNetCore.Builder.IApplicationBuilder> next) =>
            app =>
            {
                app.Use((ctx, innerNext) =>
                {
                    ctx.Connection.RemoteIpAddress ??= IPAddress.Loopback;
                    return innerNext();
                });
                next(app);
            };
    }
}
