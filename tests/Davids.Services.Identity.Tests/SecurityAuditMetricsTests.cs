using System.Collections.Concurrent;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using Davids.Services.Identity.Infrastructure.Auth;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Davids.Services.Identity.Tests;

[Trait("Category", "Integration")]
public sealed class SecurityAuditMetricsTests
{
    [Fact]
    public async Task TamperedLoginReplayedGrantAndRfc7009RevocationEmitSecurityAuditMetrics()
    {
        var events = new ConcurrentBag<(string Name, string Domain, string Outcome, string Source)>();
        using var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == IdentitySecurityMetrics.MeterName)
            {
                meterListener.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) =>
        {
            string domain = string.Empty, outcome = string.Empty, source = string.Empty;
            foreach (var tag in tags)
            {
                if (tag.Key == "domain") domain = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "outcome") outcome = tag.Value?.ToString() ?? string.Empty;
                if (tag.Key == "source") source = tag.Value?.ToString() ?? string.Empty;
            }
            events.Add((instrument.Name, domain, outcome, source));
        });
        listener.Start();

        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();

        // 1. Tampered request_token on /connect/authorize -> invalid_request_token
        using var loginForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = "davids-web",
            ["redirect_uri"] = "https://localhost/callback",
            ["response_type"] = "code",
            ["scope"] = "openid email profile roles davids-services",
            ["code_challenge"] = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
            ["code_challenge_method"] = "S256",
            ["state"] = "audit-test-state",
            ["request_token"] = "tampered-invalid-request-token",
            ["email"] = "audit-probe@davids.test",
            ["password"] = "WrongPassword123!"
        });
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/connect/authorize", loginForm)).StatusCode);

        // 2. Replayed / invalid authorization code on /connect/token -> token_grant_rejected
        using var tokenForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["grant_type"] = "authorization_code",
            ["client_id"] = "davids-web",
            ["code"] = "replayed-or-forged-authorization-code",
            ["redirect_uri"] = "https://localhost/callback",
            ["code_verifier"] = "0123456789abcdef0123456789abcdef0123456789abcdef"
        });
        Assert.Equal(HttpStatusCode.BadRequest, (await client.PostAsync("/connect/token", tokenForm)).StatusCode);

        // 3. RFC 7009 /connect/revocation on a real OpenIddict RS256 access token -> rfc7009_revocation
        var oidcSettings = factory.Services.GetRequiredService<OidcSettings>();
        var tokens = await IdentityTests.RegisterAndSignInOidcAsync(client, "audit-revoke@davids.test");

        using var revokeForm = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = oidcSettings.ClientId,
            ["token"] = tokens.AccessToken,
            ["token_type_hint"] = "access_token"
        });
        Assert.Equal(HttpStatusCode.OK, (await client.PostAsync("/connect/revocation", revokeForm)).StatusCode);

        Assert.Contains(events, e =>
            e.Name == "davids.security.login_audit" &&
            e.Domain == "customer" &&
            e.Outcome == "invalid_request_token");
        Assert.Contains(events, e =>
            e.Name == "davids.security.login_audit" &&
            e.Domain == "customer" &&
            e.Outcome == "token_grant_rejected");
        Assert.Contains(events, e =>
            e.Name == "davids.security.token_revoked" &&
            e.Domain == "customer" &&
            e.Source == "rfc7009_revocation");
    }
}
