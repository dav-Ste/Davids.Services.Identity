using System.Net;
using System.Security.Claims;
using System.Text;
using Davids.Services.Identity.Application.DTO;
using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Core.Entities;
using Davids.Services.Identity.Core.Exceptions;
using Davids.Services.Identity.Infrastructure.Auth;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Davids.Services.Identity.Api;

public static class OidcEndpoints
{
    private const string AuthorizeStylesheet = """
        :root { color-scheme: light; font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; }
        body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f3f6fb; color: #0f172a; }
        .card { width: min(420px, 92vw); background: #fff; border: 1px solid #dbe3ef; border-radius: 16px; padding: 2rem; box-shadow: 0 18px 40px rgba(15, 23, 42, 0.08); }
        .badge { display: inline-block; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: #1d4ed8; background: #dbeafe; padding: 0.25rem 0.6rem; border-radius: 999px; margin-bottom: 0.75rem; }
        h1 { margin: 0 0 0.4rem; font-size: 1.4rem; }
        p.sub { margin: 0 0 1.4rem; color: #475569; font-size: 0.92rem; line-height: 1.45; }
        label { display: block; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.35rem; color: #1e293b; }
        input[type="email"], input[type="password"] { box-sizing: border-box; width: 100%; padding: 0.68rem 0.8rem; border: 1px solid #cbd5e1; border-radius: 10px; font-size: 0.95rem; margin-bottom: 1rem; }
        input:focus { outline: 2px solid #2563eb; border-color: #2563eb; }
        .error { background: #fef2f2; border: 1px solid #fecaca; color: #991b1b; padding: 0.7rem 0.85rem; border-radius: 10px; font-size: 0.88rem; margin-bottom: 1rem; }
        button { width: 100%; padding: 0.75rem 1rem; border: 0; border-radius: 10px; background: #1d4ed8; color: #fff; font-size: 0.95rem; font-weight: 600; cursor: pointer; }
        button:hover { background: #1e40af; }
        .meta { margin-top: 1.1rem; font-size: 0.78rem; color: #64748b; text-align: center; }
        """;

    public static void MapIdentityOidcEndpoints(this WebApplication app)
    {
        app.MapGet("/connect/authorize.css", () =>
            Results.Content(AuthorizeStylesheet, "text/css; charset=utf-8"))
            .ExcludeFromDescription()
            .AllowAnonymous();

        app.MapGet("/connect/authorize", (HttpContext context, OidcLoginStateProtector stateProtector) =>
        {
            var request = context.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect authorization request cannot be retrieved.");

            var requestToken = stateProtector.Protect(
                request.ClientId,
                request.RedirectUri,
                request.CodeChallenge,
                request.State);

            return RenderAuthorizeForm(context, request, requestToken, emailValue: string.Empty, errorMessage: null);
        })
        .ExcludeFromDescription()
        .AllowAnonymous();

        app.MapPost("/connect/authorize", async (
            HttpContext context,
            IIdentityService identityService,
            IdentityDbContext dbContext,
            OidcSettings oidcSettings,
            OidcLoginStateProtector stateProtector,
            CancellationToken cancellationToken) =>
        {
            var request = context.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect authorization request cannot be retrieved.");

            if (!context.Request.HasFormContentType)
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Form-encoded body is required." });
            }

            var form = await context.Request.ReadFormAsync(cancellationToken);
            var submittedToken = form["request_token"].ToString();
            var email = form["email"].ToString().Trim();
            var password = form["password"].ToString();
            var metadata = ExtractAuditMetadata(context, request.ClientId);

            if (!stateProtector.TryValidate(
                    submittedToken,
                    request.ClientId,
                    request.RedirectUri,
                    request.CodeChallenge,
                    request.State))
            {
                await identityService.RecordProtocolFailureAuditAsync(
                    email,
                    userId: null,
                    outcome: "invalid_request_token",
                    failureReason: "Authorize form request_token expired or failed verification.",
                    metadata: metadata);
                var freshToken = stateProtector.Protect(
                    request.ClientId,
                    request.RedirectUri,
                    request.CodeChallenge,
                    request.State);
                return RenderAuthorizeForm(
                    context,
                    request,
                    freshToken,
                    email,
                    "Your sign-in form expired or failed verification. Please submit again.",
                    StatusCodes.Status400BadRequest);
            }

            UserDto user;
            await using var tx = await dbContext.Database.BeginTransactionAsync(cancellationToken);
            try
            {
                user = await identityService.AuthenticateAsync(email, password, metadata);
                await tx.CommitAsync(cancellationToken);
            }
            catch (AccountLockedException)
            {
                await tx.CommitAsync(cancellationToken);
                var retryToken = stateProtector.Protect(
                    request.ClientId,
                    request.RedirectUri,
                    request.CodeChallenge,
                    request.State);
                return RenderAuthorizeForm(
                    context,
                    request,
                    retryToken,
                    email,
                    "This account is temporarily locked due to repeated failed sign-in attempts. Please try again later.",
                    StatusCodes.Status429TooManyRequests);
            }
            catch (DomainException)
            {
                await tx.CommitAsync(cancellationToken);
                var retryToken = stateProtector.Protect(
                    request.ClientId,
                    request.RedirectUri,
                    request.CodeChallenge,
                    request.State);
                return RenderAuthorizeForm(
                    context,
                    request,
                    retryToken,
                    email,
                    "Incorrect customer email or password.",
                    StatusCodes.Status400BadRequest);
            }

            var requestedScopes = request.GetScopes();
            if (!requestedScopes.Contains(oidcSettings.Audience))
            {
                requestedScopes = requestedScopes.Add(oidcSettings.Audience);
            }

            var principal = BuildCustomerPrincipal(user, oidcSettings, requestedScopes);
            return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        })
        .ExcludeFromDescription()
        .AllowAnonymous()
        .RequireRateLimiting("authentication");

        app.MapPost("/connect/token", async (
            HttpContext context,
            IIdentityService identityService,
            OidcSettings oidcSettings) =>
        {
            var request = context.GetOpenIddictServerRequest()
                ?? throw new InvalidOperationException("The OpenID Connect token request cannot be retrieved.");
            var metadata = ExtractAuditMetadata(context, request.ClientId);

            if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            {
                context.Items[OidcTokenErrorAuditHandler.AuditRecordedItemKey] = true;
                await identityService.RecordProtocolFailureAuditAsync(
                    email: "[token-endpoint]",
                    userId: null,
                    outcome: "unsupported_grant_type",
                    failureReason: $"Rejected unsupported token grant type '{request.GrantType ?? "unknown"}'.",
                    metadata: metadata);
                return Results.Forbid(
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.UnsupportedGrantType,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "Only authorization_code (with PKCE) and refresh_token grants are supported."
                    }));
            }

            var authResult = await context.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var subject = authResult.Principal?.GetClaim(Claims.Subject);
            if (!authResult.Succeeded || !Guid.TryParse(subject, out var userId))
            {
                context.Items[OidcTokenErrorAuditHandler.AuditRecordedItemKey] = true;
                await identityService.RecordProtocolFailureAuditAsync(
                    email: authResult.Principal?.GetClaim(Claims.Email) ?? "[token-endpoint]",
                    userId: Guid.TryParse(subject, out var parsedSubject) ? parsedSubject : null,
                    outcome: "token_grant_rejected",
                    failureReason: "Invalid, expired, or revoked authorization code or refresh token.",
                    metadata: metadata);
                return Results.Forbid(
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The authorization code or refresh token is no longer valid."
                    }));
            }

            var user = await identityService.GetAsync(userId);
            if (user is null || !string.Equals(user.Role, Role.User, StringComparison.Ordinal))
            {
                context.Items[OidcTokenErrorAuditHandler.AuditRecordedItemKey] = true;
                await identityService.RecordProtocolFailureAuditAsync(
                    email: user?.Email ?? "[token-endpoint]",
                    userId: userId,
                    outcome: "account_unavailable",
                    failureReason: "Customer account unavailable or disallowed role during token grant.",
                    metadata: metadata);
                return Results.Forbid(
                    authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                    properties: new AuthenticationProperties(new Dictionary<string, string?>
                    {
                        [OpenIddictServerAspNetCoreConstants.Properties.Error] = Errors.InvalidGrant,
                        [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] =
                            "The customer account associated with this grant is unavailable."
                    }));
            }

            var scopes = authResult.Principal!.GetScopes();
            if (!scopes.Contains(oidcSettings.Audience))
            {
                scopes = scopes.Add(oidcSettings.Audience);
            }

            var principal = BuildCustomerPrincipal(user, oidcSettings, scopes);
            return Results.SignIn(principal, properties: null, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        })
        .Produces<Dictionary<string, object>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .Produces(StatusCodes.Status401Unauthorized)
        .AllowAnonymous()
        .RequireRateLimiting("authentication");

        app.MapMethods("/connect/userinfo", ["GET", "POST"], async (
            ClaimsPrincipal user,
            IIdentityService identityService) =>
        {
            if (!Guid.TryParse(user.FindFirstValue(Claims.Subject), out var userId))
            {
                return Results.Challenge();
            }

            var dto = await identityService.GetAsync(userId);
            if (dto is null)
            {
                return Results.Challenge();
            }

            return Results.Ok(new Dictionary<string, object>
            {
                [Claims.Subject] = dto.Id.ToString("N"),
                [Claims.Email] = dto.Email,
                [Claims.Role] = dto.Role
            });
        })
        .Produces<Dictionary<string, object>>(StatusCodes.Status200OK)
        .Produces(StatusCodes.Status400BadRequest)
        .RequireAuthorization();

        app.MapMethods("/connect/logout", ["GET", "POST"], () =>
            Results.SignOut(
                authenticationSchemes: [OpenIddictServerAspNetCoreDefaults.AuthenticationScheme],
                properties: new AuthenticationProperties { RedirectUri = "/" }))
            .ExcludeFromDescription()
            .AllowAnonymous();
    }

    private static ClaimsPrincipal BuildCustomerPrincipal(
        UserDto user,
        OidcSettings oidcSettings,
        System.Collections.Immutable.ImmutableArray<string> scopes)
    {
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType: Claims.Subject,
            roleType: Claims.Role);

        identity.SetClaim(Claims.Subject, user.Id.ToString("N"))
            .SetClaim(Claims.Email, user.Email)
            .SetClaim(Claims.Role, Role.User)
            .SetClaim(Claims.JwtId, Guid.NewGuid().ToString("N"));

        identity.SetScopes(scopes);
        identity.SetResources(oidcSettings.Audience);
        identity.SetDestinations(claim => claim.Type switch
        {
            Claims.Subject => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Email => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.Role => [Destinations.AccessToken, Destinations.IdentityToken],
            Claims.JwtId => [Destinations.AccessToken],
            _ => [Destinations.AccessToken]
        });

        return new ClaimsPrincipal(identity);
    }

    private static IResult RenderAuthorizeForm(
        HttpContext context,
        OpenIddictRequest request,
        string requestToken,
        string? emailValue,
        string? errorMessage,
        int statusCode = StatusCodes.Status200OK)
    {
        context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
        var sb = new StringBuilder(2048);
        sb.Append("""
            <!doctype html>
            <html lang="en">
            <head>
              <meta charset="utf-8">
              <meta name="viewport" content="width=device-width, initial-scale=1">
              <title>Davids Customer Sign In (OIDC)</title>
              <link rel="stylesheet" href="authorize.css">
            </head>
            <body>
              <main class="card">
                <span class="badge">OpenID Connect · Customer Identity</span>
                <h1>Sign in to your account</h1>
                <p class="sub">Authenticate with your Davids customer email and password using OAuth 2.1 Authorization Code + PKCE.</p>
            """);

        if (!string.IsNullOrWhiteSpace(errorMessage))
        {
            sb.Append($"<div class=\"error\" role=\"alert\">{WebUtility.HtmlEncode(errorMessage)}</div>");
        }

        sb.Append("<form method=\"post\" action=\"authorize\">");
        AppendHidden(sb, "request_token", requestToken);

        foreach (var parameter in request.GetParameters())
        {
            if (string.Equals(parameter.Key, "email", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parameter.Key, "password", StringComparison.OrdinalIgnoreCase) ||
                string.Equals(parameter.Key, "request_token", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            var value = (string?)parameter.Value;
            if (value is not null)
            {
                AppendHidden(sb, parameter.Key, value);
            }
        }

        sb.Append($"""
                <label for="email">Customer email</label>
                <input id="email" name="email" type="email" autocomplete="username" value="{WebUtility.HtmlEncode(emailValue ?? string.Empty)}" required>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
                <button type="submit">Continue</button>
              </form>
              <p class="meta">Client: <code>{WebUtility.HtmlEncode(request.ClientId ?? string.Empty)}</code> · RS256 JWKS</p>
            </main>
            </body>
            </html>
            """);

        return Results.Content(sb.ToString(), "text/html; charset=utf-8", Encoding.UTF8, statusCode);
    }

    private static void AppendHidden(StringBuilder sb, string name, string value)
        => sb.Append($"<input type=\"hidden\" name=\"{WebUtility.HtmlEncode(name)}\" value=\"{WebUtility.HtmlEncode(value)}\">");

    private static LoginRequestMetadata ExtractAuditMetadata(HttpContext context, string? clientId)
    {
        var ip = context.Connection.RemoteIpAddress;
        var normalizedIp = ip is null
            ? null
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        var correlationId = context.Request.Headers["X-Correlation-ID"].FirstOrDefault();
        if (string.IsNullOrWhiteSpace(correlationId))
        {
            correlationId = context.TraceIdentifier;
        }

        return new LoginRequestMetadata(
            ClientId: clientId,
            ClientIpAddress: normalizedIp,
            UserAgent: context.Request.Headers.UserAgent.ToString(),
            CorrelationId: correlationId);
    }
}
