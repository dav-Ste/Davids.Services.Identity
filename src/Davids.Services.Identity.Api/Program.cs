using System.Security.Claims;
using System.Threading.RateLimiting;
using Davids.ServiceDefaults;
using Davids.Services.Identity.Api;
using Davids.Services.Identity.Application.Commands;
using Davids.Services.Identity.Application.DTO;
using Davids.Services.Identity.Application.Services;
using Davids.Services.Identity.Infrastructure;
using Davids.Services.Identity.Infrastructure.Auth;
using Davids.Services.Identity.Infrastructure.Persistence;
using Davids.Services.Identity.Infrastructure.Secrets;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);
await builder.Configuration.LoadVaultAsync();
builder.AddServiceDefaults();
builder.Services.AddTrustedForwardedHeaders(builder.Configuration, builder.Environment);
builder.Services.AddIdentityInfrastructure(builder.Configuration, builder.Environment);
builder.Services.AddDataProtection()
    .ConfigureDavidsDataProtection(
        builder.Configuration,
        builder.Environment,
        applicationName: "davids-identity",
        externalRepositoryFactory: sp => new IdentityDataProtectionXmlRepository(sp.GetRequiredService<IServiceScopeFactory>()));
builder.Services.AddExceptionHandler<ApiExceptionHandler>();
builder.Services.AddProblemDetails();
builder.Services.AddIdentityOpenApi();
var authPermitLimit = Math.Max(1, builder.Configuration.GetValue("RateLimiting:AuthPermitLimit", 20));
var authWindowSeconds = Math.Max(1, builder.Configuration.GetValue("RateLimiting:WindowSeconds", 60));
builder.Services.AddRateLimiter(o =>
{
    o.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    o.OnRejected = async (rejectedContext, cancellationToken) =>
    {
        var ip = rejectedContext.HttpContext.Connection.RemoteIpAddress;
        var clientIp = ip is null
            ? "unknown"
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        var correlationId = rejectedContext.HttpContext.Request.Headers["X-Correlation-ID"].FirstOrDefault()
            ?? rejectedContext.HttpContext.TraceIdentifier;
        DavidsSecurityMetrics.RecordRateLimitRejection("davids-identity", "authentication");
        rejectedContext.HttpContext.RequestServices
            .GetRequiredService<ILoggerFactory>()
            .CreateLogger("Davids.Security.Audit")
            .LogWarning(
                "Audit: rate-limit rejected customer authentication request from {ClientIp} on {Path} (SecurityAuditEvent={SecurityAuditEvent}, CorrelationId={CorrelationId}).",
                clientIp,
                rejectedContext.HttpContext.Request.Path.Value,
                "RateLimitRejected",
                correlationId);

        rejectedContext.HttpContext.Response.StatusCode = StatusCodes.Status429TooManyRequests;
        if (rejectedContext.Lease.TryGetMetadata(MetadataName.RetryAfter, out var retryAfter))
        {
            var seconds = Math.Max(1, (int)Math.Ceiling(retryAfter.TotalSeconds));
            rejectedContext.HttpContext.Response.Headers.RetryAfter =
                seconds.ToString(System.Globalization.CultureInfo.InvariantCulture);
        }

        await rejectedContext.HttpContext.Response.WriteAsJsonAsync(new
        {
            code = "rate_limit_exceeded",
            reason = "Too many authentication requests. Please try again later."
        }, cancellationToken);
    };
    o.AddPolicy("authentication", context =>
    {
        var ip = context.Connection.RemoteIpAddress;
        var partitionKey = ip is null
            ? "unknown"
            : (ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4().ToString() : ip.ToString());
        return RateLimitPartition.GetFixedWindowLimiter(
            partitionKey,
            _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = authPermitLimit,
                Window = TimeSpan.FromSeconds(authWindowSeconds),
                QueueLimit = 0
            });
    });
});

var app = builder.Build();

if (builder.Configuration.GetValue<bool>("Database:ApplyMigrations"))
{
    if (!app.Environment.IsDevelopment())
    {
        throw new InvalidOperationException("Automatic migration is development-only.");
    }

    await using var scope = app.Services.CreateAsyncScope();
    await scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.MigrateAsync();
    await app.Services.GetRequiredService<OidcApplicationSeeder>().EnsureSeededAsync();
}

app.UseTrustedForwardedHeaders();
app.UseExceptionHandler();
if (!(app.Environment.IsDevelopment() && builder.Configuration.GetValue<bool>("Http:AllowInsecureDevelopment")))
{
    app.UseHttpsRedirection();
}

// Gracefully absorb client-aborted requests inside user code so Visual Studio Just-My-Code never halts on TaskCanceledException.
app.Use(async (context, next) =>
{
    try
    {
        if (context.Request.Path.StartsWithSegments("/connect") ||
            context.Request.Path.StartsWithSegments("/.well-known"))
        {
            await context.RequestServices.GetRequiredService<OidcApplicationSeeder>()
                .EnsureSeededAsync(CancellationToken.None);
        }

        await next();
    }
    catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
    {
        if (!context.Response.HasStarted)
        {
            context.Response.StatusCode = StatusCodes.Status499ClientClosedRequest;
        }
    }
});

app.UseAuthentication();
app.UseAuthorization();
app.UseRateLimiter();
app.MapDefaultEndpoints();

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
    app.UseSwaggerUI(options =>
    {
        options.RoutePrefix = "docs";
        options.SwaggerEndpoint("../openapi/v1.json", "Davids Identity OIDC v1");
    });
}

app.MapGet("/", () => Results.Text("Davids Identity OIDC Service"))
    .ExcludeFromDescription()
    .AllowAnonymous();
app.MapIdentityOidcEndpoints();

app.MapGet("/me", async (ClaimsPrincipal user, IIdentityService service) =>
{
    if (!Guid.TryParse(user.FindFirstValue("sub"), out var userId))
    {
        return Results.Unauthorized();
    }

    var dto = await service.GetAsync(userId);
    return dto is null ? Results.NotFound() : Results.Ok(dto);
})
.Produces<UserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status404NotFound)
.RequireAuthorization();

app.MapGet("/me/login-audits", async (int? limit, ClaimsPrincipal user, IIdentityService service) =>
{
    if (limit is < 1 or > 200)
    {
        return Results.BadRequest(new { code = "invalid_limit", reason = "Limit must be between 1 and 200." });
    }

    if (!Guid.TryParse(user.FindFirstValue("sub"), out var userId))
    {
        return Results.Unauthorized();
    }

    var audits = await service.GetLoginAuditsAsync(userId, limit ?? 50);
    return Results.Ok(audits);
})
.Produces<IReadOnlyList<LoginAuditDto>>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.RequireAuthorization();

app.MapGet("/users/{userId:guid}", async (Guid userId, HttpContext httpContext, ClaimsPrincipal user, IIdentityService service) =>
{
    if (httpContext.Request.QueryString.HasValue)
    {
        return Results.BadRequest(new { code = "unexpected_query_parameters", reason = "User resource endpoint does not accept query parameters." });
    }

    if (!Guid.TryParse(user.FindFirstValue("sub"), out var subjectId) || subjectId != userId)
    {
        return Results.Forbid();
    }

    var dto = await service.GetAsync(userId);
    return dto is null ? Results.NotFound() : Results.Ok(dto);
})
.Produces<UserDto>(StatusCodes.Status200OK)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status404NotFound)
.RequireAuthorization();

var commands = app.MapGroup("").RequireRateLimiting("authentication").AddEndpointFilter<TransactionFilter>();
commands.MapPost("/sign-up", async (SignUp command, IIdentityService service) =>
{
    if (command is null)
    {
        return Results.BadRequest(new { code = "invalid_request", reason = "Request body is required." });
    }

    await service.SignUpAsync(command);
    return Results.Created("identity/me", (object?)null);
})
.Produces(StatusCodes.Status201Created)
.Produces(StatusCodes.Status400BadRequest)
.Produces(StatusCodes.Status409Conflict);

app.Run();
public partial class Program;
