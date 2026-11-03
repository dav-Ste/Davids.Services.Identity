using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Security.Cryptography;
using Davids.Services.Identity.Application.Commands;
using Davids.Services.Identity.Application.DTO;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Davids.Services.Identity.Tests;

[Trait("Category", "Integration")]
public sealed class CustomerSelfServiceAndEmployeeSupportTests
{
    private const string InitialPassword = "Correct-horse-123!";
    private const string RotatedPassword = "Rotated-horse-456!";
    private const string AdminIssuer = "https://admin-oidc.local/";

    private static string MintEmployeeToken(RSA adminRsa, Guid employeeId, string email, string role)
    {
        var spki = adminRsa.ExportSubjectPublicKeyInfo();
        var kid = Base64UrlEncoder.Encode(SHA256.HashData(spki))[..16];
        var signingKey = new RsaSecurityKey(adminRsa.ExportParameters(includePrivateParameters: true))
        {
            KeyId = kid
        };

        var handler = new JwtSecurityTokenHandler();
        return handler.WriteToken(new JwtSecurityToken(
            issuer: AdminIssuer,
            audience: "davids-admin",
            claims:
            [
                new Claim("sub", employeeId.ToString("N")),
                new Claim("email", email),
                new Claim("role", role),
                new Claim("jti", Guid.NewGuid().ToString("N"))
            ],
            notBefore: DateTime.UtcNow.AddSeconds(-5),
            expires: DateTime.UtcNow.AddMinutes(10),
            signingCredentials: new SigningCredentials(signingKey, SecurityAlgorithms.RsaSha256)));
    }

    [Fact]
    public async Task CustomerSelfServiceAndEmployeeSupportEmitEmailOutboxAndTransactionalChangeAudits()
    {
        using var adminRsa = RSA.Create(2048);
        var adminPublicPem = adminRsa.ExportSubjectPublicKeyInfoPem();

        using var baseFactory = new IdentityFactory();
        using var factory = baseFactory.WithWebHostBuilder(b =>
        {
            b.UseSetting("AdminOidc:Issuer", AdminIssuer);
            b.UseSetting("AdminOidc:Audience", "davids-admin");
            b.UseSetting("AdminOidc:PublicKeyPem", adminPublicPem);
            b.UseSetting("RateLimiting:AuthPermitLimit", "100");
        });

        using var client = factory.CreateClient(new()
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        using (var scope = factory.Services.CreateScope())
        {
            scope.ServiceProvider.GetRequiredService<IdentityDbContext>().Database.EnsureCreated();
        }

        var customerTokens = await IdentityTests.RegisterAndSignInOidcAsync(client, "customer.one@example.com");

        // 1. Customer reads /me and changes their own email via PUT /me/email -> emits email_changed outbox + change audit.
        using var meReq = new HttpRequestMessage(HttpMethod.Get, "/me");
        meReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerTokens.AccessToken);
        var meDto = await (await client.SendAsync(meReq)).Content.ReadFromJsonAsync<UserDto>();
        Assert.NotNull(meDto);

        using var selfEmailReq = new HttpRequestMessage(HttpMethod.Put, "/me/email")
        {
            Content = JsonContent.Create(new ChangeCustomerEmail(InitialPassword, "customer.self@example.com"))
        };
        selfEmailReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerTokens.AccessToken);
        selfEmailReq.Headers.Add("X-Correlation-Id", "corr-self-email");
        using var selfEmailResp = await client.SendAsync(selfEmailReq);
        Assert.Equal(HttpStatusCode.OK, selfEmailResp.StatusCode);
        var updatedSelf = await selfEmailResp.Content.ReadFromJsonAsync<UserDto>();
        Assert.Equal("customer.self@example.com", updatedSelf!.Email);

        // 2. Customer inspects own /me/change-audits, then rotates password via PUT /me/password -> revokes token!
        using var myAuditsReq = new HttpRequestMessage(HttpMethod.Get, "/me/change-audits");
        myAuditsReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerTokens.AccessToken);
        var myAudits = await (await client.SendAsync(myAuditsReq)).Content.ReadFromJsonAsync<List<CustomerChangeAuditDto>>();
        Assert.NotNull(myAudits);
        Assert.Contains(myAudits!, a =>
            a.Action == "email_changed" &&
            a.ActorAuthority == "customer" &&
            a.Changes.Any(c => c.Field == "email" && c.OldValue == "customer.one@example.com" && c.NewValue == "customer.self@example.com"));

        using var pwReq = new HttpRequestMessage(HttpMethod.Put, "/me/password")
        {
            Content = JsonContent.Create(new ChangeCustomerPassword(InitialPassword, RotatedPassword))
        };
        pwReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerTokens.AccessToken);
        Assert.Equal(HttpStatusCode.NoContent, (await client.SendAsync(pwReq)).StatusCode);

        using var postRevokeMeReq = new HttpRequestMessage(HttpMethod.Get, "/me");
        postRevokeMeReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", customerTokens.AccessToken);
        Assert.Equal(HttpStatusCode.Unauthorized, (await client.SendAsync(postRevokeMeReq)).StatusCode);

        // 3. Employee RBAC via AdminBearer public key:
        //    - support can GET /users/{id}, PUT /users/{id}/email, POST /users/{id}/unlock, GET /change-audits
        //    - auditor can GET /users/{id} and GET /change-audits, but receives 403 on PUT/POST mutations
        var supportId = Guid.NewGuid();
        var auditorId = Guid.NewGuid();
        var supportBearer = MintEmployeeToken(adminRsa, supportId, "support@davids.local", "support");
        var auditorBearer = MintEmployeeToken(adminRsa, auditorId, "auditor@davids.local", "auditor");

        using var auditorMutateReq = new HttpRequestMessage(HttpMethod.Put, $"/users/{meDto!.Id}/email")
        {
            Content = JsonContent.Create(new EmployeeUpdateCustomerEmail("blocked@example.com"))
        };
        auditorMutateReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auditorBearer);
        Assert.Equal(HttpStatusCode.Forbidden, (await client.SendAsync(auditorMutateReq)).StatusCode);

        using var supportGetReq = new HttpRequestMessage(HttpMethod.Get, $"/users/{meDto.Id}");
        supportGetReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportBearer);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(supportGetReq)).StatusCode);

        using var supportEmailReq = new HttpRequestMessage(HttpMethod.Put, $"/users/{meDto.Id}/email")
        {
            Content = JsonContent.Create(new EmployeeUpdateCustomerEmail("customer.employee@example.com"))
        };
        supportEmailReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportBearer);
        supportEmailReq.Headers.Add("X-Correlation-Id", "corr-emp-email");
        using var supportEmailResp = await client.SendAsync(supportEmailReq);
        Assert.Equal(HttpStatusCode.OK, supportEmailResp.StatusCode);

        using var supportUnlockReq = new HttpRequestMessage(HttpMethod.Post, $"/users/{meDto.Id}/unlock");
        supportUnlockReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", supportBearer);
        Assert.Equal(HttpStatusCode.OK, (await client.SendAsync(supportUnlockReq)).StatusCode);

        // 4. Verify SQL Outbox contains two email_changed events and auditor can read full customer change audit trail.
        using (var scope = factory.Services.CreateScope())
        {
            var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
            var emailOutbox = await db.Outbox.AsNoTracking()
                .Where(m => m.Type == "email_changed")
                .ToListAsync();
            Assert.Equal(2, emailOutbox.Count);
        }

        using var auditorAuditsReq = new HttpRequestMessage(HttpMethod.Get, $"/change-audits?targetUserId={meDto.Id}");
        auditorAuditsReq.Headers.Authorization = new AuthenticationHeaderValue("Bearer", auditorBearer);
        using var auditorAuditsResp = await client.SendAsync(auditorAuditsReq);
        Assert.Equal(HttpStatusCode.OK, auditorAuditsResp.StatusCode);
        var allAudits = await auditorAuditsResp.Content.ReadFromJsonAsync<List<CustomerChangeAuditDto>>();
        Assert.NotNull(allAudits);
        Assert.Contains(allAudits!, a => a.Action == "customer_signed_up");
        Assert.Contains(allAudits!, a =>
            a.Action == "password_changed" &&
            a.ActorAuthority == "customer" &&
            a.Changes.All(c => c.NewValue == "[REDACTED]"));
        Assert.Contains(allAudits!, a =>
            a.Action == "email_changed" &&
            a.ActorAuthority == "employee" &&
            a.ActorSub == supportId.ToString("D") &&
            a.ActorRole == "support" &&
            a.CorrelationId == "corr-emp-email");
        Assert.Contains(allAudits!, a => a.Action == "account_unlocked" && a.ActorAuthority == "employee");
    }
}
