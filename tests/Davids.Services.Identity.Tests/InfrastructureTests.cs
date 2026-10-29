using System.Text.Json;
using Davids.Services.Identity.Application.Events;
using Davids.Services.Identity.Infrastructure.Auth;
using Davids.Services.Identity.Infrastructure.Messaging;
using Davids.Services.Identity.Infrastructure.Secrets;
using Microsoft.AspNetCore.Hosting;
using Xunit;

namespace Davids.Services.Identity.Tests;

public sealed class InfrastructureTests
{
    [Fact]
    [Trait("Category", "Integration")]
    public async Task OpenApiAndLivenessAreServedInDevelopment()
    {
        using var factory = new IdentityFactory().WithWebHostBuilder(b => b.UseEnvironment("Development"));
        using var client = factory.CreateClient(new() { BaseAddress = new Uri("https://localhost") });
        Assert.True((await client.GetAsync("/alive")).IsSuccessStatusCode);
        Assert.Contains("openapi", await (await client.GetAsync("/openapi/v1.json")).Content.ReadAsStringAsync());
    }

    [Fact]
    [Trait("Category", "Integration")]
    public async Task OpenApiIsNotExposedOutsideDevelopment()
    {
        using var factory = new IdentityFactory();
        using var client = factory.CreateIdentityClient();
        Assert.Equal(System.Net.HttpStatusCode.NotFound, (await client.GetAsync("/openapi/v1.json")).StatusCode);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void VaultFlatteningMapsNestedOidcSecretData()
    {
        var ephemeralPem = OidcSettings.GenerateRsaPrivateKeyPem();
        var json = JsonSerializer.Serialize(new
        {
            Oidc = new { SigningKeyPem = ephemeralPem },
            ConnectionStrings = new { identitydb = "Server=sql" }
        });
        using var document = JsonDocument.Parse(json);
        var values = VaultConfiguration.Flatten(document.RootElement);
        Assert.Equal(ephemeralPem, values["Oidc:SigningKeyPem"]);
        Assert.Equal("Server=sql", values["ConnectionStrings:identitydb"]);
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void OidcSettingsRejectMissingOrUndersizedRsaKey()
    {
        Assert.Throws<InvalidOperationException>(() => new OidcSettings().InitializeKeys(requireExplicitEncryptionKey: false));
        using var weakRsa = System.Security.Cryptography.RSA.Create(1024);
        var weakSettings = new OidcSettings { SigningKeyPem = weakRsa.ExportPkcs8PrivateKeyPem() };
        Assert.Throws<InvalidOperationException>(() => weakSettings.InitializeKeys(requireExplicitEncryptionKey: false));
    }

    [Fact]
    [Trait("Category", "Unit")]
    public void SignedUpRoutingKeyMatchesLegacyCustomersContract()
    {
        Assert.Equal("signed_up", JsonNamingPolicy.SnakeCaseLower.ConvertName(nameof(SignedUp)));
        Assert.Equal("signed_in", JsonNamingPolicy.SnakeCaseLower.ConvertName(nameof(SignedIn)));
    }
}
