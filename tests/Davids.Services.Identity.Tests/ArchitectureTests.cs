using System.Security.Cryptography;
using Davids.Services.Identity.Application.Services.Identity;
using Davids.Services.Identity.Core.Entities;
using Davids.Services.Identity.Infrastructure;
using Davids.Services.Identity.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting.Internal;
using Xunit;

namespace Davids.Services.Identity.Tests;

[Trait("Category", "Unit")]
public sealed class ArchitectureTests
{
    [Fact]
    public void CoreLayerHasZeroOuterLayerOrInfrastructureFrameworkDependencies()
    {
        var coreRefs = typeof(User).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(coreRefs, n => n.StartsWith("Davids.", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("OpenIddict", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(coreRefs, n => n.StartsWith("RabbitMQ", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void ApplicationLayerDependsOnlyOnCoreAndNeverOnInfrastructureOrApi()
    {
        var appRefs = typeof(IdentityService).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.Contains("Davids.Services.Identity.Core", appRefs, StringComparer.Ordinal);
        Assert.DoesNotContain("Davids.Services.Identity.Infrastructure", appRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Davids.Services.Identity.Api", appRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain("Davids.ServiceDefaults", appRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(appRefs, n => n.StartsWith("Microsoft.EntityFrameworkCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(appRefs, n => n.StartsWith("Microsoft.AspNetCore", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(appRefs, n => n.StartsWith("OpenIddict", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(appRefs, n => n.StartsWith("RabbitMQ", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void InfrastructureAndApiLayersFollowInwardDependenciesAndMaintainAdminIdentityIsolation()
    {
        var infraRefs = typeof(IdentityDbContext).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain("Davids.Services.Identity.Api", infraRefs, StringComparer.OrdinalIgnoreCase);
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.Services.AdminIdentity", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.Services.Customers", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.APIGateway", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(infraRefs, n => n.StartsWith("Davids.Frontend", StringComparison.OrdinalIgnoreCase));

        var apiRefs = typeof(Program).Assembly.GetReferencedAssemblies()
            .Select(a => a.Name ?? string.Empty)
            .ToArray();

        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.Services.AdminIdentity", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.Services.Customers", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.APIGateway", StringComparison.OrdinalIgnoreCase));
        Assert.DoesNotContain(apiRefs, n => n.StartsWith("Davids.Frontend", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void EfCoreRuntimeModelMatchesMigrationsSnapshotWithoutPendingChanges()
    {
        using var designTimeDb = new DesignTimeFactory().CreateDbContext([]);
        Assert.False(
            designTimeDb.Database.HasPendingModelChanges(),
            "Design-time IdentityDbContext has pending EF Core model changes relative to IdentityDbContextModelSnapshot.");

        using var rsa = RSA.Create(2048);
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["ConnectionStrings:identitydb"] = "Server=localhost;Database=davids_identity;Integrated Security=true;TrustServerCertificate=true",
                ["Oidc:SigningKeyPem"] = rsa.ExportRSAPrivateKeyPem()
            })
            .Build();
        var services = new ServiceCollection();
        services.AddIdentityInfrastructure(
            configuration,
            new HostingEnvironment { EnvironmentName = "Development", ApplicationName = "Davids.Services.Identity.Tests" });

        using var provider = services.BuildServiceProvider();
        using var scope = provider.CreateScope();
        var runtimeDb = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        Assert.False(
            runtimeDb.Database.HasPendingModelChanges(),
            "Runtime DI IdentityDbContext has pending EF Core model changes relative to IdentityDbContextModelSnapshot.");
    }
}
