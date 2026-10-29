using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Design;

namespace Davids.Services.Identity.Infrastructure.Persistence;

public sealed class DesignTimeFactory : IDesignTimeDbContextFactory<IdentityDbContext>
{
    public IdentityDbContext CreateDbContext(string[] args)
    {
        var connection = Environment.GetEnvironmentVariable("ConnectionStrings__identitydb")
            ?? "Server=localhost;Database=davids_identity;Integrated Security=true;TrustServerCertificate=true";
        return new IdentityDbContext(
            new DbContextOptionsBuilder<IdentityDbContext>()
                .UseSqlServer(connection)
                .UseOpenIddict()
                .Options);
    }
}
