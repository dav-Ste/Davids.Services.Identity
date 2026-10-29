using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;

namespace Davids.Services.Identity.Infrastructure.Persistence;

public sealed class IdentityDataProtectionXmlRepository(IServiceScopeFactory scopeFactory) : IXmlRepository
{
    public IReadOnlyCollection<XElement> GetAllElements()
    {
        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        if (db.Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true)
        {
            db.Database.EnsureCreated();
        }

        var rows = db.DataProtectionKeys
            .AsNoTracking()
            .OrderBy(x => x.Id)
            .Select(x => x.Xml)
            .ToList();

        return rows.Select(XElement.Parse).ToList().AsReadOnly();
    }

    public void StoreElement(XElement element, string? friendlyName)
    {
        ArgumentNullException.ThrowIfNull(element);

        using var scope = scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<IdentityDbContext>();
        if (db.Database.ProviderName?.Contains("Sqlite", StringComparison.OrdinalIgnoreCase) == true)
        {
            db.Database.EnsureCreated();
        }

        var serialized = element.ToString(SaveOptions.DisableFormatting);
        var existing = !string.IsNullOrWhiteSpace(friendlyName)
            ? db.DataProtectionKeys.FirstOrDefault(x => x.FriendlyName == friendlyName)
            : null;

        if (existing is not null)
        {
            existing.Xml = serialized;
        }
        else
        {
            db.DataProtectionKeys.Add(new IdentityDataProtectionKeyRow
            {
                FriendlyName = friendlyName,
                Xml = serialized,
                CreatedAtUtc = DateTime.UtcNow
            });
        }

        db.SaveChanges();
    }
}
