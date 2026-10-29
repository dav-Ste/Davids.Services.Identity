using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Davids.Services.Identity.Core.Entities;

namespace Davids.Services.Identity.Core.Repositories;

public interface ILoginAuditRepository
{
    Task AddAsync(LoginAuditEntry entry);
    Task<IReadOnlyList<LoginAuditEntry>> BrowseForUserAsync(Guid userId, int limit = 50);
}
