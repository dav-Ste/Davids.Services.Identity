using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Davids.Services.Identity.Core.Entities;

namespace Davids.Services.Identity.Core.Repositories;

public interface ICustomerChangeAuditRepository
{
    Task<IReadOnlyList<CustomerChangeAuditEntry>> BrowseForUserAsync(Guid targetUserId, int limit = 50);
    Task<IReadOnlyList<CustomerChangeAuditEntry>> BrowseRecentAsync(
        int limit = 100,
        Guid? targetUserId = null,
        string? actorSub = null);
}
