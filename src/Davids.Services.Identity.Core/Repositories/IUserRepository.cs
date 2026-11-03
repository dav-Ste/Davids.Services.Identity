using System;
using System.Threading.Tasks;
using Davids.Services.Identity.Core.Entities;

namespace Davids.Services.Identity.Core.Repositories
{
    public interface IUserRepository
    {
        Task<User?> GetAsync(Guid id);
        Task<User?> GetAsync(string email);
        Task AddAsync(User user, CustomerChangeAuditEntry? changeAudit = null);
        Task UpdateAsync(User user, CustomerChangeAuditEntry? changeAudit = null);
    }
}
