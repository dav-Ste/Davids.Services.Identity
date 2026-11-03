using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Davids.Services.Identity.Application.Commands;
using Davids.Services.Identity.Application.DTO;

namespace Davids.Services.Identity.Application.Services
{
    public interface IIdentityService
    {
        Task<UserDto?> GetAsync(Guid id);
        Task<UserDto> AuthenticateAsync(string email, string password, LoginRequestMetadata? metadata = null);
        Task SignUpAsync(SignUp command, string? correlationId = null);
        Task ChangeMyPasswordAsync(Guid userId, ChangeCustomerPassword command, IdentityActorMetadata actor);
        Task<UserDto> ChangeMyEmailAsync(Guid userId, ChangeCustomerEmail command, IdentityActorMetadata actor);
        Task<UserDto> UpdateCustomerEmailByEmployeeAsync(
            Guid targetUserId,
            EmployeeUpdateCustomerEmail command,
            IdentityActorMetadata actor);
        Task<UserDto> UnlockCustomerByEmployeeAsync(Guid targetUserId, IdentityActorMetadata actor);
        Task RecordProtocolFailureAuditAsync(
            string? email,
            Guid? userId,
            string outcome,
            string? failureReason,
            LoginRequestMetadata? metadata = null);
        Task<IReadOnlyList<LoginAuditDto>> GetLoginAuditsAsync(Guid userId, int limit = 50);
        Task<IReadOnlyList<CustomerChangeAuditDto>> GetMyChangeAuditsAsync(Guid userId, int limit = 50);
        Task<IReadOnlyList<CustomerChangeAuditDto>> BrowseChangeAuditsAsync(
            int limit = 100,
            Guid? targetUserId = null,
            string? actorSub = null);
    }
}
