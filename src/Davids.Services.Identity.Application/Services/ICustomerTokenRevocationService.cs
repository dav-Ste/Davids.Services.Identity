using System;
using System.Threading;
using System.Threading.Tasks;

namespace Davids.Services.Identity.Application.Services;

public interface ICustomerTokenRevocationService
{
    Task RevokeAllForSubjectAsync(
        Guid userId,
        string? currentAccessTokenJti = null,
        DateTime? currentAccessTokenExpiresAtUtc = null,
        CancellationToken cancellationToken = default);
}
