using System;
using Davids.Services.Identity.Core.Entities;

namespace Davids.Services.Identity.Application.DTO;

public sealed record LoginRequestMetadata(
    string? ClientId = null,
    string? ClientIpAddress = null,
    string? UserAgent = null,
    string? CorrelationId = null);

public sealed record LoginAuditDto(
    Guid Id,
    DateTime OccurredAtUtc,
    Guid? UserId,
    string Email,
    bool Succeeded,
    string Outcome,
    string? FailureReason,
    string? ClientId,
    string? ClientIpAddress,
    string? UserAgent,
    string? CorrelationId)
{
    public static LoginAuditDto FromEntity(LoginAuditEntry entry)
        => new(
            entry.Id,
            entry.OccurredAtUtc,
            entry.UserId,
            entry.Email,
            entry.Succeeded,
            entry.Outcome,
            entry.FailureReason,
            entry.ClientId,
            entry.ClientIpAddress,
            entry.UserAgent,
            entry.CorrelationId);
}
