using System;

namespace Davids.Services.Identity.Core.Entities;

public sealed class CustomerChangeAuditEntry
{
    public Guid Id { get; }
    public DateTime OccurredAtUtc { get; }
    public Guid TargetUserId { get; }
    public string TargetEmail { get; }
    public string Action { get; }
    public string ActorSub { get; }
    public string? ActorEmail { get; }
    public string ActorRole { get; }
    public string ActorAuthority { get; }
    public string ChangedFieldsJson { get; }
    public string? CorrelationId { get; }

    public CustomerChangeAuditEntry(
        Guid id,
        DateTime occurredAtUtc,
        Guid targetUserId,
        string targetEmail,
        string action,
        string actorSub,
        string? actorEmail,
        string actorRole,
        string actorAuthority,
        string changedFieldsJson,
        string? correlationId)
    {
        if (id == Guid.Empty)
        {
            throw new ArgumentException("Change audit ID cannot be empty.", nameof(id));
        }

        if (targetUserId == Guid.Empty)
        {
            throw new ArgumentException("Target user ID cannot be empty.", nameof(targetUserId));
        }

        if (string.IsNullOrWhiteSpace(action))
        {
            throw new ArgumentException("Audit action cannot be empty.", nameof(action));
        }

        Id = id;
        OccurredAtUtc = occurredAtUtc;
        TargetUserId = targetUserId;
        TargetEmail = Truncate(targetEmail?.Trim() ?? string.Empty, 320);
        Action = Truncate(action.Trim(), 64);
        ActorSub = Truncate(string.IsNullOrWhiteSpace(actorSub) ? targetUserId.ToString("D") : actorSub.Trim(), 64);
        ActorEmail = string.IsNullOrWhiteSpace(actorEmail) ? null : Truncate(actorEmail.Trim(), 320);
        ActorRole = Truncate(string.IsNullOrWhiteSpace(actorRole) ? Role.User : actorRole.Trim(), 32);
        ActorAuthority = Truncate(string.IsNullOrWhiteSpace(actorAuthority) ? "customer" : actorAuthority.Trim(), 32);
        ChangedFieldsJson = string.IsNullOrWhiteSpace(changedFieldsJson) ? "[]" : changedFieldsJson;
        CorrelationId = string.IsNullOrWhiteSpace(correlationId) ? null : Truncate(correlationId.Trim(), 128);
    }

    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}
