using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Serialization;
using Davids.Services.Identity.Core.Entities;

namespace Davids.Services.Identity.Application.DTO;

public sealed record IdentityActorMetadata(
    string ActorSub,
    string? ActorEmail,
    string ActorRole,
    string ActorAuthority,
    string? CorrelationId = null,
    string? CurrentAccessTokenJti = null,
    DateTime? CurrentAccessTokenExpiresAtUtc = null);

public sealed record CustomerFieldChangeDto(
    [property: JsonPropertyName("field")] string Field,
    [property: JsonPropertyName("oldValue")] string? OldValue,
    [property: JsonPropertyName("newValue")] string? NewValue);

public sealed record CustomerChangeAuditDto(
    Guid Id,
    string Service,
    string Action,
    string TargetType,
    string TargetId,
    string? TargetLabel,
    string ActorSub,
    string? ActorEmail,
    string ActorRole,
    string ActorAuthority,
    IReadOnlyList<CustomerFieldChangeDto> Changes,
    string? CorrelationId,
    DateTime OccurredAtUtc)
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase
    };

    public static CustomerChangeAuditDto FromEntity(CustomerChangeAuditEntry entry)
    {
        var changes = string.IsNullOrWhiteSpace(entry.ChangedFieldsJson)
            ? []
            : JsonSerializer.Deserialize<List<CustomerFieldChangeDto>>(entry.ChangedFieldsJson, JsonOptions) ?? [];

        return new CustomerChangeAuditDto(
            entry.Id,
            "identity",
            entry.Action,
            "customer_account",
            entry.TargetUserId.ToString("D"),
            entry.TargetEmail,
            entry.ActorSub,
            entry.ActorEmail,
            entry.ActorRole,
            entry.ActorAuthority,
            changes,
            entry.CorrelationId,
            entry.OccurredAtUtc);
    }
}
