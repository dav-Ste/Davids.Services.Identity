using System;

namespace Davids.Services.Identity.Core.Entities;

public sealed class LoginAuditEntry
{
    public Guid Id { get; }
    public DateTime OccurredAtUtc { get; }
    public Guid? UserId { get; }
    public string Email { get; }
    public bool Succeeded { get; }
    public string Outcome { get; }
    public string? FailureReason { get; }
    public string? ClientId { get; }
    public string? ClientIpAddress { get; }
    public string? UserAgent { get; }
    public string? CorrelationId { get; }

    public LoginAuditEntry(
        Guid id,
        DateTime occurredAtUtc,
        Guid? userId,
        string? email,
        bool succeeded,
        string? outcome,
        string? failureReason = null,
        string? clientId = null,
        string? clientIpAddress = null,
        string? userAgent = null,
        string? correlationId = null)
    {
        Id = id == Guid.Empty ? Guid.NewGuid() : id;
        OccurredAtUtc = occurredAtUtc;
        UserId = userId;
        Email = Sanitize(email, 320, "[empty]").ToLowerInvariant();
        Succeeded = succeeded;
        Outcome = Sanitize(outcome, 64, succeeded ? "succeeded" : "failed");
        FailureReason = SanitizeOptional(failureReason, 256);
        ClientId = SanitizeOptional(clientId, 128);
        ClientIpAddress = SanitizeOptional(clientIpAddress, 64);
        UserAgent = SanitizeOptional(userAgent, 512);
        CorrelationId = SanitizeOptional(correlationId, 128);
    }

    private static string Sanitize(string? value, int maxLength, string fallback)
    {
        var cleaned = SanitizeOptional(value, maxLength);
        return string.IsNullOrWhiteSpace(cleaned) ? fallback : cleaned;
    }

    private static string? SanitizeOptional(string? value, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        Span<char> buffer = stackalloc char[Math.Min(value.Length, maxLength)];
        var count = 0;
        foreach (var ch in value.AsSpan().Trim())
        {
            if (char.IsControl(ch))
            {
                continue;
            }

            buffer[count++] = ch;
            if (count == buffer.Length)
            {
                break;
            }
        }

        return count == 0 ? null : new string(buffer[..count]);
    }
}
