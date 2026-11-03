using System.Diagnostics.Metrics;

namespace Davids.Services.Identity.Infrastructure.Auth;

public static class IdentitySecurityMetrics
{
    public const string MeterName = "Davids.Security.Audit";

    private static readonly Meter AuditMeter = new(MeterName, "1.0.0");

    private static readonly Counter<long> LoginAuditCounter =
        AuditMeter.CreateCounter<long>("davids.security.login_audit", unit: "{event}");

    private static readonly Counter<long> TokenRevokedCounter =
        AuditMeter.CreateCounter<long>("davids.security.token_revoked", unit: "{token}");

    private static readonly Counter<long> ChangeAuditCounter =
        AuditMeter.CreateCounter<long>("davids.security.change_audit", unit: "{event}");

    public static void RecordLoginAudit(string? outcome, bool succeeded)
    {
        LoginAuditCounter.Add(
            1,
            new KeyValuePair<string, object?>("domain", "customer"),
            new KeyValuePair<string, object?>("outcome", outcome ?? "unknown"),
            new KeyValuePair<string, object?>("succeeded", succeeded ? "true" : "false"));
    }

    public static void RecordTokenRevocation(string? source)
    {
        TokenRevokedCounter.Add(
            1,
            new KeyValuePair<string, object?>("domain", "customer"),
            new KeyValuePair<string, object?>("source", source ?? "unknown"));
    }

    public static void RecordChangeAudit(string? action, string? actorAuthority)
    {
        ChangeAuditCounter.Add(
            1,
            new KeyValuePair<string, object?>("service", "identity"),
            new KeyValuePair<string, object?>("action", action ?? "unknown"),
            new KeyValuePair<string, object?>("actor_authority", actorAuthority ?? "unknown"));
    }
}
