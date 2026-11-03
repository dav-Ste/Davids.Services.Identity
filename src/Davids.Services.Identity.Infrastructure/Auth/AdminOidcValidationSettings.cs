using System.Security.Cryptography;
using Microsoft.IdentityModel.Tokens;

namespace Davids.Services.Identity.Infrastructure.Auth;

public sealed class AdminOidcValidationSettings
{
    public const string SchemeName = "AdminBearer";

    public string? Authority { get; set; }
    public string? Issuer { get; set; }
    public string Audience { get; set; } = "davids-admin";
    public string? PublicKeyPem { get; set; }
    public bool? RequireHttpsMetadata { get; set; }

    public bool IsConfigured =>
        !string.IsNullOrWhiteSpace(Authority) ||
        !string.IsNullOrWhiteSpace(PublicKeyPem);

    public string? MetadataAddress =>
        string.IsNullOrWhiteSpace(Authority)
            ? null
            : Authority.TrimEnd('/') + "/.well-known/openid-configuration";

    public string? EffectiveIssuer
    {
        get
        {
            var raw = !string.IsNullOrWhiteSpace(Issuer) ? Issuer : Authority;
            return string.IsNullOrWhiteSpace(raw) ? null : raw.TrimEnd('/') + "/";
        }
    }

    public RsaSecurityKey? ValidateAndResolveStaticPublicKey()
    {
        if (!IsConfigured)
        {
            return null;
        }

        if (string.IsNullOrWhiteSpace(Audience))
        {
            throw new InvalidOperationException("AdminOidc:Audience must be configured.");
        }

        if (!string.IsNullOrWhiteSpace(Authority) &&
            (!Uri.TryCreate(Authority, UriKind.Absolute, out var authorityUri) ||
             (authorityUri.Scheme != Uri.UriSchemeHttp && authorityUri.Scheme != Uri.UriSchemeHttps)))
        {
            throw new InvalidOperationException("AdminOidc:Authority must be an absolute HTTP(S) URI.");
        }

        if (string.IsNullOrWhiteSpace(PublicKeyPem))
        {
            return null;
        }

        var trimmed = PublicKeyPem.Trim();
        if (trimmed.Contains("PRIVATE KEY", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(
                "AdminOidc:PublicKeyPem must contain an RSA PUBLIC key only; Customer Identity never holds Admin signing keys.");
        }

        using var rsa = RSA.Create();
        try
        {
            rsa.ImportFromPem(trimmed);
        }
        catch (Exception ex) when (ex is CryptographicException or ArgumentException)
        {
            throw new InvalidOperationException("AdminOidc:PublicKeyPem is not a valid PEM RSA public key.", ex);
        }

        if (rsa.KeySize < 2048)
        {
            throw new InvalidOperationException("AdminOidc:PublicKeyPem must be at least 2048 bits.");
        }

        var parameters = rsa.ExportParameters(includePrivateParameters: false);
        var spki = rsa.ExportSubjectPublicKeyInfo();
        var kid = Base64UrlEncoder.Encode(SHA256.HashData(spki))[..16];
        return new RsaSecurityKey(parameters) { KeyId = kid };
    }
}
