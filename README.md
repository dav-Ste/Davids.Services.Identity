# Davids.Services.Identity

`Davids.Services.Identity` is the standalone .NET 10 **Customer OpenID Connect (OIDC) Provider** microservice repository (`Davids.Services.Identity.slnx`). Built on self-hosted `OpenIddict` (`7.7.2`), it manages **customer-only** (`role: "user"`) registration, OAuth 2.1 **Authorization Code + PKCE (`S256`)** authentication, asymmetric **RS256** JWT issuance, public JWKS discovery, single-use rotating refresh tokens with reuse detection, RFC 7009 token revocation (synced to SQL Server and Redis), SQL Server persistence in `identitydb`, and transactional RabbitMQ outbox integration.

Administrator accounts are never stored in `identitydb`; they live exclusively in the sibling `Davids.Services.AdminIdentity` OIDC authority (`adminidentitydb`).

## Projects

- `src/Davids.Services.Identity.Core`: customer identity (`Role.User = "user"` only), revoked access-token tracking, and domain validation.
- `src/Davids.Services.Identity.Application`: registration/identity commands, DTOs, and application services.
- `src/Davids.Services.Identity.Infrastructure`: SQL Server (`identitydb`) with EF Core + OpenIddict stores, 2048-bit+ RSA signing/encryption key management, public PKCE client seeder (`davids-web`), RabbitMQ transactional outbox/inbox, Vault KV-v2 loader (`secret/data/davids/identity`), and `OidcRevocationSyncHandler` (`davids:identity:revoked:<jti>`).
- `src/Davids.Services.Identity.Api`: minimal HTTP API exposing OpenIddict protocol endpoints, `/sign-up`, `/me`, and `/users/{userId}` with RS256 `CustomerBearer` validation.
- `tests/Davids.Services.Identity.Tests`: SQLite-backed OIDC discovery/JWKS, Authorization Code + PKCE (`S256`), single-use refresh rotation/replay revocation, RFC 7009 revocation, role-isolation, and Vault tests.

## Build & Test

Clone the sibling `Davids.Shared` repository (`../Davids.Shared`) alongside `Davids.Services.Identity` (the `Davids` Aspire infrastructure repository is not required for standalone builds/tests):

```powershell
dotnet restore Davids.Services.Identity.slnx --locked-mode
dotnet build Davids.Services.Identity.slnx --no-restore -c Release
dotnet test Davids.Services.Identity.slnx --no-build --no-restore -c Release
```

## OIDC & HTTP Contract

Requests can be sent directly to the Customer Identity API, or through the YARP API Gateway by prefixing routes with `/identity`:

| Method | Path | Behaviour |
|---|---|---|
| GET | `/.well-known/openid-configuration` | Standard OIDC discovery metadata (`S256` PKCE, `RS256` signing, endpoints) |
| GET | `/.well-known/jwks` | Public RSA JSON Web Key Set (`kty: RSA`, `use: sig`) for zero-secret resource server validation |
| GET / POST | `/connect/authorize` | Interactive customer sign-in for public PKCE client `davids-web` (`response_type=code`, `code_challenge_method=S256` required) |
| POST | `/connect/token` | Exchanges `authorization_code` + `code_verifier` or rotates single-use `refresh_token` (`60 min` access token, `14 day` rolling refresh token) |
| GET / POST | `/connect/userinfo` | Standard OIDC UserInfo endpoint (`sub`, `email`, `role`) |
| POST | `/connect/revocation` | RFC 7009 revocation; revokes refresh grants in OpenIddict and records access-token `jti` in `RevokedAccessTokens` + Redis `davids:identity:revoked:<jti>` |
| GET / POST | `/connect/logout` | OIDC End-Session logout endpoint |
| POST | `/sign-up` | JSON `email`, `password` (12+ chars); creates a `user` account in `identitydb` (non-`user` roles rejected with `400`) and queues `signed_up` in the SQL outbox; returns `201` |
| GET | `/me` | Valid RS256 `CustomerBearer` token (`aud: davids-services`, `role == "user"`) required |
| GET | `/users/{userId}` | Matching customer `sub` GUID only |

## Persistence and events

Customer Identity owns its dedicated SQL Server database (`identitydb`) and publishes `signed_up` and `signed_in` events to RabbitMQ (`identity` topic exchange) through its transactional outbox; `Davids.Services.Customers` consumes `identity.signed_up` to provision an `incomplete` customer profile in `customersdb`.
