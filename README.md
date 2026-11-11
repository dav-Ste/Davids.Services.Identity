# Davids.Services.Identity

| Pull Request CI | CodeQL SAST | Platform Architecture & Orchestration |
|---|---|---|
| [![CI — Build, Tests & Security](https://github.com/dav-Ste/Davids.Services.Identity/actions/workflows/pull-request-ci.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Services.Identity/actions/workflows/pull-request-ci.yml) | [![CodeQL — PR, Main & Weekly SAST](https://github.com/dav-Ste/Davids.Services.Identity/actions/workflows/codeql.yml/badge.svg?branch=main)](https://github.com/dav-Ste/Davids.Services.Identity/actions/workflows/codeql.yml) | [**`Davids` — Architecture & Security Diagram**](https://github.com/dav-Ste/Davids#architecture-project-relationships--security-posture) |

`Davids.Services.Identity` is the standalone `.NET 10` **Customer OpenID Connect (OIDC) Provider** microservice repository (`Davids.Services.Identity.slnx`, default local port `:5004`). Built on self-hosted `OpenIddict` (`7.7.2`), it manages **customer-only** (`role: "user"`) registration, OAuth 2.1 **Authorization Code + PKCE (`S256`)** authentication, asymmetric **RS256** JWT issuance, public JWKS discovery, single-use rotating refresh tokens with reuse detection, per-account lockout protection, customer login-audit logging, RFC 7009 token revocation (synced to SQL Server and Redis), SQL Server persistence in `identitydb`, and transactional RabbitMQ outbox integration.

Administrator accounts are never stored in `identitydb`; they live exclusively in the sibling [`Davids.Services.AdminIdentity`](https://github.com/dav-Ste/Davids.Services.AdminIdentity) OIDC authority (`adminidentitydb`).

## Projects

- `src/Davids.Services.Identity.Core`: Customer identity (`Role.User = "user"` only), login audit entities, revoked access-token tracking, and domain validation.
- `src/Davids.Services.Identity.Application`: Registration/identity commands, DTOs, and application services.
- `src/Davids.Services.Identity.Infrastructure`: SQL Server (`identitydb`) with EF Core + OpenIddict stores, 2048-bit+ RSA signing/encryption key management, public PKCE client seeder (`davids-web`), RabbitMQ transactional outbox/inbox, Vault KV-v2 loader (`secret/data/davids/identity`), and `OidcRevocationSyncHandler` (`davids:identity:revoked:<jti>`).
- `src/Davids.Services.Identity.Api`: Minimal HTTP API exposing OpenIddict protocol endpoints, `/sign-up`, `/me`, `/me/login-audits`, and `/users/{userId}` with `RS256` `CustomerBearer` validation.
- `tests/Davids.Services.Identity.Tests`: 27 unit, architecture, and SQLite-backed integration tests covering OIDC discovery/JWKS, Authorization Code + PKCE (`S256`), single-use refresh rotation/replay revocation, RFC 7009 revocation, lockout, login audits, role isolation, and Vault secret loading.

## OIDC & HTTP contract

Requests can be sent directly to the Customer Identity API (`:5004`), or through [`Davids.APIGateway`](https://github.com/dav-Ste/Davids.APIGateway) (`:17320`) by prefixing routes with `/identity`:

| Method | Path | Access | Behaviour |
|---|---|---|---|
| `GET` | `/.well-known/openid-configuration` | Anonymous | Standard OIDC discovery metadata (`S256` PKCE, `RS256` signing, endpoints) |
| `GET` | `/.well-known/jwks` | Anonymous | Public RSA JSON Web Key Set (`kty: RSA`, `use: sig`) for zero-secret resource server validation |
| `GET` / `POST` | `/connect/authorize` | Anonymous | Interactive customer sign-in for public PKCE client `davids-web` (`response_type=code`, `code_challenge_method=S256` + antiforgery `request_token`) |
| `POST` | `/connect/token` | Anonymous | Exchanges `authorization_code` + `code_verifier` or rotates single-use `refresh_token` (`60 min` access token, `14 day` rolling refresh token) |
| `GET` / `POST` | `/connect/userinfo` | `CustomerBearer` | Standard OIDC UserInfo endpoint (`sub`, `email`, `role`) |
| `POST` | `/connect/revocation` | Public client | RFC 7009 revocation; revokes refresh grants in OpenIddict and records access-token `jti` in `RevokedAccessTokens` + Redis `davids:identity:revoked:<jti>` |
| `GET` / `POST` | `/connect/logout` | Anonymous | OIDC End-Session logout endpoint |
| `POST` | `/sign-up` | Anonymous | JSON `email`, `password` (`12+` chars); creates a `user` account in `identitydb` (non-`user` roles rejected with `400`) and queues `signed_up` in the SQL outbox; returns `201` |
| `GET` | `/me` | `CustomerBearer` | Returns authenticated customer claims (`aud: davids-services`, `role == "user"`) |
| `PUT` | `/me/password` | `CustomerBearer` | Verifies `currentPassword`, rotates password hash, revokes OpenIddict tokens + caller `jti`, and appends a zero-secret `CustomerChangeAuditLogs` entry |
| `PUT` | `/me/email` | `CustomerBearer` | Verifies `currentPassword` & email uniqueness, updates login email, queues `email_changed` in SQL Outbox for `Customers`, and records `CustomerChangeAuditLogs` |
| `GET` | `/me/login-audits` | `CustomerBearer` | Returns append-only zero-secret login audit history (`CustomerLoginAuditLogs`) for the authenticated customer |
| `GET` | `/me/change-audits` | `CustomerBearer` | Returns append-only zero-secret account change history (`CustomerChangeAuditLogs`) for the authenticated customer |
| `GET` | `/users/{userId}` | Owner (`sub`) or `AdminBearer` (`admin`/`support`/`auditor`) | Returns customer account metadata and lockout state |
| `POST` | `/users/{userId}/unlock` | `AdminBearer` (`admin`/`support`) | Clears failed login counter and lockout window (routed via `/customer-accounts/users/{userId}/unlock`) |
| `PUT` | `/users/{userId}/email` | `AdminBearer` (`admin`/`support`) | Workforce-verified email recovery + `email_changed` outbox sync (routed via `/customer-accounts/users/{userId}/email`) |
| `GET` | `/change-audits` | `AdminBearer` (`admin`/`support`/`auditor`) | Workforce customer CIAM change-audit query (`?targetUserId=&limit=`) |
| `GET` | `/health`, `/alive` | Probe | Readiness and liveness endpoints wired via `Davids.ServiceDefaults` |

## Persistence and events

Customer Identity owns its dedicated SQL Server database (`identitydb`) and publishes `signed_up` and `signed_in` events to RabbitMQ (`identity` topic exchange) through its transactional outbox; [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers) consumes `identity.signed_up` to provision an `incomplete` customer profile in `customersdb`.

## Build, test & container image

Clone [`Davids.Shared`](https://github.com/dav-Ste/Davids.Shared) (`../Davids.Shared`) alongside `Davids.Services.Identity` (or pass `/p:UseSharedPackageReference=true` to consume `Davids.ServiceDefaults` as a NuGet package without cloning `Davids.Shared`):

```powershell
dotnet restore Davids.Services.Identity.slnx --locked-mode
dotnet build Davids.Services.Identity.slnx --no-restore -c Release -warnaserror
dotnet test Davids.Services.Identity.slnx --no-build --no-restore -c Release
```

Build the hardened multi-stage container image (`USER 10001:10001`, `EXPOSE 8080`) from the parent workspace directory:

```powershell
docker build -f Davids.Services.Identity/Dockerfile -t davids-identity:local ..
```

## Related repositories

- [`Davids`](https://github.com/dav-Ste/Davids) — `.NET 10` Aspire AppHost, Vault bootstrap, Kubernetes/Istio manifests, architecture diagram & lifecycle security suite
- [`Davids.Shared`](https://github.com/dav-Ste/Davids.Shared) — `Davids.ServiceDefaults` shared observability, Data Protection, and resilience defaults
- [`Davids.APIGateway`](https://github.com/dav-Ste/Davids.APIGateway) — YARP `2.3.0` edge reverse proxy & confidential Admin OIDC BFF
- [`Davids.Services.AdminIdentity`](https://github.com/dav-Ste/Davids.Services.AdminIdentity) — Administrator OpenIddict `RS256` OIDC Provider (`adminidentitydb`)
- [`Davids.Services.Customers`](https://github.com/dav-Ste/Davids.Services.Customers) — Customer profiles & order tracking API (`customersdb`)
- [`Davids.Frontend.Admin`](https://github.com/dav-Ste/Davids.Frontend.Admin) — Passwordless Workforce RBAC customer, IAM & audit web UI
- [`Davids.Frontend.Web`](https://github.com/dav-Ste/Davids.Frontend.Web) — Customer Self-Service Web Portal (`CustomerBffCookie` PKCE `S256` BFF)
