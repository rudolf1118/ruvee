# API design (V1)

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed. Only the Phase 1
health endpoints exist.

This document lists endpoints and transport rules. What each flow does, and why, is specified in
the security documents linked from each section. Tables are in
[database-design.md](database-design.md).

## Conventions

- **Base path:** `/api/v1`. Caddy serves the web app and the API from the **same origin**. The
  Phase 1 health endpoints `/health/live` and `/health/ready` stay outside the versioned path.
- **Bodies:** `application/json` only. Binary values are unpadded base64url strings. The server
  checks the **decoded** length of every binary field against the sizes in
  [database-design.md](database-design.md) before doing anything else.
- **Request size:** 64 KiB by default. `POST /sync/commits` allows 4 MiB, which covers 2 MiB of
  decoded records plus encoding. Larger uploads, such as imports, re-seeding and rotation, are
  split across requests.
- **Secrets** travel only in request bodies, the session cookie, or the `Authorization` header.
  They never appear in a URL or query string ([INV-12](../security/security-invariants.md)).
- **Validation:** every request body is checked with a Zod schema that rejects unknown fields.
  Every field is either an opaque byte string (envelope, record, OPAQUE message, MAC, hash) or
  documented metadata ([INV-01](../security/security-invariants.md)).
- **Clocks:** the server sets every timestamp. Client clock values appear only inside
  ciphertext.

### Authentication levels

| Level      | Requirement                                                                                                                                                                        |
| ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `none`     | Unauthenticated, rate-limited.                                                                                                                                                     |
| `session`  | A valid session of kind `cookie` or `token`, on a device that is `pending` or `active`.                                                                                            |
| `active`   | `session`, and the device is `active`.                                                                                                                                             |
| `step-up`  | `active`, and `auth_at` is within the last 5 minutes ([INV-14](../security/security-invariants.md)).                                                                               |
| `recovery` | A session of kind `recovery` ([account-recovery.md §3](../security/account-recovery.md#3-recovery-with-the-recovery-key)). It is accepted **only** on the `/recovery/*` endpoints. |

The web app uses the `__Host-ruvee_session` cookie. The extension and mobile apps send
`Authorization: Bearer <access token>`. A request carrying both is rejected. State-changing
requests from cookie clients need the `Origin` and `X-Ruvee-Request: 1` checks
([authentication.md §6](../security/authentication.md#6-csrf)).

## Authentication

Specified in [authentication.md](../security/authentication.md). Phase 2.

| Method and path                      | Level     | Body to the server, and response                                                                                                                                                                                                                     |
| ------------------------------------ | --------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /auth/register/start`          | `none`    | `{ bootstrapToken, username, registrationRequest }` → `{ registrationResponse, instanceId, serverPublicKey }`. Returns `404` after the first account exists.                                                                                         |
| `POST /auth/register/finish`         | `none`    | `{ bootstrapToken, username, registrationRecord, accountId, device: { id, platform, label }, keys: { kdfProfile, saltPw, akId, akEpoch, wrappedAkPassword, recoveryKeyId, wrappedAkRecovery, recoveryVerifier, keysetVersion, keyset } }` → session. |
| `POST /auth/login/start`             | `none`    | `{ username, startLoginRequest, deviceId?, platform }` → `{ loginId, loginResponse }`                                                                                                                                                                |
| `POST /auth/login/finish`            | `none`    | `{ loginId, finishLoginRequest }` → session, plus `{ accountId, device: { id, status } }`                                                                                                                                                            |
| `POST /auth/reauth/start`, `/finish` | `active`  | Same messages as login. Updates `auth_at` on the current session.                                                                                                                                                                                    |
| `POST /auth/refresh`                 | `none`    | `{ refreshToken }` → `{ accessToken, refreshToken, accessExpiresAt }`. Token clients only. Reuse of a rotated token revokes the session.                                                                                                             |
| `POST /auth/logout`                  | `session` | Revokes the current session.                                                                                                                                                                                                                         |

The "session" result is a `Set-Cookie` header for a web request. For a token client it is
`{ accessToken, refreshToken, accessExpiresAt }`. `platform` decides which one is used.

## Account

| Method and path                 | Level     | Body to the server, and response                                                                                                                                                           | Phase |
| ------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----- |
| `GET /account`                  | `session` | → `{ accountId, username, createdAt, passwordChangedAt }`                                                                                                                                  | 2     |
| `GET /account/keys`             | `active`  | → `{ kdfProfile, saltPw, akId, akEpoch, wrappedAkPassword, keysetVersion, keyset, rowVersion }`. The recovery wrap is not returned here.                                                   | 2     |
| `POST /account/password/start`  | `step-up` | `{ registrationRequest }` → `{ registrationResponse }`                                                                                                                                     | 2     |
| `POST /account/password/finish` | `step-up` | `{ registrationRecord, kdfProfile, saltPw, wrappedAkPassword, expectedRowVersion }`. Revokes all other sessions ([authentication.md §9](../security/authentication.md#9-password-change)). | 2     |
| `PUT /account/recovery`         | `step-up` | `{ recoveryKeyId, wrappedAkRecovery, recoveryVerifier, expectedRowVersion }` ([account-recovery.md §5](../security/account-recovery.md#5-recovery-key-rotation))                           | 2     |
| `GET /account/events?cursor=`   | `active`  | → security events, newest first, 50 per page.                                                                                                                                              | 2     |
| `POST /account/vault-reset`     | `step-up` | `{ confirmUsername, newKeys: { … as at registration … } }` ([account-recovery.md §6.1](../security/account-recovery.md#61-vault-reset-by-the-user))                                        | 3     |

A stale `expectedRowVersion` returns `409 row_version_conflict`, and the client refetches.

## Recovery

Specified in [account-recovery.md §3](../security/account-recovery.md#3-recovery-with-the-recovery-key). Phase 2.

| Method and path                 | Level      | Body to the server, and response                                                                                                                                                                   |
| ------------------------------- | ---------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `POST /recovery/start`          | `none`     | `{ username, recoveryAuthKey, device: { id, platform } }` → recovery session (15 minutes). Every failure returns the same `401 recovery_failed`.                                                   |
| `GET /recovery/material`        | `recovery` | → `{ accountId, recoveryKeyId, wrappedAkRecovery, akId, akEpoch, keysetVersion, keyset, rowVersion, serverPublicKey, instanceId }`                                                                 |
| `POST /recovery/password/start` | `recovery` | `{ registrationRequest }` → `{ registrationResponse }`                                                                                                                                             |
| `POST /recovery/complete`       | `recovery` | `{ registrationRecord, kdfProfile, saltPw, wrappedAkPassword, recoveryKeyId, wrappedAkRecovery, recoveryVerifier, label, expectedRowVersion }` → a normal session. All other sessions are revoked. |

## Devices and pairing

Specified in [device-enrollment.md](../security/device-enrollment.md). Phase 2.

| Method and path                       | Level     | Body to the server, and response                                                                                                             |
| ------------------------------------- | --------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| `GET /devices`                        | `active`  | → every device: `{ id, platform, status, enrolledVia, label, createdAt, enrolledAt, lastSeenAt, revokedAt }`. The label is an envelope.      |
| `GET /devices/current`                | `session` | → the calling device. Pending devices use this to wait for approval.                                                                         |
| `PATCH /devices/{deviceId}`           | `active`  | `{ label }`                                                                                                                                  |
| `POST /devices/{deviceId}/revoke`     | `step-up` | `{ reason: "retired" \| "lost" }`. The caller can't revoke itself; it logs out instead.                                                      |
| `GET /sessions`                       | `active`  | → sessions with device id, kind, created, last used, and expiry times                                                                        |
| `DELETE /sessions/{sessionId}`        | `active`  | Revokes that session.                                                                                                                        |
| `POST /pairings`                      | `active`  | `{ pairingId }` (device A)                                                                                                                   |
| `GET /pairings/{pairingId}`           | `session` | → state, and for the role of the caller: A gets `{ requesterDeviceId, platform, epk, mac }`, and B gets `{ ciphertext, mac }` after approval |
| `POST /pairings/{pairingId}/request`  | `session` | `{ epk, platform, mac }` (device B, which must be `pending`)                                                                                 |
| `POST /pairings/{pairingId}/approve`  | `active`  | `{ ciphertext, mac, label }` (device A)                                                                                                      |
| `POST /pairings/{pairingId}/complete` | `active`  | Device B, now active. Deletes the pairing.                                                                                                   |
| `DELETE /pairings/{pairingId}`        | `session` | Either device cancels.                                                                                                                       |

`pairingId` is in the path, so it appears in routing. It is not a secret, because knowing it
without `S` allows nothing, but it is logged only as the route template (see [Logging](#logging)).

## Sync

Specified in [sync-protocol.md](sync-protocol.md). Phases 3 and 4. Every endpoint requires `active`.

| Method and path                   | Body to the server, and response                                                                                                                                                                         | Phase |
| --------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----- |
| `POST /vaults`                    | `{ vaultId, vkId }` → creates the empty vault with `seq = 0`. The first commit is the genesis manifest.                                                                                                  | 3     |
| `GET /sync/changes?since=&limit=` | → `{ currentSeq, items: [{ itemId, revision, updatedSeq, record \| null }], manifests: [{ seq, manifest }], nextCursor? }`. `limit` is at most 500.                                                      | 3     |
| `POST /sync/commits`              | `{ vaultId, commitId, baseSeq, mutations: [{ itemId, baseRevision, newRevision, record \| null }], manifest }` → `{ seq }`, or `409` with `seq_conflict`, `revision_conflict` or `idempotency_mismatch`. | 3     |
| `GET /sync/events`                | Server-Sent Events: `vault-changed` with `{ seq }` only.                                                                                                                                                 | 4     |
| `POST /sync/reseed`               | Phase 4 design ([sync-protocol.md §11](sync-protocol.md#server-restored-from-an-older-backup)).                                                                                                          | 4     |

## Administration

There is no HTTP administration API. These commands run on the server host through the API
container ([authentication.md §3](../security/authentication.md#3-account-bootstrap),
[account-recovery.md §6.2](../security/account-recovery.md#62-operator-reset)):

- `ruvee-admin bootstrap-token`
- `ruvee-admin delete-account --username <name>`

## Errors

Every error uses one shape:

```json
{
  "error": {
    "code": "revision_conflict",
    "message": "The item changed on the server.",
    "details": {}
  }
}
```

- `code` comes from a closed list. `message` is a fixed string for that code. Neither ever
  repeats request input.
- `details` appears only for codes that need it. Its fields are documented per code, for
  example `currentSeq` or the conflicting item ids and revisions.
- Authentication failures never distinguish "unknown user" from "wrong password"
  ([authentication.md §4](../security/authentication.md#4-login)).
- Unexpected errors return `500 internal_error` with the request id only. The existing Phase 1
  exception filter already does this.

| Status | Codes                                                                                                |
| ------ | ---------------------------------------------------------------------------------------------------- |
| 400    | `invalid_request`, `unsupported_format`                                                              |
| 401    | `unauthenticated`, `login_failed`, `recovery_failed`, `session_expired`, `device_revoked`            |
| 403    | `forbidden`, `step_up_required`, `device_not_enrolled`, `csrf_rejected`                              |
| 404    | `not_found`                                                                                          |
| 409    | `seq_conflict`, `revision_conflict`, `idempotency_mismatch`, `row_version_conflict`, `pairing_state` |
| 413    | `payload_too_large`                                                                                  |
| 429    | `rate_limited`, with `Retry-After`                                                                   |

## Logging

Phase 1 already logs only method, path without the query string, request id and status. V1
keeps that and adds:

- The **route template** (`/api/v1/pairings/:pairingId/approve`) replaces the raw path, so ids
  never reach the logs.
- Account id and device id may be logged, because they are server-visible metadata.
- Bodies, headers, cookies, tokens, OPAQUE messages, envelopes and usernames are never logged.
  A failed login is recorded as a security event, not in the application log.
- Logs go to stdout only. Retention is the operator's choice, and 14 days is recommended. Caddy
  access logs follow the same rules: no query strings and no `Authorization` or `Cookie` headers.
- There is no third-party telemetry or error reporting.

## Web app security headers

The web app is served by Next.js behind Caddy. These headers apply to every HTML response. They
reduce the likelihood of XSS (T-18, T-19), but they **do not** protect against a malicious server
([threat-model.md §6](../security/threat-model.md#6-the-web-client-delivery-problem)).

| Header                         | Value                                                                                                                                                                                                                                                                                                                                            |
| ------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `Content-Security-Policy`      | `default-src 'none'; script-src 'self' 'wasm-unsafe-eval' <nonce or hashes>; style-src 'self'; img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; require-trusted-types-for 'script'; trusted-types ruvee` |
| `Strict-Transport-Security`    | `max-age=31536000; includeSubDomains` in public mode                                                                                                                                                                                                                                                                                             |
| `X-Content-Type-Options`       | `nosniff`                                                                                                                                                                                                                                                                                                                                        |
| `Referrer-Policy`              | `no-referrer`                                                                                                                                                                                                                                                                                                                                    |
| `Permissions-Policy`           | `camera=(self)` for scanning pairing QR codes, and every other feature disabled                                                                                                                                                                                                                                                                  |
| `Cross-Origin-Opener-Policy`   | `same-origin`                                                                                                                                                                                                                                                                                                                                    |
| `Cross-Origin-Resource-Policy` | `same-origin`                                                                                                                                                                                                                                                                                                                                    |

`'wasm-unsafe-eval'` is required to instantiate libsodium.js and `@serenity-kit/opaque`. It
allows WebAssembly compilation, not JavaScript `eval`.

Next.js App Router emits inline scripts. Two ways to allow them without `'unsafe-inline'`:

- per-request nonces, which force dynamic rendering of every page
- a static export, where build-time hashes can be listed

The choice is [D-16](open-decisions.md). Phase 2 must also verify that Tailwind and Next.js work
with `style-src 'self'`. If inline styles are unavoidable, that is recorded as a deviation and
not quietly allowed.

Further rules:

- No third-party scripts, fonts or images.
- Item content is never rendered as HTML.
- The vault UI is client-rendered and receives no vault data from server rendering.

### Cache control

Every `/api/v1` response, and every HTML page of the vault UI, sends `Cache-Control: no-store`.
Static assets with content hashes in their names may be cached as `immutable`. The web app has
no service worker in V1, so no API response can end up in a service-worker cache
([sync-protocol.md §12](sync-protocol.md#12-local-storage)).
