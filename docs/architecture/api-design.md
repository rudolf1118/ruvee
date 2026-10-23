# API design (V1)

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed. Only the Phase 1
health endpoints exist.

This document lists endpoints and transport rules. What each flow does, and why, is specified in
the security documents linked from each section. Tables are in
[database-design.md](database-design.md).

## What is implemented

Only the health endpoints and the transport conventions below are implemented (P2-05, local
branch, remote CI not yet run). Every other endpoint in this document is **proposed** and has no
contract yet.

- **Source of truth:** the Zod schemas in [`packages/contracts`](../../packages/contracts/src).
  The OpenAPI 3.1 document [`packages/contracts/openapi.json`](../../packages/contracts/openapi.json)
  is generated from them (`pnpm --filter @ruvee/contracts openapi:write`). Tests check that the
  committed file matches the schemas, that the routes the API registers are exactly the
  documented ones, and that actual responses parse with the schemas.
- **Endpoints:** `GET /health/live` and `GET /health/ready`. Neither requires authentication;
  no authentication exists. `OPTIONS` and every other method or path return `404 not_found`.
- **Not yet implemented:** the `/api/v1` base path (no versioned endpoint exists), the 4 MiB
  limit for `POST /sync/commits` (Phase 3), the authentication levels, and the `Origin` and
  `X-Ruvee-Request` checks and cookie-plus-bearer rejection (P2-09, with sessions).

| Rule           | Implemented behavior                                                                                                                                                                                                                                                                                                                                        |
| -------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bodies         | Read only for `POST`, `PUT`, `PATCH` and `DELETE`; a body on other methods is ignored, not parsed. A body must be `application/json`, optionally with `charset=utf-8` and no other parameter, without `Content-Encoding`. Otherwise `415 unsupported_media_type`. Invalid JSON, or JSON whose top level is not an object or array, is `400 malformed_json`. |
| Size           | 64 KiB of received bytes; more is `413 payload_too_large`. Compressed bodies are refused, so the limit can't be bypassed by compression. Node's 16 KiB header limit applies to headers.                                                                                                                                                                     |
| Validation     | `ContractValidationPipe` with a contract schema. Failures are `400 invalid_request` with `details.issues`: at most 20, each with a field path and a code from a closed list. Zod messages, received values and unknown key names are never returned.                                                                                                        |
| Unknown fields | Request schemas are strict objects: an unknown field is rejected with issue code `unknown_field` at the path of the object that contains it. The field name is not echoed. Request schemas must not use records or maps, whose keys come from the request. Unknown query parameters and headers are ignored.                                                |
| Field lengths  | Every string and array in a request schema must have a maximum (a review rule; no request schema exists yet). Binary fields use `base64urlBytes`, which accepts only canonical unpadded base64url and checks the decoded length through the encoded length.                                                                                                 |
| Request ids    | `X-Request-Id` is echoed if it matches `^[A-Za-z0-9._-]{1,64}$`, and replaced by a generated UUID otherwise. It is returned in the header and in every error body.                                                                                                                                                                                          |
| Caching        | Every response, including errors, has `Cache-Control: no-store`.                                                                                                                                                                                                                                                                                            |

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
| `POST /auth/register/start`          | `none`    | `{ bootstrapToken, username, registrationRequest }` → `{ registrationResponse }`. Returns `404` after the first account exists.                                                                                                                      |
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
| `GET /recovery/material`        | `recovery` | → `{ accountId, recoveryKeyId, wrappedAkRecovery, akId, akEpoch, keysetVersion, keyset, rowVersion }`                                                                                              |
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
| `POST /pairings/{pairingId}/request`  | `session` | `{ epk, platform, mac }` (device B, which must be `pending`). `device_id_B` comes from the session. A second request gets `409`.             |
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

Every error uses one shape, refined in P2-05 from the Phase 1 filter's shape:

```json
{
  "statusCode": 400,
  "error": "invalid_request",
  "message": "The request does not match the expected format.",
  "requestId": "3f0c9a52-1d7e-4a8b-9c1e-6b2f0d4e7a11",
  "details": { "issues": [{ "path": ["label"], "code": "too_big" }] }
}
```

- `error` is the code, from a closed list. `message` is a fixed string for that code. Neither
  ever repeats request input. `statusCode` always equals the HTTP status.
- `requestId` is always present and matches `^[A-Za-z0-9._-]{1,64}$`.
- `details` appears only for codes that need it. Its fields are documented per code: today only
  `invalid_request` has it; later codes may add, for example, `currentSeq` or the conflicting
  item ids and revisions.
- Authentication failures never distinguish "unknown user" from "wrong password"
  ([authentication.md §4](../security/authentication.md#4-login)).
- Unexpected errors return `500 internal_error`. An HTTP exception whose status has no code
  (for example a framework `403`) is also reported as `500 internal_error` and logged, so every
  new status must be added to the contract list first.

Codes that are **implemented**, in `packages/contracts/src/errors.ts`:

| Status | Codes                               | Returned when                                                                   |
| ------ | ----------------------------------- | ------------------------------------------------------------------------------- |
| 400    | `invalid_request`, `malformed_json` | A schema check failed, or the request was unusable; the body is not valid JSON. |
| 404    | `not_found`                         | No route matches.                                                               |
| 413    | `payload_too_large`                 | The body exceeds 64 KiB.                                                        |
| 415    | `unsupported_media_type`            | The body is not uncompressed UTF-8 `application/json`.                          |
| 500    | `internal_error`                    | Anything unexpected.                                                            |

Codes that are **proposed** for later endpoints, and are added to the contract only with them:

| Status | Codes                                                                                                |
| ------ | ---------------------------------------------------------------------------------------------------- |
| 400    | `unsupported_format`                                                                                 |
| 401    | `unauthenticated`, `login_failed`, `recovery_failed`, `session_expired`, `device_revoked`            |
| 403    | `forbidden`, `step_up_required`, `device_not_enrolled`, `csrf_rejected`                              |
| 409    | `seq_conflict`, `revision_conflict`, `idempotency_mismatch`, `row_version_conflict`, `pairing_state` |
| 429    | `rate_limited`, with `Retry-After`                                                                   |

## Logging

Implemented in P2-05: the access log line has the request id, method, status, response time and
the **route template** (such as `/items/:itemId`), never the raw path or query string. Unknown
paths, and requests rejected before routing (body errors), are logged with the fixed route
`(unmatched)`. Health probes (`GET` and `HEAD` on the health paths) are not access-logged.
Unexpected errors are logged with their class name and stack frames only, without the message,
because messages can contain request input or connection strings. A test sends a synthetic secret
in the path, query string, `Authorization`, `Cookie`, other headers, bodies and exception
messages, and checks that no log line and no response contains it.

V1 keeps that and adds:

- The route template is the only form of path that is logged
  (`/api/v1/pairings/:pairingId/approve`), so ids never reach the logs.
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

## Changes after architecture validation

Status remains **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](../security/architecture-validation.md): `instanceId` and
`serverPublicKey` removed from `register/start` and `recovery/material`, because OPAQUE uses no
server identifier and clients no longer pin the server key (V-02, V-03). The pairing request
takes `device_id_B` from the session and accepts one request per pairing (V-09).

## Changes after P2-05 (API contracts and conventions)

Status remains **Proposed**. Changes made on 2026-10-23, from the implementation:

- New section [What is implemented](#what-is-implemented), separating the implemented health
  endpoints and conventions from the proposed endpoints.
- [Errors](#errors): the shape is the existing flat Phase 1 shape with stable codes, instead of
  the nested `{ error: { code, message, details } }` proposed in Phase 0, so there is one format.
  `malformed_json` (400) and `unsupported_media_type` (415) were added. Proposed codes are listed
  separately.
- [Logging](#logging): the route template replaced the raw path, and error messages are no longer
  logged.
- Deferred to P2-09: the `Origin` and `X-Ruvee-Request` checks and the cookie-plus-bearer
  rejection, which need sessions.
