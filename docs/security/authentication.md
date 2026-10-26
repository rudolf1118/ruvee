# Authentication and sessions

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed, not implemented.

This document covers how a client proves to the server who the user is, and how sessions work.
It does **not** cover unlocking the vault, which needs keys the server never has
([cryptographic-design.md](cryptographic-design.md)). A valid session never grants decryption
([INV-06](security-invariants.md)).

Endpoints are listed in [api-design.md](../architecture/api-design.md). Tables are in
[database-design.md](../architecture/database-design.md).

## Recommendation

Use **OPAQUE (RFC 9807)** through **`@serenity-kit/opaque`** on the server (Node) and on the web
and extension clients. Its default configuration (ristretto255 with SHA-512; the published 1.1.0
build compiles `opaque-ke` 4.0.1) is used with the "memory-constrained" Argon2id key-stretching
preset. This is recorded in [ADR-0004](../adr/0004-opaque-authentication.md). The configuration
was exercised in the [architecture validation spike](architecture-validation.md#6-library-validation).

Mobile has no usable binding today, which blocks Phase 6 authentication but not Phases 2–5
(section 2.3).

## 1. Why OPAQUE

- The password never leaves the client in any form the server can use to log in elsewhere or
  check guesses cheaply. A TLS-terminating proxy or a request log can't capture a
  password-equivalent.
- Offline guessing against the OPAQUE record needs the OPAQUE server setup (its OPRF seed) as
  well as the record (RFC 9807 §10.11). Ruvee keeps the setup outside the database
  ([server secrets](#server-secrets)). A database copy **alone** therefore allows no guessing
  against the record. A copy that also contains the setup file (a host snapshot, a whole-disk or
  volume backup) does, and that guessing does not involve `SK` or the vault wrap. The precise
  claim, including the condition on `SK`, is in
  [architecture-validation.md §3.4](architecture-validation.md#34-the-narrowed-claim).
- Unknown usernames get simulated responses that look the same as real ones (RFC 9807 §10.9).

What it does **not** give: a malicious server that serves the web app can capture the password
from the page anyway ([threat model §6](threat-model.md#6-the-web-client-delivery-problem)).
OPAQUE protects the password from the server **process and its data**, not from modified client
code.

## 2. Implementation evaluation

Evidence is in [research-sources.md](research-sources.md).

### 2.1 Candidates

| Implementation                                   | Version and maintenance                                        | Protocol version                                            | Platforms                | Audit                                                                                         | Verdict                                                                               |
| ------------------------------------------------ | -------------------------------------------------------------- | ----------------------------------------------------------- | ------------------------ | --------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `@serenity-kit/opaque`                           | 1.1.0 (2026-02-01); repository active (2026-08)                | `opaque-ke` 4.0.1 compiled into the WASM; based on RFC 9807 | Browser, Node (WASM)     | 7ASecurity, Oct–Nov 2023 (earlier version); `opaque-ke` audited by NCC Group in 2021 (v0.5.0) | **Use for server, web and extension.** Audits predate this version.                   |
| `react-native-opaque`                            | 0.3.1 (2023-10-03); last push 2024-10                          | `opaque-ke` 3.0.0-pre.4 (pre-RFC draft)                     | iOS, Android             | Included in the 2023 7ASecurity scope                                                         | **Not usable.** Stale, and expected to be incompatible with 1.x registration records. |
| `@serenity-kit/opaque` on Hermes WASM            | Hermes V1 WebAssembly arrived with React Native 0.84 (2026-02) | Same as web                                                 | iOS, Android, unverified | n/a                                                                                           | **Unverified.** Candidate for the Phase 6 spike.                                      |
| `opaque-ke` via a native binding (UniFFI or JSI) | Would be Ruvee-maintained                                      | Same crate as web, so wire-compatible                       | iOS, Android             | Inherits `opaque-ke`'s; the binding itself would be unaudited                                 | **Candidate for the Phase 6 spike.**                                                  |

### 2.2 Configuration

| Parameter                | Value                                                                                                                                                                                                                                                                                                                                                                            |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Cipher suite             | `@serenity-kit/opaque` default: ristretto255 OPRF and group, SHA-512, Triple-DH. Not the P-256 package.                                                                                                                                                                                                                                                                          |
| Key stretching           | `"memory-constrained"` (also the library default): Argon2id v1.3, m = 2¹⁶ KiB (64 MiB), t = 3, p = 4, salt of 16 zero bytes. The OPRF key acts as the secret salt (RFC 9807 §10.11). Fixed in code on every client; the server cannot choose it. Registration and login must use exactly the same preset: a mismatch fails login (spike OP-02). Mobile must use the same preset. |
| Client identifier        | Normalized username (Unicode NFC, then lowercase). Also used as the credential identifier (`userIdentifier`) on the server.                                                                                                                                                                                                                                                      |
| Server identifier        | **Not set.** RFC 9807 §10.3 then uses the server public key, which the envelope already authenticates. A new device needs nothing from the server before logging in.                                                                                                                                                                                                             |
| AKE context              | Not settable in `@serenity-kit/opaque` 1.1.0 (it is always empty). Acceptable because the server key pair is used for nothing else.                                                                                                                                                                                                                                              |
| Password input           | The validated, normalized string from [cryptographic-design.md §3.1](cryptographic-design.md#31-password-normalization). It must be a well-formed string, because the library maps lone surrogates to U+FFFD (spike OP-08).                                                                                                                                                      |
| `export_key`             | **Not used** ([INV-11](security-invariants.md)).                                                                                                                                                                                                                                                                                                                                 |
| Server static public key | **Not pinned.** It is part of the cleartext credentials that the envelope MAC covers (RFC 9807 §4). A different server setup makes the client's `finishLogin` fail (spike OP-05).                                                                                                                                                                                                |

The OPAQUE stretch (64 MiB, p=4) and the vault stretch (64 MiB, p=1, different salt) are
independent derivations of the same password. Logging in on a new session costs both. Unlocking
on an enrolled device costs only the vault one. An attacker who has the database **and** the
OPAQUE server setup can test guesses against the OPAQUE record at about one Argon2id (64 MiB,
t = 3) per guess, **without `SK`**. A cracked password gives account access, and the password
itself, which matters if it is reused, but still not decryption, which also needs `SK`
([threat model T-03](threat-model.md#5-threats-and-outcomes)).

No published test vectors cover this KSF configuration: the upstream RFC 9807 vectors use the
identity KSF. The regression fixtures in [Interoperability tests](#interoperability-tests) are
therefore the only check that stored accounts keep working across upgrades.

### 2.3 Mobile blocker and alternatives

The wire protocol and parameters are fixed now, so web-created accounts will work with any
correct binding of `opaque-ke` 4.x. Phase 6 must start with a spike that picks one of:

1. Hermes WebAssembly running the same `@serenity-kit/opaque` package. This is the lowest
   divergence, but compatibility is unverified.
2. A Ruvee-maintained native binding of `opaque-ke` 4.x (UniFFI or JSI Turbo Module). It is
   reliable but adds a Rust toolchain and an unaudited binding to maintain.
3. Updating `react-native-opaque` upstream to `opaque-ke` 4.x and depending on it.

Acceptance for any option: a registration made on web logs in from the mobile binding, and the
reverse, using recorded fixtures ([interoperability tests](#interoperability-tests)).

**If no option works, mobile is blocked.** The fallback below is documented for completeness. It
is **not** recommended and must not be used without an explicit owner decision:

> _Fallback: client-hashed password._ The client derives `auth_key = Argon2id(P, salt_auth)` and
> sends it over TLS; the server stores `Argon2id(auth_key, server_salt)` plus an HMAC pepper kept
> outside the database. Its tradeoffs:
>
> - The server and any TLS-terminating component see `auth_key` at every login. That is enough to
>   log in and to run offline guessing against `P`.
> - It has no enumeration resistance by construction.
> - Vault confidentiality is unchanged, because decryption still needs `SK`.
> - UX is the same as OPAQUE.

## 3. Account bootstrap

V1 has one account per server.

1. When the server starts with no account, registration is closed.
2. The operator runs the API's admin command on the server host:
   `ruvee-admin bootstrap-token`. It prints a 256-bit random token **to the operator's terminal
   only**, never to the server log, and stores `SHA-256(token)` with a 60-minute expiry.
3. The web setup screen asks for the token, username, master password and confirmation.
4. `POST /api/v1/auth/register/start` checks the token, then runs OPAQUE registration step 1.
5. The client generates all keys and the Recovery Kit
   ([cryptographic-design.md](cryptographic-design.md),
   [account-recovery.md](account-recovery.md#2-creating-the-recovery-kit)). The user must confirm
   the Recovery Key before continuing.
6. `POST /api/v1/auth/register/finish` stores, in one transaction, the OPAQUE record, account key
   material, the recovery verifier, the first device and the first session, and marks the token
   used. From then on, registration endpoints return `404`.

Tokens are single-use, expire, are compared in constant time, and are rate-limited
([INV-20](security-invariants.md)).

## 4. Login

1. The client calls `POST /api/v1/auth/login/start` with `{ username, startLoginRequest, deviceId?, platform }`.
   `deviceId` is present for an enrolled device. `platform` decides between a cookie session and
   tokens, and is recorded for a new pending device.
2. The server checks throttling (section 7). It loads the registration record, or uses `null` for
   an unknown username, so that `@serenity-kit/opaque` produces a simulated response.
   **Phase 2 must test** that unknown and known usernames are indistinguishable in response shape,
   size and timing within a tolerance. The server stores the server login state under a random
   `loginId` for 60 seconds, bound to the username, `deviceId` and `platform`, and returns
   `{ loginId, loginResponse }`.
3. The client runs `finishLogin`. If it returns nothing (a wrong password, a substituted server
   or a tampered response all look the same), the client reports a generic failure locally.
   It calls `POST /api/v1/auth/login/finish` with `{ loginId, finishLoginRequest }`.
4. The server **consumes** the login state: it deletes and returns it in one atomic operation,
   so a `loginId` can be used at most once ([INV-23](security-invariants.md)). The library itself
   accepts a replayed state and finalization (spike OP-07), so this check must be Ruvee's. It
   then runs `finishLogin`. On success it creates a session bound to the device (section 5). If
   the device is unknown, it creates a `pending` device record that can do nothing except
   enrollment. On failure it records the failure for throttling and returns a generic `401`.

The same single-use rule applies to `reauth`.

Error responses never distinguish "unknown user" from "wrong password", and contain no OPAQUE
internals ([api-design.md](../architecture/api-design.md#errors)).

## 5. Sessions

| Client                       | Credential                                                                                                 | Stored on client                                                                                                                             | Lifetime (proposed; see [D-08](../architecture/open-decisions.md)) |
| ---------------------------- | ---------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| Web app (same origin as API) | Session cookie `__Host-ruvee_session`: `HttpOnly; Secure; SameSite=Strict; Path=/`. No `Domain` attribute. | Browser cookie jar; never readable by script                                                                                                 | 12 h idle (sliding), 14 days absolute                              |
| Browser extension, mobile    | Access token (bearer, 10 minutes) and refresh token (rotating)                                             | Extension: `chrome.storage.session` for the access token and extension-origin IndexedDB for the refresh token. Mobile: Keychain or Keystore. | Refresh: 30 days idle, 90 days absolute                            |

Rules:

- Tokens are 32 random bytes, base64url encoded. The server stores only `SHA-256(token)`
  ([INV-13](security-invariants.md)).
- **Refresh rotation:** every refresh returns a new refresh token and invalidates the old one.
  If an already-rotated refresh token is presented again, the whole token family is revoked and a
  security event is recorded.
- **Device binding:** every session row references one device. Revoking a device revokes all of
  its sessions.
- **Revocation:** the user can end any session from device management, and logout revokes the
  current one. Revocation takes effect on the next request; there are no stateless tokens to wait
  out, except the 10-minute access token, which is itself checked against the session row.
- **Step-up:** the endpoints listed in [INV-14](security-invariants.md) require
  `session.auth_at` within the last 5 minutes. To refresh it, the client runs OPAQUE again through
  `POST /api/v1/auth/reauth/start` and `/finish`. Recovery sessions (see
  [account-recovery.md](account-recovery.md)) are a separate, narrower session kind.
- **Expiry and the vault:** when a session expires or is revoked, the client **locks** the vault
  ([INV-15](security-invariants.md)). The encrypted local cache stays on the device.

## 6. CSRF

The web session is a cookie, so state-changing requests are protected three ways:

1. `SameSite=Strict` on the session cookie.
2. The server rejects any non-`GET` request whose `Origin` header is missing or not exactly the
   configured public origin.
3. State-changing endpoints accept only `Content-Type: application/json` and require the header
   `X-Ruvee-Request: 1`. Cross-site forms can send neither without a CORS preflight, and CORS is
   not opened to other origins.

Bearer-token clients (extension and mobile) don't use cookies, so CSRF does not apply. The API
rejects requests that carry both a cookie and a bearer token.

**As built (2026-10-25):** the extension's unauthenticated calls (`login/*`, `refresh`) carry no
cookie and no token, so they still go through the CSRF check. They pass it only from an origin
listed in `EXTENSION_ORIGINS`, with `X-Ruvee-Request: 1`, and only without a cookie; the
extension fetches with `credentials: 'omit'`, so a cookie on such a request means it came from
somewhere else. A cookie request must always come from `PUBLIC_ORIGIN`.

## 7. Rate limiting and brute-force protection

There is no Redis. V1 runs a single API instance; counters are kept in PostgreSQL for anything
that must survive a restart, and in memory for general request rates.

| Target                           | Limit (proposed)                                                                                 | Storage    |
| -------------------------------- | ------------------------------------------------------------------------------------------------ | ---------- |
| Login failures per username      | After 5 failures, exponential delay starting at 30 s and capped at 15 minutes. Reset on success. | PostgreSQL |
| Login attempts per client IP     | 20 per minute                                                                                    | Memory     |
| Recovery starts per username     | 5 per hour                                                                                       | PostgreSQL |
| Bootstrap token attempts         | 10 per hour in total                                                                             | PostgreSQL |
| Pairings per account             | At most 3 open and 10 created per hour; exactly one request per pairing                          | PostgreSQL |
| All other authenticated requests | 300 per minute per session                                                                       | Memory     |

- Throttling delays; it never permanently locks the account. Permanent lockout would let an
  attacker deny the user service.
- Throttled responses use `429` with `Retry-After`, and look the same for known and unknown
  usernames.
- Every failure is recorded as a security event with no secret material.
- Client IP comes from Caddy's verified `X-Forwarded-For` only when the request arrives from the
  configured proxy address.
- As built (2026-10-26, review R3, R16, R17): every password check (login, step-up, reopening)
  and every recovery and bootstrap attempt is reserved in one atomic statement before it runs, so
  parallel requests share the bound; the per-session limit is enforced in memory for every
  authenticated request; per-address limits key IPv6 clients by their /64; the API warns once if
  a request carries `X-Forwarded-For` while `TRUSTED_PROXY_ADDRESS` is unset, and at start in
  production when it is unset. Wrong reopening codes have their own per-address limit (R11).

## 8. What a stolen session can and cannot do

A stolen session cookie or refresh token (attacker A4 in the threat model) **can** do the
following. A copied browser profile of a locked device may contain such a credential, so device
theft can include this attacker ([T-22](threat-model.md#5-threats-and-outcomes)).

- download every encrypted item record, manifest, the encrypted keyset, the password wrap of
  `AK`, KDF salt and profile, and device metadata. The recovery wrap is returned only to a
  recovery session.
- see the metadata in [threat-model.md §4](threat-model.md#4-what-the-server-can-see)
- submit sync commits. The server cannot validate their content, so it could upload garbage or
  tombstones; clients detect it ([INV-07](security-invariants.md)), but server-side data can be
  damaged
- open a pairing request, which is useless without the pairing secret
- keep the session alive until it expires or is revoked

It **cannot**:

- decrypt anything: every wrap needs `SK` with the password, or `RK`
- create a commit that clients accept, because a valid manifest needs `K_manifest`
- complete device enrollment, which needs the pairing secret shown on an unlocked device
- change the password, rotate the Recovery Key, revoke devices, rotate keys, reset the vault or
  export, all of which need step-up (OPAQUE with the password)
- extend the session past its absolute lifetime

The damage it can do (deleting server-side data) is limited by local copies, backups and
detection. The user should revoke the session; revocation is immediate.

## 9. Password change

A password change needs an unlocked device and step-up.

1. The client derives new key material and re-wraps `AK`
   ([cryptographic-design.md §6.1](cryptographic-design.md#61-password-change-and-kdf-upgrade-re-wrap-only)).
2. It runs OPAQUE registration for the new password: `POST /api/v1/account/password/start`, then
   `/finish`, with the new registration record, new `salt_pw`, profile, new `AK_WRAP_PASSWORD`
   and the expected `account_keys.row_version`.
3. The server replaces the OPAQUE record and the password wrap in one transaction, revokes every
   other session, and records a security event. The current session continues.
4. Other enrolled devices:
   - **Online:** their session is revoked, so the user logs in with the new password. The device
     then unwraps the new server wrap with `SK` and the new password, and replaces its local wrap.
   - **Offline:** they still unlock their local copy with the **old** password until they
     reconnect. This is inherent to offline unlock and is shown in the UI.

What a password change does not undo is described in
[cryptographic-design.md §6.4](cryptographic-design.md#64-what-changing-a-password-does-not-do).

## Server secrets

| Secret               | Where                                                                                                                                                                                                                                                                                                                                                                      | If lost                                                                                                                                           | If stolen                                                                                                                                                |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------- |
| OPAQUE server setup  | A file mounted into the API container (Docker secret), read at startup. Not in PostgreSQL, not in database backups, not in `.env.example` or the repository ([INV-21](security-invariants.md)). Backed up separately and offline by the operator. A host snapshot or whole-disk backup normally **does** contain it; such a copy must be protected like the server itself. | Every login fails. The user regains access through the Recovery Key flow, which re-registers OPAQUE ([account-recovery.md](account-recovery.md)). | Together with the database, allows offline password guessing without `SK`, and impersonating the server to clients (RFC 9807 §10.12; threat model T-03). |
| Database credentials | Environment, validated at startup (Phase 1 `DATABASE_URL`)                                                                                                                                                                                                                                                                                                                 | Service outage                                                                                                                                    | Database access, which is attacker A2                                                                                                                    |

## Interoperability tests

- RFC 9807 Appendix C vectors are exercised by `opaque-ke` upstream, with the identity KSF only.
  `@serenity-kit/opaque` does not accept injected randomness, so Ruvee cannot run them through
  the wrapper. Ruvee does not reimplement OPAQUE.
- Ruvee tests: registration and login round trips between the web client and the Node server;
  a wrong password fails; an unknown username returns an indistinguishable response; a
  substituted server setup fails at the client; a replayed `loginId` is refused; malformed
  messages return the generic error.
- **Regression fixtures:** a registration record and a server setup created with the pinned
  version are committed as **test-only** fixtures. Every dependency upgrade must still log in
  with them. A failure means stored accounts would break.
- **Phase 6:** the chosen mobile binding must log in against the same fixtures, and a record
  registered on mobile must log in from web.

## Changes after architecture validation

Status remains **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](architecture-validation.md):

- §1: the database-theft claim is narrowed to a database copy without the OPAQUE setup, and
  guessing with the setup is stated to be independent of `SK` (V-01).
- §2.2: the server identifier is removed (V-02). Server public-key pinning is removed, because
  the envelope already authenticates the key (V-03). The KSF facts are recorded: zero salt, AKE
  context not settable, exact preset match required, no published vectors for it (V-14). The
  password must be a well-formed string (V-05).
- §2.1: `opaque-ke` 4.0.1 is the version compiled into the published 1.1.0 build (V-13).
- §4: the login state is consumed atomically and bound to the username, device and platform,
  because the library accepts a replay (V-04). Step 5 (pin comparison) is removed.
- §7: one request per pairing. §8: device theft can include this attacker (V-06); the recovery
  wrap is not returned to normal sessions.
- Server secrets: host snapshots contain the setup; theft also allows server impersonation.
- Interoperability tests: replaced the pinning test with a substituted-setup test and a replay
  test.
