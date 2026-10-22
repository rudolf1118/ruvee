# ADR-0004: OPAQUE authentication, separate from vault keys

- Status: Proposed
- Date: 2026-10-22
- Specification: [authentication.md](../security/authentication.md)

## Context

Login must not reveal a password-equivalent to the server, its logs or a TLS-terminating proxy.
The master prompt suggests OPAQUE if a mature implementation exists, and requires authentication
to be designed separately from encryption.

## Decision

Use OPAQUE (RFC 9807) through `@serenity-kit/opaque` 1.1.0 (`opaque-ke` 4.0.0, ristretto255 and
SHA-512, "memory-constrained" Argon2id) on the server, the web app and the extension.

- `export_key` is not used. Vault keys never derive from authentication, and authentication never
  derives from vault keys. The one exception is `RAK` for recovery.
- The OPAQUE server setup lives outside the database.
- Clients pin the server's static public key.

## Consequences

- There is no password-equivalent on the server, and no guessing after a database theft without
  the separate secret.
- Logging in costs one more Argon2id evaluation.
- Mobile has no current binding, which blocks Phase 6 authentication until a spike resolves it
  (D-05, R-04).
- Audits predate the versions used (R-02).

## Alternatives considered

- **Client-hashed password with a server-side hash and pepper.** Documented as a fallback in
  authentication.md §2.3. It is **not recommended**, because the server sees a login-equivalent
  at every login.
- **SRP-6a.** Not preferred: the server sends the salt in the clear, which allows precomputation
  against a targeted account, a weakness OPAQUE is designed to avoid. SRP implementations were not
  evaluated in Phase 0 research.
