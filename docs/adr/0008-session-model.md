# ADR-0008: Cookie sessions for web, rotating tokens elsewhere

- Status: Proposed
- Date: 2026-10-22
- Specification: [authentication.md §5](../security/authentication.md#5-sessions)

## Context

The web app runs on the same origin as the API. The extension and mobile apps can't rely on
first-party cookies. Sessions must be device-bound, revocable, protected against CSRF, and must
never grant decryption.

## Decision

- **Web:** a `__Host-ruvee_session` cookie (`HttpOnly`, `Secure`, `SameSite=Strict`), 12 hours
  idle and 14 days absolute, with `Origin` checks and a custom header.
- **Other clients:** 10-minute access tokens and rotating refresh tokens, with family revocation
  on reuse.
- **Everywhere:** tokens are random and stored hashed, and step-up is required for destructive
  actions.

## Consequences

- Script can't read web session tokens. Revocation is immediate.
- Lifetimes are an owner choice (D-08).
- Every request checks the database. That is cheap at single-user scale, and there is no Redis.

## Alternatives considered

- **Stateless JWTs.** Rejected because revocation is delayed and key management grows.
- **Bearer tokens in web storage.** Rejected because any XSS could read them.
