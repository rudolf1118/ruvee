# ADR-0006: User-held Recovery Key, no administrator recovery

- Status: Proposed
- Date: 2026-10-22
- Specification: [account-recovery.md](../security/account-recovery.md)

## Context

The master prompt requires recovery-key generation and verification, a recovery procedure,
device-loss recovery and account reset. It forbids hidden administrator recovery. The prototype
says Ruvee cannot recover the master password.

## Decision

- A random 128-bit Recovery Key is shown once as a Recovery Kit, and verified before setup
  completes.
- `RWK` wraps `AK`. `RAK`, which is domain-separated from `RWK`, authorizes the recovery flow, and
  the server stores only `SHA-256(RAK)`.
- Using the key forces rotation.
- Reset destroys data and never decrypts it.

## Consequences

- Forgetting the password, or losing every device, is recoverable with the kit alone. Losing both
  the kit and the other means is permanent data loss (R-09).
- A server that sees `RAK` can take over account access and destroy the working recovery wrap,
  but cannot decrypt (R-08). A second OPAQUE registration keyed by `RK` is the alternative
  (decision D-22).
- The recovery material alone lets the kit holder unwrap `AK`, so every device is notified when
  recovery **starts**.
- After recovery from device loss, the lost devices must be revoked and `SK` rotated (R-17).
- Rotating the key does not invalidate old database backups, which still hold the old wrap.

## Alternatives considered

- **No recovery at all.** Does not meet the master prompt.
- **Server-side escrow or administrator reset of the vault.** Forbidden.
- **Social or trusted-contact recovery.** Needs sharing, which is deferred.

## Changes after architecture validation

Still **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](../security/architecture-validation.md):

- Consequences: the junk-wrap case, the notice at start, and the device-loss steps (V-07,
  V-08).
- The decision itself is unchanged.
