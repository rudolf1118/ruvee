# ADR-0005: Device enrollment by MAC-authenticated pairing

- Status: Proposed
- Date: 2026-10-22
- Specification: [device-enrollment.md §3](../security/device-enrollment.md#3-adding-a-device-by-pairing)

## Context

A new device needs `SK`. The server relays every message between devices, and must not be able
to substitute its own key in either direction.

## Decision

The enrolled device shows a 128-bit pairing secret as a 29-character code or QR code. Both
devices derive `K_pair` from it, and MAC the new device's ephemeral X25519 key and the sealed
reply. The approving device names the new device, and the server never sees the name in
plaintext. The reply also carries a sync checkpoint.

## Consequences

- The server cannot substitute keys or alter the platform shown for approval (T-05).
- The new device starts with a checkpoint, so it detects rollback from its first sync.
- The code is longer than a numeric PIN.
- Compromised endpoints and a malicious web app on either device are outside what pairing
  protects (R-01).

## Alternatives considered

- **A short code with a PAKE (CPace or SPAKE2).** No audited JavaScript and React Native
  implementation exists among the selected libraries. Revisit later.
- **Fingerprint comparison.** Unreliable in practice.
- **A password-only wrap.** Rejected by ADR-0003.
