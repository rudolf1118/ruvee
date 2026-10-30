# ADR-0005: Device enrollment by MAC-authenticated pairing

- Status: Accepted for development (owner, 2026-10-25). Not independently reviewed; not approved for real data.
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
- The code is longer than a numeric PIN, and **must stay that long**: the 128 bits of the secret
  are the whole security margin, because a recorded transcript lets anyone test guesses. A
  shorter code is blocked unless a reviewed PAKE implementation exists.
- The protocol is a Ruvee-specific composition, not an established protocol. It must be reviewed
  independently before real data.
- One request per pairing; a MAC failure burns the pairing; the server binds the request to the
  requesting session's device.
- Compromised endpoints and a malicious web app on either device are outside what pairing
  protects (R-01).

## Alternatives considered

- **A short code with a PAKE (CPace or SPAKE2).** No audited JavaScript and React Native
  implementation exists among the selected libraries, and none usable was found on npm. Revisit
  later.
- **HPKE (RFC 9180) PSK mode for the reply.** Standardized, but the JavaScript implementation is
  unaudited and it does not cover the request. Left for the reviewer.
- **Fingerprint comparison.** Unreliable in practice.
- **A password-only wrap.** Rejected by ADR-0003.

## Changes after architecture validation

Still **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](../security/architecture-validation.md):

- Consequences: the no-shortening rule, the review requirement and the single-request rule
  (V-09). The payload no longer carries the OPAQUE server key or `instance_id` (V-02, V-03).
- Alternatives: PAKE search result and HPKE added.
- The cryptographic construction is unchanged.
