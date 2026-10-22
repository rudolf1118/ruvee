# ADR-0003: Two-secret key derivation with a device-held Secret Key

- Status: Proposed
- Date: 2026-10-22
- Specification: [cryptographic-design.md §3](../security/cryptographic-design.md#3-secrets-and-keys)

## Context

The server must store a wrap of the account key so that new devices and password changes work.
If that wrap depended only on the password, a stolen database would allow offline guessing.

## Decision

The password wrap is keyed by `AUK`, derived from the Argon2id output **and** a random 256-bit
Secret Key `SK`. `SK` is held on enrolled devices and inside the encrypted keyset, and never on
the server in usable form. New devices receive `SK` by pairing or through the Recovery Key.

## Consequences

- Database theft alone allows no guessing, because the wrap needs `SK` as well (T-01).
- A password alone cannot enroll a new device. Users need an enrolled device or their Recovery
  Kit. This is the main user-experience cost.
- A stolen device, or an XSS attack that reads `SK`, reduces security to the password strength
  (R-05, R-06).

## Alternatives considered

- **Password-only wrap**, as many password managers do. Rejected because of offline guessing after
  database theft.
- **Typing `SK` on each new device**, as 1Password's Emergency Kit allows. Pairing gives the same
  security with less typing. The Recovery Key covers the case with no device.
