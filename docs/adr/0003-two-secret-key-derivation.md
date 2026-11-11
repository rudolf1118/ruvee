# ADR-0003: Two-secret key derivation with a device-held Secret Key

- Status: **Accepted for development** (owner approval of D-04, 2026-10-24). This is an
  implementation decision, not a security audit, and not approval to store real secrets. It does
  not approve the pairing protocol (D-21, [ADR-0005](0005-device-pairing.md)), which stays open.
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

- A database copy alone allows no guessing against the vault wrap, because the wrap needs `SK`
  as well (T-01). This does **not** cover the OPAQUE record: with the OPAQUE server setup, the
  password can be guessed without `SK`, but a cracked password still doesn't decrypt. The exact
  conditions are in
  [architecture-validation.md §3.4](../security/architecture-validation.md#34-the-narrowed-claim).
- Once `SK` has leaked from a device, later database copies are guessable until `SK` is
  rotated (R-17).
- A password alone cannot enroll a new device. Users need an enrolled device or their Recovery
  Kit. This is the main user-experience cost.
- A stolen device, or an XSS attack that reads `SK`, reduces security to the password strength
  (R-05, R-06).

## Alternatives considered

- **Password-only wrap**, as many password managers do. Rejected because of offline guessing after
  database theft.
- **Typing `SK` on each new device**, as 1Password's Emergency Kit allows. Pairing gives the same
  security with less typing. The Recovery Key covers the case with no device.

## Changes after architecture validation

Still **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](../security/architecture-validation.md):

- Consequences: the database-theft claim is narrowed to the vault wrap and to `SK` not having
  leaked; the OPAQUE path is stated separately (V-01, V-08).
- The decision itself is unchanged.

## Changes after P2-03

On 2026-10-24 the owner approved D-04 for this development milestone, with the condition that a
password alone must never give a new device decryption capability. `packages/crypto` implements
the derivation of `AUK` from the Argon2id output and `SK`, and the password wrap of `AK` keyed by
`AUK`. Tests show that `AUK` changes with the password for a fixed `SK`, and that no envelope
purpose is keyed by `SK` alone (INV-17). Pairing and recovery, the two ways a new device obtains
`SK`, are not implemented.
