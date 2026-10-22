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
