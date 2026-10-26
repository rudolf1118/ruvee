# ADR-0011: Device proof of possession with per-device Ed25519 keys

- Status: Proposed. D-31 option A selected by the owner as the development direction
  (2026-10-26). Not reviewed; needs D-19 before real data.
- Date: 2026-10-26
- Specification: [device-proof.md](../security/device-proof.md)

## Context

The password plus a device's public id gave an `active` session (predeployment-review R2), and
the server accepted replacement wraps on the envelope header alone, including on the reopening
password path (R12). A password holder without `SK` could therefore lock the owner out of the
server copy, rotate the Recovery Kit to garbage, revoke devices and push commits. The options
are in [r2-device-proof-decision.md](../security/r2-device-proof-decision.md).

## Decision (proposed)

- Each device holds an Ed25519 key pair (`crypto_sign_*`, libsodium). The private key is a
  `LOCAL_RECORD` sealed under `K_local`, so it is usable only while the device is unlocked. A
  session acts as an enrolled device only after a signature with that key (at login or right
  after); the password alone gives at most a 10-minute pre-proof session with a five-route
  allowlist.
- Requests that replace encrypted key material also carry a signature by an Ed25519 key derived
  from `AK` (`KDF(AK, "rvakver1")` as the seed). It proves possession of `AK`, not that the new
  envelopes decrypt.
- Credential, key and device changes additionally need a fresh, single-use, session-bound server
  nonce, consumed in the same transaction as the change.
- Device keys are accepted only with the setup token, an approving device's signature (pairing,
  whose request MAC now covers the key), the Recovery Key, or a reopening.

## Consequences

- R2 and R12 close only together with the full authorization table of device-proof.md §7.
- ADR-0002 gains `crypto_sign_keypair`, `crypto_sign_seed_keypair`, `crypto_sign_detached` and
  `crypto_sign_verify_detached`, and the KDF context `rvakver1`.
- The pairing request MAC changes (`pair-req-2`): the pairing review (device-enrollment.md §3.4)
  must cover it.
- Devices enrolled before this change must re-enroll with the Recovery Kit (development only).
- A password holder can still read the encrypted key material during a pre-proof session; it is
  useless without `SK` and already in every database copy.
- XSS in the unlocked origin can still sign (T-18, T-19); this raises the bar from "password plus
  a public id" to "code running on an unlocked enrolled device".

## Alternatives considered

Option B (a bearer device secret with a server-side hash) and option C (every password login
pending until paired), in r2-device-proof-decision.md. A non-extractable WebCrypto key usable
while locked was considered and not chosen.
