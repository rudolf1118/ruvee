# D-31 (proposed): device proof of possession and wrap-replacement checks

> **Status: proposal for the owner's decision. Not approved, not implemented.** It answers
> predeployment-review R2 (and R12, which has the same root). Nothing here is a reviewed
> cryptographic protocol; whichever option is chosen must be written up as an ADR, given test
> vectors and reviewed independently (D-19) before real data. Until then R2 and R12 stay open.

## 1. The problem, in Ruvee's own terms

- `POST /auth/login/finish` trusts the `deviceId` the client sends. The password plus a known,
  non-revoked device id yields an `active` session for that device
  (`auth.service.ts` `loginFinish`). Device ids are not secret: they appear in `GET /devices`,
  security events, logs and every database copy.
- An `active` session may replace `AK_WRAP_PASSWORD`, `AK_WRAP_RECOVERY` and the keyset after a
  step-up, which is the password again. The server checks only the envelope **headers**
  (`account-security.service.ts` `passwordFinish`, the kit rotation, the reopening completion).
  It cannot tell a real wrap of `AK` from random bytes.
- So the password alone gives T-14 powers (lock the owner out of the server copy, rotate the
  kit to garbage, revoke devices), contrary to device-enrollment.md §1 and INV-06, which say a
  password alone yields a `pending` device. Vault contents stay safe: decryption needs `SK`.

Two separate questions follow, and both need an answer:

1. **Device possession:** how an enrolled device proves it is that device, with something other
   than its public identifier.
2. **Key possession:** how the server checks that whoever replaces a wrap holds `AK`.

## 2. Options

### Option A: per-device signing key, plus an account verification key derived from `AK` (recommended for discussion)

Recommended because it separates the two questions cleanly: the device key answers "is this
the enrolled device" without the server holding anything secret, and the `AK`-derived key answers
"does the uploader hold `AK`" without the server learning anything that decrypts. It uses one
well-known primitive, Ed25519 (libsodium `crypto_sign`, already in the dependency), which is
not yet among Ruvee's approved primitives (ADR-0002).

**Device key, and where it lives.** Each device generates an Ed25519 key pair (`DSK`, `DPK`) when
it first logs in as a new device, before it is enrolled. The server stores `DPK` in the device
row once the device is enrolled, never before. Until enrollment `DSK` exists only in the worker's
memory (a device that restarts mid-pairing starts again with a new key). After enrollment it is
stored like `SK` (device-enrollment.md §5), sealed under `K_local` (derived from `AK`), so it is
**usable only while unlocked**. Ruvee's unlock already opens `AK` locally before it restores the
server session, so login and every proof below happen after a local unlock; a locked device can
prove nothing. (An alternative for the owner: a non-extractable WebCrypto key, usable while
locked and not exportable by script, but usable by any script in the origin; not proposed.)

**Initial trust.** `DPK` is accepted only through a path that already proves more than the
password:

- the first device: in the bootstrap request, authorized by the host-issued setup token;
- pairing: in B's pairing request, which `req_mac` covers, so device A approves exactly this key
  and the server cannot substitute it (device-enrollment.md §3.3);
- recovery: in the request that proves `RAK`, so the Recovery Kit holder enrolls the key;
- reopening (D-30): a device active in the snapshot proves with its restored `DPK`; a device
  enrolled by the Recovery Kit path registers a new one as in recovery.

**Login.** `login/start` returns, with `loginId`, a 32-byte random `challenge` kept in the same
single-use login state. An enrolled device sends
`Sign(DSK, "ruvee/v1/device-login" ‖ account_id ‖ device_id ‖ loginId ‖ challenge ‖ H(finishLoginRequest))`.
The server checks it against the stored `DPK` after OPAQUE succeeds; without a valid signature
the login creates a new `pending` device, as for an unknown id, and never adopts an existing one.
Both are required: a valid signature never replaces the password.

**Which operations require proof.** Every request that changes credentials, keys or devices:
step-up (`reauth/finish`), password change, Recovery Kit rotation, `SK` rotation, device revoke,
pairing approval, vault reset, and the reopening completion. Each obtains a fresh single-use
`nonce` from the server, bound to its session (for example returned by that operation's own
`…/start`), and sends
`Sign(DSK, "ruvee/v1/device-op" ‖ account_id ‖ device_id ‖ session_ref ‖ op_name ‖ nonce ‖ H(canonical request body))`.
`session_ref` is a value the server derives from the session, never the cookie. The server
consumes the nonce in the same transaction as the operation. This binds the proof to one
account, device, session, operation and body, and the consumed nonce stops replay. Ordinary
reads and sync commits do not need it.

**Validating a replacement wrap (key possession).** The client derives
`(AVSK, AVPK) = crypto_sign_seed_keypair(KDF(AK, "rvakver1"))`. The server stores `AVPK` with the
keyset at account creation (and a new one after a full rotation). Every upload that replaces a
wrap or the keyset includes
`Sign(AVSK, "ruvee/v1/wrap-replace" ‖ account_id ‖ ak_id ‖ ak_epoch ‖ op_name ‖ nonce ‖ H(new envelope(s)))`,
and the server refuses a replacement without a valid signature under the current `AVPK`.

What this does and does not establish:

- It proves that whoever made the request held `AK` (or a key derived from it) at that moment,
  and that these exact envelopes were what they chose to upload.
- It does **not** prove that the new envelopes are correct or decrypt to `AK`. The server cannot
  check that without the keys. The client must open its own new wrap before uploading (it does so
  for the password path), and a client that holds `AK` can always upload garbage and lock its
  owner out; that is outside what any server-side check can stop.
- `AVPK` reveals nothing that decrypts: it is a public key, and `KDF` is one-way.

**Replay and restore.** Challenges and nonces are random, single-use and short-lived, and are
never part of a backup. A restored server has the `DPK`s and `AVPK` as of the snapshot. A
signature captured before the backup names a nonce that no longer exists, and the restore policy
ends every session, so nothing captured earlier replays against the restored server.

### Option B: per-device secret with a server-side hash, plus an `AK`-derived verifier

A device receives a random 256-bit `device_secret` at enrollment; the server stores
`SHA-256(device_secret)` and the client presents the secret at login. Wraps carry
`MAC(KDF(AK, "rvakver1"), …)`, and the server stores that key to check the MAC.

- Simpler: no new primitive.
- Weaker: the secret is a bearer token. A malicious or compromised server, or anyone who reads
  the server's memory or TLS-terminated traffic, learns it and can replay it. The server must hold
  the MAC key, so anyone with the database can forge wrap replacements (they could already
  replace rows, but the check would no longer separate "had the database" from "had `AK`").

### Option C: no device proof; every password login is `pending`

Every login creates or reuses only a `pending` device; activation always needs pairing or the
Recovery Kit.

- No cryptography added; it closes the device half of R2.
- Every new browser session needs pairing, including on an already-enrolled device whose cookie
  expired (D-08: 14 days absolute). That is a usability change the owner must accept.
- Does not answer the key-possession half. Combine it with Option A's or B's verifier.

## 3. Effects on each flow (Option A; B and C differ as noted)

| Flow                               | What changes                                                                                                                                                                                                                       | Open points                                                                                                                                                                                                                    |
| ---------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **First device (bootstrap)**       | The bootstrap request adds `DPK` and `AVPK`.                                                                                                                                                                                       | None beyond the format.                                                                                                                                                                                                        |
| **Pairing**                        | B generates `(DSK, DPK)` before the request; `DPK` is added to the request that `req_mac` covers, so A approves exactly that key and the server cannot substitute it (device-enrollment.md §3.3).                                  | The pairing protocol's MAC input changes: its review (§3.4) must cover it.                                                                                                                                                     |
| **Recovery (Recovery Kit)**        | The new device registers its `DPK` in the same request that proves `RAK`; it obtains `AK`, so it can sign wrap replacements.                                                                                                       | Whether recovery itself should also invalidate every other device's `DPK` (it rotates `SK` after device loss already).                                                                                                         |
| **Reopening (D-30)**               | The password path's completion requires the device signature (the device was active at the snapshot, so its `DPK` was restored) and the `AVPK` signature; this closes R12. The Recovery Kit path signs with the `AK` it recovered. | Devices enrolled after the snapshot have no restored `DPK`: they re-pair, as today.                                                                                                                                            |
| **Revocation**                     | The server deletes or marks the `DPK`. A revoked device cannot activate again with the password alone.                                                                                                                             | None.                                                                                                                                                                                                                          |
| **`SK` rotation, password change** | No change to `DSK`; the replacement carries the `AVSK` signature.                                                                                                                                                                  | None.                                                                                                                                                                                                                          |
| **Full rotation (Phase 4)**        | New `AK` gives a new `AVPK`; the upload is signed under the **old** `AVSK` and carries the new `AVPK`.                                                                                                                             | Must be part of the Phase 4 design.                                                                                                                                                                                            |
| **Backup and restore**             | `DPK` and `AVPK` are restored as of the snapshot; the existing device review (D-28) covers devices revoked later.                                                                                                                  | None new.                                                                                                                                                                                                                      |
| **Migration of existing accounts** | Existing devices have no `DPK`. A one-time "register my key" step is exactly what an R2 attacker would do first, so it must not be allowed from a password-only session.                                                           | **Owner decision:** (a) development data is synthetic, so require re-enrollment (reset) and allow no migration; or (b) allow registration only from a session that existed before the cutover, once. (a) is simpler and safer. |
| **Extension, mobile (later)**      | Same scheme; mobile keeps `DSK` in the platform key store.                                                                                                                                                                         | Phase 5 and 6 designs.                                                                                                                                                                                                         |

## 4. What the owner is asked to decide

1. Option A, B, C, or C combined with A's verifier.
2. Adding Ed25519 (`crypto_sign`) to the approved primitives (ADR-0002), if A is chosen.
3. Whether step-up and the listed sensitive operations require the device signature (A), or only
   login does.
4. The migration choice in §3.
5. That the result is written as an ADR with test vectors and goes to the independent review
   with the pairing protocol (D-19).
6. Whether a non-extractable WebCrypto key (usable while locked) is preferred to a `K_local`-sealed
   key (usable only while unlocked).

## 5. Claims that need independent cryptographic review

- The transcript formats above: domain separation, unambiguous encodings (length-prefixed or
  fixed-size fields), and that no signature in one context verifies in another.
- That `KDF(AK, "rvakver1")` as an Ed25519 seed is sound alongside Ruvee's other `AK`
  derivations, and the handling of `AVPK` across full rotation.
- The pairing change: `DPK` inside the `req_mac` input, and that the server still cannot
  substitute keys (device-enrollment.md §3.4 is already a pending review item).
- That the set of operations requiring proof is complete, and the nonce lifecycle has no gap
  (issued, bound, consumed atomically, expired).
- The migration and recovery paths: that no password-only path can register a `DPK` or `AVPK`.

## 6. Limits, whichever option is chosen

- XSS in the web origin, while unlocked, can use `DSK` and `AVSK` (T-18, T-19). This raises the
  bar from "password plus a public id" to "code running on an enrolled, unlocked device"; it does
  not defend against that.
- A malicious server can still refuse service, serve old data (handled by checkpoints, INV-07),
  or lie about device lists; it cannot forge the signatures.
- Nothing here changes what a device that already holds `SK` and the password can decrypt.
