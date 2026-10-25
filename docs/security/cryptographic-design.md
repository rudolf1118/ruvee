# Cryptographic design

Status: **Proposed (Phase 0).** Not independently reviewed. The byte format is not frozen. The
owner approved D-01, D-04 and D-20 for development on 2026-10-24, and `packages/crypto`
implements the parts listed in
[§10](#10-implementation-status-packagescrypto-p2-03). The rest may be implemented only once the
decisions it depends on in [open-decisions.md](../architecture/open-decisions.md) are approved.

This document is authoritative for keys, derivations, envelope formats, byte encodings, limits
and test vectors. Protocol flows that use these keys live elsewhere:

- server authentication and sessions: [authentication.md](authentication.md)
- adding devices: [device-enrollment.md](device-enrollment.md)
- recovery and reset: [account-recovery.md](account-recovery.md)
- sync, rollback detection and local storage: [sync-protocol.md](../architecture/sync-protocol.md)

The threats this design addresses are in [threat-model.md](threat-model.md), and the properties
it must uphold are in [security-invariants.md](security-invariants.md).

## 1. Summary of the construction

| Need                                 | Choice                                                                | Library call (libsodium)                                                   |
| ------------------------------------ | --------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| Password stretching                  | Argon2id v1.3, versioned profiles, p=1                                | `crypto_pwhash` with `ALG_ARGON2ID13`                                      |
| Combining password and device secret | Keyed BLAKE2b-256 (Secret Key as key)                                 | `crypto_generichash(32, msg, key)`                                         |
| Subkeys from a random key            | libsodium KDF (BLAKE2b with salt and personalization), 8-byte context | `crypto_kdf_derive_from_key`                                               |
| Authenticated encryption             | XChaCha20-Poly1305-IETF, random 192-bit nonce, explicit AAD           | `crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt`                       |
| Key transfer to a new device         | X25519 sealed box to an ephemeral key, plus a pairing-secret MAC      | `crypto_box_keypair`, `crypto_box_seal(_open)`, `crypto_generichash` keyed |
| Hashing for integrity commitments    | BLAKE2b-256 with domain prefix                                        | `crypto_generichash(32, msg)`                                              |
| Randomness                           | libsodium CSPRNG (OS-backed)                                          | `randombytes_buf`                                                          |
| Server authentication                | OPAQUE (RFC 9807), separate from all keys below                       | `@serenity-kit/opaque` (see [authentication.md](authentication.md))        |

**One library family for every client.** Web and extension use `libsodium-wrappers-sumo`. Mobile
uses `react-native-libsodium`, which wraps native libsodium on iOS and Android. Both expose the
same libsodium functions, so every client runs the same primitives with the same parameters and
byte formats. The server never encrypts or decrypts vault data and needs none of these keys. The
rationale and rejected alternatives are in [ADR-0002](../adr/0002-libsodium-primitives.md).

**Why not HKDF.** The master prompt lists HKDF as a candidate. libsodium.js 0.8.4 exports HKDF
constants but not the HKDF functions (verified by running it; see
[research-sources.md](research-sources.md)). `react-native-libsodium` marks its HKDF functions
`_unstable_`. WebCrypto HKDF is absent on React Native. libsodium's BLAKE2b-based derivation is
available and stable on every target, so it is used instead. Both are standard, keyed-PRF-based
derivations; the choice is about implementation availability, not strength.

**Why not AES-256-GCM.** libsodium.js does not provide it, so web and mobile would need two
different implementations (WebCrypto and native APIs). Its 96-bit nonce also makes random nonces
unsafe beyond about 2³² messages per key. XChaCha20-Poly1305's 192-bit random nonce removes
nonce-management state, which matters for offline devices. XChaCha20 is an **expired IETF draft,
not an RFC**. It is used because the implementation is mature and has independent test vectors,
not because it is standardized.

## 2. Notation and encodings

- `‖` is byte concatenation.
- `u8`, `u16`, `u32` and `u64` are unsigned big-endian integers of 1, 2, 4 and 8 bytes.
- `LP(x)` is `u32(len(x)) ‖ x`.
- A UUID is encoded as its 16 raw bytes (RFC 9562 byte order). All Ruvee identifiers are random
  (version 4) UUIDs generated from the CSPRNG.
- Domain strings such as `"ruvee/v1/auk"` are ASCII with no terminator. Every domain string used
  in one hash input is followed only by fixed-length fields or `LP` fields, so inputs are
  unambiguous.
- `H(msg)` is `crypto_generichash(32, msg)`: unkeyed BLAKE2b-256.
- `MAC(key, msg)` is `crypto_generichash(32, msg, key)`: keyed BLAKE2b-256.
- `KDF(key, ctx)` is `crypto_kdf_derive_from_key(32, 1, ctx, key)`. `ctx` is exactly 8 ASCII bytes,
  and the subkey id is always 1; separation comes from the context.
- **Lengths are checked by Ruvee, not by the library.** Every key, salt, nonce and context is
  checked for its exact length before a libsodium call. libsodium.js 0.8.4 accepts a 15-byte
  BLAKE2b key although the documented minimum is 16, and reports
  `crypto_pwhash_MEMLIMIT_MAX` as a negative number. No limit is read from library constants
  ([validation V-12](architecture-validation.md#1-findings)).
- In JSON APIs, binary values are base64url without padding. Byte-exact formats (envelopes,
  records, manifests) are always transported as base64url of the exact bytes defined here, never
  re-serialized.

## 3. Secrets and keys

| Name                          | Size     | Generated by                                   | Purpose                                                                                                                       |
| ----------------------------- | -------- | ---------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| Master password `P`           | variable | User                                           | Something the user knows. Input to OPAQUE and to `PwK`. Never stored, logged or sent.                                         |
| Password salt `salt_pw`       | 16 B     | Client CSPRNG, new for every password set      | Salt for `PwK`. Stored on the server in plaintext.                                                                            |
| Password key `PwK`            | 32 B     | `Argon2id(P, salt_pw, profile)`                | Intermediate; only used to derive `AUK`.                                                                                      |
| Secret Key `SK`               | 32 B     | Client CSPRNG at account creation              | Device-held second secret. Copied to enrolled devices; stored in the encrypted keyset. Never sent to the server in plaintext. |
| Account Unlock Key `AUK`      | 32 B     | `MAC(SK, …PwK…)`                               | Wraps `AK`.                                                                                                                   |
| Account Key `AK`              | 32 B     | Client CSPRNG at account creation or rotation  | Root of the account's data keys. Identified by `ak_id` (16 B random) and `ak_epoch` (u32).                                    |
| Recovery Key `RK`             | 16 B     | Client CSPRNG at creation or rotation          | User-held recovery secret, printed in the Recovery Kit. Identified by `recovery_key_id` (16 B random).                        |
| Recovery Wrapping Key `RWK`   | 32 B     | `MAC(RK, "ruvee/v1/recovery-wrap")`            | Wraps `AK` for recovery.                                                                                                      |
| Recovery Auth Key `RAK`       | 32 B     | `MAC(RK, "ruvee/v1/recovery-auth")`            | Proves possession of `RK` to the server. The server stores only `SHA-256(RAK)`.                                               |
| Keyset key `K_keyset`         | 32 B     | `KDF(AK, "rvkeyst1")`                          | Encrypts the keyset: `SK` and vault keys.                                                                                     |
| Local storage key `K_local`   | 32 B     | `KDF(AK, "rvlocal1")`                          | Encrypts device-local records such as the pending-change queue and sync checkpoint.                                           |
| Device label key `K_devlabel` | 32 B     | `KDF(AK, "rvdevlb1")`                          | Encrypts user-visible device names stored on the server.                                                                      |
| Vault Key `VK`                | 32 B     | Client CSPRNG, one per vault                   | Wraps item keys. Identified by `vk_id` (16 B random). V1 has exactly one vault.                                               |
| Manifest key `K_manifest`     | 32 B     | `KDF(VK, "rvmanif1")`                          | Encrypts and authenticates the vault manifest.                                                                                |
| Item Key `IK`                 | 32 B     | Client CSPRNG, one per item                    | Encrypts one item's body. Identified by `ik_id` (16 B random).                                                                |
| Pairing secret `S`            | 16 B     | Existing device CSPRNG, per enrollment attempt | Authenticates a new device's ephemeral key and the reply. See [device-enrollment.md](device-enrollment.md).                   |

Hierarchy:

```
P ──Argon2id(salt_pw, profile)──► PwK ─┐
                                       ├─ MAC(SK, …) ──► AUK ──wraps──► AK
SK (device-held) ──────────────────────┘                                │
RK (Recovery Kit) ──► RWK ──wraps──────────────────────────────────────►│
                  └─► RAK (server auth for recovery only)               │
                                                                        ├─KDF─► K_keyset ──encrypts──► keyset { SK, VK… }
                                                                        ├─KDF─► K_local
                                                                        └─KDF─► K_devlabel
VK ──wraps──► IK ──encrypts──► item body
VK ──KDF──► K_manifest ──encrypts──► vault manifest
```

`AK` and `VK` are separate so that a future shared vault can give another member `VK` without
giving them the account root. Per-item keys let an item move to another vault later by
re-wrapping its 32-byte key instead of re-encrypting its body.

### 3.1 Password normalization

`P` is produced in this order:

1. Reject the input unless it is a well-formed string (`String.prototype.isWellFormed()`, or
   the platform's equivalent check for unpaired surrogates). Both libraries silently replace a
   lone surrogate with U+FFFD, so without this check two different inputs would derive the same
   keys (spike LS-09c, OP-08).
2. Apply Unicode NFC. No trimming, case folding or other changes.
3. Encode as UTF-8, and reject an empty result or one longer than 4,096 bytes.

The same normalized string is given to OPAQUE, which encodes it as UTF-8 itself, and its UTF-8
bytes are given to Argon2id. Neither library normalizes: NFC and NFD forms of one password
derive different keys. Minimum length and strength
policy is a UX decision ([open decision D-09](../architecture/open-decisions.md)); the
cryptography does not depend on it.

### 3.2 Argon2id profiles

KDF parameters are never sent as raw numbers. Accounts store a **profile id** from a fixed
registry compiled into every client. A client must reject an unknown profile id and must never
derive with parameters weaker than profile 1. This stops a malicious server from downgrading the
work factor.

| Profile | Status                      | Memory                                 | Iterations (`opslimit`) | Lanes | Output |
| ------- | --------------------------- | -------------------------------------- | ----------------------- | ----- | ------ |
| 1       | V1 default, **provisional** | 64 MiB (`memlimit` = 67,108,864 bytes) | 3                       | 1     | 32 B   |
| 2       | Reserved                    | 256 MiB                                | 3                       | 1     | 32 B   |

Why these values:

- Profile 1 matches the memory and iteration count of RFC 9106's second recommended option
  (64 MiB, t=3). Lanes are 1 because libsodium's Argon2id API fixes parallelism at 1. An attacker
  using p=1 parameters pays the same memory-time cost per guess, while the defender cannot use
  multiple cores. It is well above the OWASP server-side minimums.
- The first RFC 9106 option (2 GiB) is not feasible in a browser tab, an MV3 service worker or a
  mid-range phone.
- **Calibration is done per release, not per device.** One account is unlocked on every device
  the user owns, so parameters must be affordable on the weakest supported device. Before
  Phase 2 code is accepted, profile 1 must be benchmarked in the
  [platform spike](../planning/implementation-roadmap.md). The budget is a median of at most
  2 seconds and a peak of at most 128 MiB on the reference low-end Android device, in a Web Worker
  in Chrome and Safari, and in the MV3 service worker. If a platform misses the budget, the
  platform is blocked and the owner decides. **Profile 1 is never silently weakened.**
- **Measured so far (one Apple M5 machine only):** profile 1 takes about 80 ms in a dedicated
  worker in Chromium, Chrome, Playwright Firefox and Playwright WebKit, and in Node. In the MV3
  extension service worker it takes about 300 ms. Nothing was measured on a phone or an older
  laptop, and these numbers must not be used to argue for them. Profile 1 stays provisional
  until P2-02 measures the reference devices
  ([architecture-validation.md §7](architecture-validation.md#7-key-derivation-measurements)).
  The P2-02 benchmark on the same machine, 20 samples per engine, measured a median of 82 to
  98 ms ([kdf-calibration.md](kdf-calibration.md)).
- **The peak-memory budget needs a definition (D-03).** Browsers expose only the WebAssembly
  memory size (64.3 MiB for profile 1), not process memory. In Node the whole process peaked at
  136 MiB for profile 1, of which 45 MiB was the idle runtime. Whether the 128 MiB budget means
  memory added by the derivation or the whole process must be decided before it can be checked.
- Profile 2 is enabled only by a future release, after the same benchmarks pass on every
  supported platform. Moving an account to a new profile requires an unlocked device and only
  re-wraps `AK` (section 6.1). Items are not re-encrypted.

Resource bounds: clients run Argon2id in a worker (Web Worker, extension offscreen document or
native thread), never on the UI thread. A client never runs more than one derivation at a time,
and abandons a derivation when the unlock screen is dismissed.

### 3.3 Derivations

```
PwK = crypto_pwhash(32, P, salt_pw, opslimit(profile), memlimit(profile), ALG_ARGON2ID13)

AUK = MAC(SK, "ruvee/v1/auk" ‖ account_id ‖ u8(profile) ‖ salt_pw ‖ PwK)

RWK = MAC(RK, "ruvee/v1/recovery-wrap")
RAK = MAC(RK, "ruvee/v1/recovery-auth")

K_keyset   = KDF(AK, "rvkeyst1")
K_local    = KDF(AK, "rvlocal1")
K_devlabel = KDF(AK, "rvdevlb1")
K_manifest = KDF(VK, "rvmanif1")
```

`AUK` is a keyed BLAKE2b with `SK` as the key. If `SK` is unknown, `AUK` is pseudorandom
whatever the password. If `SK` is known (for example after a device is stolen), finding `AUK`
costs one Argon2id evaluation per password guess.

`RK` is 128 bits from the CSPRNG and is not guessable. It is used directly as a BLAKE2b key
(16 bytes is libsodium's documented `crypto_generichash_KEYBYTES_MIN`; Ruvee checks the length
itself, see section 2). `RWK` and `RAK` are bound to the
account and to `recovery_key_id` through the AAD of the recovery wrap (section 4.3), not through
the derivation. That way recovery can start from the Recovery Kit and a username alone.

## 4. Encryption envelope (format version 1)

Every symmetric encryption in Ruvee produces exactly this structure:

| Offset | Size     | Field            | Value                                                             |
| ------ | -------- | ---------------- | ----------------------------------------------------------------- |
| 0      | 2        | `magic`          | `0x52 0x56` (`"RV"`)                                              |
| 2      | 1        | `format_version` | `0x01`                                                            |
| 3      | 1        | `alg`            | `0x01` = XChaCha20-Poly1305-IETF                                  |
| 4      | 1        | `purpose`        | See section 4.3                                                   |
| 5      | 16       | `key_id`         | Identifies the key generation; meaning per purpose (section 4.3)  |
| 21     | 24       | `nonce`          | 24 bytes from `randombytes_buf`, fresh for every encryption       |
| 45     | variable | `ciphertext`     | Plaintext length + 16-byte Poly1305 tag (libsodium combined mode) |

`header` is bytes 0–44 (45 bytes).

### 4.1 Associated data

```
AAD = "ruvee/v1/aad" ‖ header ‖ context(purpose)
```

`context(purpose)` is the purpose-specific byte string in section 4.3. The context is **not**
stored in the envelope. The decrypting side rebuilds it from what it expects (which item, which
revision, which vault), so an envelope moved to a different place, revision or purpose fails to
decrypt. Because the header is included in the AAD, the version, algorithm, purpose, key id and
nonce are all authenticated.

### 4.2 Nonces

- Every encryption draws a new 24-byte nonce from `randombytes_buf`. There are no counters and no
  deterministic nonces.
- Re-encrypting the same plaintext (for example re-saving an unchanged item) still draws a new
  nonce.
- With 192-bit random nonces, the collision probability stays negligible for any number of
  encryptions Ruvee will perform under one key. The libsodium documentation states that random
  nonces are safe for this construction.
- Tests must assert that two encryptions of the same input under the same key produce different
  nonces, and that no code path accepts a caller-supplied nonce outside test-vector generation.
  The test-vector interface is a separate, test-only entry point.

### 4.3 Purposes

| `purpose` | Name               | Key          | `key_id`          | `context`                                                       | Plaintext                      | Max envelope size |
| --------- | ------------------ | ------------ | ----------------- | --------------------------------------------------------------- | ------------------------------ | ----------------- |
| `0x01`    | `AK_WRAP_PASSWORD` | `AUK`        | `ak_id`           | `account_id ‖ u32(ak_epoch) ‖ u8(profile) ‖ salt_pw`            | `AK` (32 B)                    | exactly 93 B      |
| `0x02`    | `AK_WRAP_RECOVERY` | `RWK`        | `recovery_key_id` | `account_id ‖ ak_id ‖ u32(ak_epoch)`                            | `AK` (32 B)                    | exactly 93 B      |
| `0x03`    | `KEYSET`           | `K_keyset`   | `ak_id`           | `account_id ‖ u32(keyset_version)`                              | Keyset JSON (section 5.1)      | 16,445 B          |
| `0x04`    | `ITEM_KEY`         | `VK`         | `vk_id`           | `vault_id ‖ item_id ‖ ik_id`                                    | `IK` (32 B)                    | exactly 93 B      |
| `0x05`    | `ITEM_BODY`        | `IK`         | `ik_id`           | `vault_id ‖ item_id ‖ u64(revision) ‖ u16(item_schema_version)` | Padded item JSON (section 5.2) | 65,597 B          |
| `0x06`    | `MANIFEST`         | `K_manifest` | `vk_id`           | `vault_id ‖ u64(seq)`                                           | Manifest (section 5.3), 137 B  | exactly 198 B     |
| `0x07`    | `LOCAL_RECORD`     | `K_local`    | `ak_id`           | `device_id ‖ LP(record_name)`                                   | Local record JSON              | 1,048,637 B       |
| `0x08`    | `DEVICE_LABEL`     | `K_devlabel` | `ak_id`           | `account_id ‖ device_id`                                        | UTF-8 label, ≤ 128 B           | 189 B             |

Purpose values `0x09`–`0x0F` are reserved for attachments, portable backups and device-bound
local wraps in later phases. They must be specified before use.

### 4.4 Parsing rules

A decoder must check, in this order, and fail closed with a typed error:

1. The length is at least 61 bytes (45-byte header and 16-byte tag) and no more than the
   purpose's maximum. Exact-size purposes must match exactly.
2. `magic` is `"RV"`, `format_version` is `1` and `alg` is `1`. Anything else fails with
   `unsupported_format`. A client never "tries" other versions.
3. `purpose` equals the purpose the caller expects. A caller always states what it expects.
4. `key_id` equals the key the caller is about to use. A mismatch fails with `wrong_key`, before
   decryption is attempted.
5. AEAD decryption with the rebuilt AAD. A failure is `integrity_failure`, and no partial
   plaintext is ever returned. The AEAD reports only that authentication failed: a changed
   nonce, ciphertext, tag or AAD field all produce the same library error (spike LS-04). So
   `integrity_failure` is one class, and no code may try to tell which field was changed.
6. Plaintext post-checks: exact lengths for key material, valid padding for item bodies, and
   schema validation for JSON. A failure is `malformed_plaintext`.

Errors never include key material, plaintext or full ciphertext. Their handling is described in
section 7.

## 5. Plaintext formats

### 5.1 Keyset (`KEYSET`)

```json
{
  "v": 1,
  "secretKey": "<base64url 32 B>",
  "vaults": [{ "vaultId": "<uuid>", "vkId": "<base64url 16 B>", "vk": "<base64url 32 B>" }]
}
```

`keyset_version` (in the AAD and on the server) increases by 1 every time the keyset is
re-encrypted. A client that has seen version `n` rejects a keyset with a lower version. This is
rollback protection for the keyset; see [sync-protocol.md](../architecture/sync-protocol.md).

### 5.2 Item record and body

The server stores one **item record** per item:

```
record = "RVI" ‖ u8(1) ‖ LP(item_key_envelope) ‖ LP(item_body_envelope)
```

- `item_key_envelope` is the `ITEM_KEY` envelope wrapping `IK` under `VK`.
- `item_body_envelope` is the `ITEM_BODY` envelope.
- Maximum record size is 65,702 bytes.
- `IK` stays the same across revisions of an item; every revision uses a fresh nonce.
  Re-keying an item (new `IK`) is part of full key rotation (section 6.3).

The body plaintext is UTF-8 JSON, validated against the item schema for `item_schema_version`.
Item schemas are defined in Phase 3. Every item field is inside the body, including title,
username, URLs, tags, favorite, archive and trash state, and timestamps. Before encryption the
JSON is padded with ISO/IEC 7816-4 padding (one `0x80` byte, then `0x00` bytes) to the next
multiple of 256 bytes. This is the same scheme as libsodium's `sodium_pad`, implemented in
`packages/crypto` because `react-native-libsodium` does not expose `pad`, and tested against
libsodium.js. Padded plaintext is at most 65,536 bytes.

### 5.3 Vault manifest (`MANIFEST`)

The fixed-length binary plaintext (137 bytes):

```
u8(1) ‖ vault_id ‖ u64(seq) ‖ prev_manifest_hash(32) ‖ items_digest(32)
      ‖ u32(live_count) ‖ u32(tombstone_count) ‖ author_device_id ‖ u64(created_at_ms) ‖ commit_id
```

The other values it relies on are defined as follows:

```
manifest_hash = H("ruvee/v1/manifest-hash" ‖ manifest_envelope)
record_hash   = H("ruvee/v1/record-hash" ‖ record)
entry         = item_id ‖ u64(revision) ‖ u8(state) ‖ record_hash   // state 1 = live, 2 = tombstone; record_hash = 32 zero bytes for a tombstone
items_digest  = H("ruvee/v1/items-digest" ‖ u32(n) ‖ entry_1 ‖ … ‖ entry_n)   // entries sorted by item_id, bytewise ascending
```

For the first manifest, `seq` is 1 and `prev_manifest_hash` is 32 zero bytes. How the manifest
is used is specified in [sync-protocol.md](../architecture/sync-protocol.md).

### 5.4 Recovery Key display format

The Recovery Kit shows `RK` as text and as a QR code:

```
check  = H("ruvee/v1/rk-check" ‖ RK)[0..2]                 // first 2 bytes
text   = "RK1-" ‖ CrockfordBase32(RK ‖ check)              // 18 bytes → 29 characters
```

The 29 characters are printed in groups of five. Decoding accepts lowercase letters, treats
`O` as `0` and `I`/`L` as `1`, ignores spaces and dashes, and rejects a wrong checksum before any
network request. The checksum catches typos; it adds no security.

### 5.5 Device-transfer payload

This format is defined in [device-enrollment.md](device-enrollment.md) because it is part of
that protocol. It uses only `crypto_box_seal` and `MAC` as described there.

## 6. Key lifecycle

| Key                           | Where it lives                                                                                                          | Created                | Replaced                    | Destroyed                                                                                     |
| ----------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ---------------------- | --------------------------- | --------------------------------------------------------------------------------------------- |
| `P`                           | User's memory; client memory only during derivation                                                                     | By the user            | Password change             | Client releases it after deriving `PwK` (best effort; see the sync protocol's memory section) |
| `PwK`, `AUK`                  | Client memory during unlock only                                                                                        | Each unlock            | Each unlock                 | Immediately after unwrapping `AK`                                                             |
| `SK`                          | Each enrolled device's local store; inside the encrypted keyset on the server                                           | Account creation       | SK rotation (6.2)           | Device removal, or local wipe on revocation                                                   |
| `AK`                          | Wrapped on the server (password wrap and recovery wrap); wrapped in each device's local store; in memory while unlocked | Account creation       | Full rotation (6.3)         | On lock (memory); on rotation (old wraps deleted)                                             |
| `RK`                          | Printed Recovery Kit only. Never stored on devices or the server.                                                       | Account setup          | Recovery-key rotation (6.2) | User destroys the old kit                                                                     |
| `VK`, `IK`                    | Inside the keyset and item records (wrapped); in memory while unlocked                                                  | Vault or item creation | Full rotation (6.3)         | On lock (memory)                                                                              |
| `S` and ephemeral X25519 keys | Memory of the two devices during one enrollment                                                                         | Per enrollment         | Never                       | When enrollment completes, fails or expires (10 minutes)                                      |

### 6.1 Password change and KDF upgrade (re-wrap only)

A password change re-wraps `AK`. It does not re-encrypt any item:

1. Unlock: derive `AUK` and unwrap `AK`.
2. Generate a new `salt_pw'`. Choose the profile (the same one, or a newer one for an upgrade).
3. Derive `PwK'` from the new password, then `AUK'` with the same `SK`.
4. Produce a new `AK_WRAP_PASSWORD` envelope with the same `ak_id` and `ak_epoch`.
5. Upload it together with the OPAQUE re-registration, atomically. The flow and session effects
   are in [authentication.md](authentication.md#9-password-change).

### 6.2 Narrow rotations

- **Recovery-key rotation:** generate a new `RK'` and `recovery_key_id'`. Upload the new
  `AK_WRAP_RECOVERY` and `SHA-256(RAK')`, and delete the old wrap in the same transaction. The
  flow is in [account-recovery.md](account-recovery.md#5-recovery-key-rotation).
- **Secret Key rotation:** generate `SK'`. Re-encrypt the keyset (incrementing
  `keyset_version`) and re-wrap `AK` under `AUK'` derived with `SK'`. Other devices unlock
  locally with their old wrap, then read `SK'` from the new keyset on their next sync and
  replace their local wrap. **Triggers:** revoking a device as lost or possibly compromised, and
  the end of a recovery that followed device loss. Once `SK` has left a device by theft or XSS,
  any later database copy allows offline guessing of the current password until `SK` is
  rotated ([validation V-08](architecture-validation.md#1-findings)). Rotating `SK` does not
  help against a device that already holds `AK`; only full rotation does.

### 6.3 Full rotation (new `AK`, `VK` and every `IK`)

This is the only operation that stops a former key holder from reading **future** data. It
generates a new `AK` (`ak_epoch + 1`), `VK` and a fresh `IK` for every item. It re-encrypts every
item as a new revision, writes a new keyset, new password and recovery wraps, and a new manifest
chain entry, then deletes the old wraps. It needs an unlocked device and step-up authentication.
It is a Phase 4 deliverable because it is a large sync commit; the details are in
[sync-protocol.md](../architecture/sync-protocol.md#full-key-rotation). The formats above already
carry `ak_id`, `ak_epoch`, `vk_id` and `ik_id`, so rotation needs no format change.

### 6.4 What changing a password does **not** do

Changing the password, rotating `SK` or rotating `RK` only change how `AK` is wrapped **from now
on**. None of them affect copies made earlier:

- An attacker who copied a device's local store (old wrapped `AK` and `SK`) can still try to
  guess the **old** password offline. If they succeed, they get `AK`, and with it everything the
  vault contained up to the moment they lose access to new ciphertext.
- An old server backup still holds the old password wrap and the old recovery wrap. The old
  password together with `SK`, or the old `RK`, still unwraps the **same** `AK`.
- Any plaintext an attacker already decrypted, or any ciphertext they already downloaded,
  remains exposed forever. No key operation changes that.

Full rotation (6.3) protects only data written **after** the rotation, and only if the attacker
cannot also obtain the new keys. The UI must say this plainly when the user changes their
password after a suspected compromise, and must offer full rotation together with changing the
passwords stored in the vault.

## 7. Corruption and failure handling

- **Item record fails to parse or decrypt:** mark the item "unreadable" in the client, keep the
  raw bytes, and never overwrite, delete or re-upload it automatically. Show the item id and the
  last known good revision if the local cache has one. Offer recovery from another device's copy
  or from a backup. Sync of other items continues.
- **Manifest fails to decrypt or does not match** (wrong digest, broken chain, `seq` lower than
  the checkpoint): stop applying remote changes, switch the vault to read-only from the local
  cache, and show a blocking integrity warning. Never "repair" by trusting the server.
- **Keyset or wrap fails to decrypt:** treat it as a wrong password if it occurs during unlock and
  the password wrap is the only one tried. Otherwise it is an integrity failure. Never fall back to
  an older key or an alternative format.
- **Local store corruption:** discard the local copy and re-download from the server, then
  verify against the local checkpoint if it survived. If the checkpoint is also lost, warn that
  rollback cannot be checked (see [sync-protocol.md](../architecture/sync-protocol.md#limits)).
- Every one of these failures is logged on the device without key material or plaintext. Counts
  of integrity failures may be reported to the server as security events with no item contents.

## 8. Test vectors and interoperability plan

Revised after the [architecture validation](architecture-validation.md#8-test-vector-plan-reassessed)
(V-10). The Phase 0 plan used Python and Go generators. It also expected field-specific errors
from the AEAD and cited libsodium's own test outputs as independent. Those parts are withdrawn.

**Goal.** Every client implementation must produce and accept exactly the bytes defined here.
Evidence comes from published vectors where they exist, and otherwise from **one** independent
implementation that shares no code with libsodium: `@noble/hashes`, `@noble/ciphers` and
`@noble/curves`, pinned exactly. A second independent language is not required. Noble's Argon2 is
outside its audit scope, so it is trusted only because it passes the RFC 9106 vector.

**1. Published primitive vectors.** These run in Node and in every supported browser engine, and
later on mobile:

| Primitive                                                                             | Published source                                                             | Notes                                                                                                                                                                                                                                           |
| ------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| XChaCha20-Poly1305-IETF                                                               | draft-irtf-cfrg-xchacha-03 §A.3.1; Wycheproof `xchacha20_poly1305_test.json` | Run directly through libsodium                                                                                                                                                                                                                  |
| Argon2id v1.3                                                                         | RFC 9106 §5.3; Argon2 reference `test.c` (Argon2id cases)                    | RFC 9106 needs p = 4 with secret and AD, so only noble can run it. The `test.c` vectors use 8-byte salts, so libsodium runs them through `crypto_pwhash_str_verify`. noble then cross-checks raw `crypto_pwhash` at p = 1, including profile 1. |
| BLAKE2b                                                                               | RFC 7693 Appendix A; BLAKE2 reference `blake2b-kat.txt` (keyed, 64-byte key) | Run directly through libsodium                                                                                                                                                                                                                  |
| X25519                                                                                | RFC 7748 §6.1                                                                | Run directly through libsodium                                                                                                                                                                                                                  |
| Keyed BLAKE2b-256 with 16- and 32-byte keys, `crypto_kdf`, `crypto_box_seal`, padding | **None published**                                                           | Cross-implementation checks against noble, from each function's documented definition                                                                                                                                                           |
| OPAQUE                                                                                | RFC 9807 Appendix C, identity KSF only                                       | Upstream only; see [authentication.md](authentication.md#interoperability-tests)                                                                                                                                                                |

Negative cases for the AEAD expect only "authentication fails".

**2. Ruvee protocol interoperability vectors.** These cover the derivations (`PwK`, `AUK`, `RWK`,
`RAK` and every `K_*`), one envelope of every purpose, an item record with `record_hash`,
`items_digest` for 0, 1 and 3 items (including a tombstone), a manifest with its
`manifest_hash`, the Recovery Key and pairing-code text, and pairing MACs. `PwK` inputs include
ASCII, NFC versus NFD input showing that normalization is applied, a rejected lone surrogate,
emoji, and a password at the 4,096-byte maximum. Each vector is produced by `packages/crypto`
on libsodium **and** by a small noble-based reference, and the two must agree.

**They are not authoritative yet.** Until this byte format has been reviewed and frozen, they
are labelled provisional and regenerated whenever the format changes. Nobody may treat a
committed provisional vector as a compatibility promise. Fixed nonces are used only through the
test-only interface (INV-02).

**3. Parsing and tampering tests** on the envelope decoder:

- Typed errors only for decisions Ruvee's parser makes **before** decryption: length below the
  minimum or above the purpose's maximum, `magic`, `format_version`, `alg` (`unsupported_format`),
  the wrong `purpose`, and a `key_id` other than the expected one (`wrong_key`).
- Everything the AEAD covers yields one `integrity_failure`: a flipped bit in the nonce,
  ciphertext or tag, and a wrong context field such as another item id, revision or `seq`.
  Tests assert the class, not which field changed.
- Plaintext post-checks: bad padding, wrong key length, schema failure (`malformed_plaintext`).
- Other format checks: unknown profile id, Recovery Key or pairing code with a bad checksum.
- Property and fuzz tests: encode and decode round trips for random inputs; arbitrary bytes into
  the decoder must never produce anything except a typed error; `items_digest` does not depend on
  input order.

**4. Application authorization and replay tests.** These are HTTP and integration tests, not
vectors: a single-use `loginId`; one request per pairing; a MAC failure burning a pairing;
recovery-session scope; step-up; refresh-token reuse; a keyset or manifest rollback; and a
manifest whose `prev_manifest_hash` does not chain. They have exact status codes, because Ruvee
defines them ([INV-23](security-invariants.md)).

**Where the vectors run.**

| Runtime                                                  | Phase | How                                                                                              |
| -------------------------------------------------------- | ----- | ------------------------------------------------------------------------------------------------ |
| Node 24 (`libsodium-wrappers-sumo`)                      | 2     | The P2-01 harness's own runner in CI; Vitest for `packages/crypto` (P2-03)                       |
| Chromium, Firefox and WebKit, main thread and Web Worker | 2     | Playwright-driven test page in CI. Playwright WebKit is not Safari; Safari is checked by hand.   |
| MV3 service worker and offscreen document                | 5     | Test harness extension loaded by Playwright, with `'wasm-unsafe-eval'` declared                  |
| iOS and Android (`react-native-libsodium`)               | 6     | On-device test runner in CI (simulator/emulator), plus one physical reference device per release |

Category 1, the cross-implementation checks and the library behavior Ruvee relies on now run in
the first two rows as a CI job: the
[primitive validation harness](../../tools/crypto-validation/README.md) (P2-01), with synthetic
data only. It tests the libraries, not this format. The earlier spike in
`spikes/architecture-validation/` remains as disposable evidence, including its MV3 service
worker run.

**OPAQUE interoperability** is separate, because Ruvee does not implement OPAQUE. See
[authentication.md](authentication.md#interoperability-tests).

## 9. What this design deliberately does not do

- No custom primitives. Padding and Crockford base32 are encodings, not cryptography, and are
  tested against references.
- No use of OPAQUE's `export_key` for vault keys. Unlocking must work offline, and authentication
  and decryption stay independent ([ADR-0004](../adr/0004-opaque-authentication.md)).
- No server-side encryption or decryption of vault data, and no server-held key that can decrypt
  vaults.
- No compression before encryption, which would leak content through ciphertext length.
- Signatures are not used in V1. The single user's devices share symmetric keys. Signing keys per
  device are left for shared vaults, where other users' devices need to verify authorship.

## 10. Implementation status (`packages/crypto`, P2-03)

Implemented locally on 2026-10-24 as a **development milestone**. This byte format is still
Proposed and has not been reviewed (D-19). The package is not approved for real secrets, and
remote CI has not run. The owner approved D-01, D-04 and D-20 for this milestone only.

### Public API

| Export                                      | Purpose                                                                                                                                                           |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `initRuveeCrypto()`                         | Explicit, asynchronous initialization. Loads libsodium.js, refuses any build other than libsodium 1.0.22, and returns the operations below. Nothing loads before. |
| `generateKey()`                             | 32 bytes from the CSPRNG, for `SK`, `AK` or `VK`.                                                                                                                 |
| `generateKeyId()`, `generatePasswordSalt()` | 16 bytes from the CSPRNG, for `ak_id` or `vk_id`, and for `salt_pw`.                                                                                              |
| `deriveAccountUnlockKey()`                  | `PwK` and then `AUK` (§3.3) from the password, `salt_pw`, a profile id, `SK` and `account_id`. `PwK` never leaves the call.                                       |
| `wrapAccountKey()`, `unwrapAccountKey()`    | The 93-byte `AK_WRAP_PASSWORD` envelope (§4.3). A wrong password surfaces as `integrity_failure` (§7).                                                            |
| `sealKeyset()`, `openKeyset()`              | The `KEYSET` envelope with the §5.1 JSON. `K_keyset` is derived from `AK` inside the call.                                                                        |
| `normalizePassword()`                       | The §3.1 rule, returning the string OPAQUE will receive.                                                                                                          |
| `padPlaintext()`, `unpadPlaintext()`        | §5.2 padding, ready for Phase 3 item bodies.                                                                                                                      |
| `wipe()`, `RuveeCryptoError`, constants     | Best-effort zeroing; the typed error; `PASSWORD_MAX_BYTES`, `DEFAULT_KDF_PROFILE`, `KEYSET_FORMAT_VERSION`, envelope and padding sizes.                           |

No public function takes a nonce, a raw KDF parameter, a library instance or a purpose code.
Fixed nonces exist only in `src/testing/fixed-nonce.ts`, which is outside the package's exports
and its build; a lint rule forbids production modules from importing it (INV-02).

### Added on 2026-10-25 (recovery, items, manifests, local records)

Implemented locally for the web-vault milestone; same status as the rest of this section
(Proposed, unreviewed, development only). Remote CI has not run.

| Export                                                                | Purpose                                                                                                                                                                                                            |
| --------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `generateRecoveryKey()`, `formatRecoveryKey()`, `parseRecoveryKey()`  | `RK` and `recovery_key_id` from the CSPRNG; the §5.4 text form with its lenient decoding. A bad checksum or malformed text is `invalid_recovery_key` before anything else runs.                                    |
| `deriveRecoveryKeys()`, `recoveryVerifier()`                          | `RWK`, `RAK` (§3.3) and `SHA-256(RAK)`. SHA-256 is libsodium's `crypto_hash_sha256`, used only for this verifier.                                                                                                  |
| `wrapAccountKeyForRecovery()`, `unwrapAccountKeyForRecovery()`        | The 93-byte `AK_WRAP_RECOVERY` envelope.                                                                                                                                                                           |
| `sealItemRecord()`, `openItemRecord()`, `recordHash()`                | The §5.2 record (`ITEM_KEY` and `ITEM_BODY`), padded body, `record_hash`. A new revision passes the previous record, whose `ITEM_KEY` envelope is reused, so `IK` never leaves the package. Schema version 1 only. |
| `itemsDigest()`, `sealManifest()`, `openManifest()`, `manifestHash()` | §5.3. `openManifest` also checks that the plaintext's vault and `seq` are the ones the caller expected. Digest entries must have distinct item ids.                                                                |
| `sealLocalRecord()`, `openLocalRecord()`                              | `LOCAL_RECORD` under `K_local`. Record names are lowercase ASCII, 1 to 64 characters, and are part of the AAD.                                                                                                     |
| `generateUuid()`, `uuidToBytes()`, `uuidFromBytes()`                  | Random version 4 UUIDs and the 16-byte encoding of §2.                                                                                                                                                             |
| `parseItemRecord()`, `manifestStructureProblem()`                     | Key-free structural checks of §4.4 steps 1 to 3 for records and manifests, for the server (sync-protocol §4.2).                                                                                                    |

Guard changes: the MAC accepts 16-byte keys (only `RK`) as well as 32-byte keys; an unkeyed hash
`H` takes messages up to 8 MiB (`items_digest` for about 147,000 items); SHA-256 takes at most 64
bytes; the AEAD bound is 1 MiB (`LOCAL_RECORD`); the KDF allowlist is `rvkeyst1`, `rvlocal1` and
`rvmanif1`. `crypto_kdf_derive_from_key` still receives only subkey length 32 and id 1, so the V-15
containment is unchanged.

Verification: the provisional vectors now also cover `RWK`, `RAK`, the verifier, the Recovery Key
text, `AK_WRAP_RECOVERY`, an item record and its hash, `items_digest` for 0, 1 and 3 items (with a
tombstone), `K_manifest`, a manifest envelope and its hash, `K_local` and a local record. Each is
computed by the package and by the independent noble reference (with its own Crockford encoder and
padding), and they agree. Portable checks cover round trips and binding: a record presented at
another revision, item or vault, a manifest at another `seq`, a local record under another name or
device, and every single-symbol typo in a Recovery Key. They pass in Node and in Playwright
Chromium, Firefox and WebKit, page and worker.

### Not implemented

| Part of this design                                         | Why                                                                                                                                                                                                                      |
| ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Pairing code text, pairing MACs, `crypto_box_seal` transfer | D-21 is open, and D-04's approval explicitly excludes the pairing protocol. P2-12.                                                                                                                                       |
| `DEVICE_LABEL`, `K_devlabel`                                | §4.3 fixes only "UTF-8, at most 128 bytes". Whether a label is normalized and whether an empty label is allowed must be decided first. Device labels are optional on the server, so the web vault sends none until then. |
| Item schema versions other than 1                           | The item JSON schema lives in the web app (`apps/web/src/vault/item-schema.ts`); the package only carries the version in the AAD.                                                                                        |

### Password input (D-20)

In order: anything but a string is refused; a string longer than **65,536 UTF-16 code units** is
refused before normalization; a string with an unpaired surrogate is refused; NFC is applied and
nothing else (no trimming, case folding or truncation); the result must be **1 to 4,096 UTF-8
bytes, counted after NFC**. The code-unit bound only limits the work given to `normalize()`. It
cannot refuse a password that would pass the byte limit: a canonical decomposition has at most 4
code points (a test checks every code point in the engine's Unicode data), so a valid input has at
most 32,768 code units. NFC under different engines' Unicode versions was not compared.

### Library boundary

Every libsodium call goes through one guard, which checks types and exact sizes before the call
and the output length after it. The table lists what is accepted and which library behavior that
contains. **The guard contains these defects for Ruvee's callers. It does not fix libsodium.js**,
and the pinned release still has them.

| Function                               | Accepted by the guard                                                               | Library behavior contained                                                                              |
| -------------------------------------- | ----------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| `crypto_kdf_derive_from_key`           | Subkey length exactly 32, subkey id exactly 1, context `rvkeyst1`, 32-byte key      | V-15 (stale memory outside 16..64); numeric ids from 2³¹ throw; an 8-byte non-ASCII context is accepted |
| `crypto_generichash`                   | Output 32 bytes, key 32 bytes, message at most 1,024 bytes                          | V-12: 1- to 15-byte keys and outputs are accepted                                                       |
| `crypto_pwhash` (Argon2id)             | Password 1 to 4,096 bytes, 16-byte salt, parameters only from the registry objects  | `memlimit` silently rounded down to whole KiB, no memory ceiling, negative `MEMLIMIT_MAX`               |
| XChaCha20-Poly1305 encrypt and decrypt | 32-byte key, 24-byte nonce, plaintext at most 16,384 bytes, AAD at most 1,024 bytes | Decryption failures of every kind become one `integrity_failure`                                        |
| `randombytes_buf`                      | 16, 24 or 32 bytes                                                                  |                                                                                                         |
| All                                    | `Uint8Array` only                                                                   | Strings are silently UTF-8 encoded by the library (a 32-character string is accepted as a key)          |

Library exceptions are replaced by `library_failure` without their message. Profile 1 stays
**provisional**: phone compatibility and final approval of the parameters are open (D-03, D-26).

### Errors

`RuveeCryptoError.code` is one of `invalid_argument`, `invalid_password`, `unsupported_profile`,
`malformed_envelope`, `unsupported_format`, `wrong_purpose`, `wrong_key`, `integrity_failure`,
`malformed_plaintext` and `library_failure`. §4.4 does not name the errors for its steps 1 and 3;
the package calls them `malformed_envelope` and `wrong_purpose`. Messages are fixed per code, and
the only extra detail is a field name or a reason from a closed set. No error carries a library
message, a `cause`, or any key, password or plaintext, and the package never logs.

### Buffer ownership and memory

Inputs are borrowed: they are read and never modified or wiped. Every returned `Uint8Array` is a
new buffer owned by the caller, who should `wipe()` key material when done. The package wipes its
intermediates (password bytes, `PwK`, the `AUK` input, `K_keyset`, keyset plaintext bytes) on
success and on failure.

This is **best effort**. JavaScript strings cannot be erased, so the password, its normalized
form and the keyset JSON text (which holds `SK` and `VK` as base64url) stay in memory until the
garbage collector reclaims them. The engine may also copy buffers when it moves them, and
libsodium.js copies every argument into WebAssembly memory, where this package cannot erase it.

### Interpretations to confirm in the format review

- Keyset decoding is strict: exactly the §5.1 fields, `v` = 1, one vault, canonical unpadded
  base64url with the exact byte lengths, and lowercase canonical UUID text. Encoding is compact
  JSON in the §5.1 key order. Decoders do not depend on whitespace or key order; the fixed form
  only makes vectors reproducible.
- `ak_epoch` and `keyset_version` accept the full u32 range, including 0. Rejecting a keyset older
  than the last one seen is the caller's job.
- The error names for §4.4 steps 1 and 3, above.

### Verification

| Kind                         | What runs through the package                                                                                                                                                                                                                                                                                                  |
| ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Published vectors            | XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 §A.3.1 and all 315 Wycheproof tests (9 with off-size nonces are refused by the guard), read from the hash-checked files in `tools/crypto-validation/vectors`.                                                                                                                   |
| Cross-implementation (noble) | Keyed BLAKE2b-256 with 32-byte keys, `crypto_kdf` for `rvkeyst1`, Argon2id at profile 1, XChaCha20-Poly1305 in both directions; padding against `sodium_pad`.                                                                                                                                                                  |
| Provisional protocol vectors | `packages/crypto/test/vectors/provisional-protocol-vectors.json`: `PwK` and `AUK` for ASCII, preserved whitespace, NFC, NFD, emoji and non-Latin, 4,096 bytes and a rejected lone surrogate; `K_keyset`; both envelopes. The package, an independent noble reference and the file must agree. **Not a compatibility promise.** |
| Negative and boundary        | Every header field, tampered bytes and context fields, wrong keys, wrong purposes, lengths, keyset schema failures, decoder fuzzing, the profile floor, V-15 reproduction and containment, nonce uniqueness.                                                                                                                   |

The other published vectors (Argon2id `test.c` with 8-byte salts, RFC 9106 with p = 4, BLAKE2b-512
and 64-byte keys) use sizes the guard refuses by design. They still run in the P2-01 harness, and
a test checks that the package locks the same libsodium.js and noble tarballs as the harness.

Runtimes: Node 24.13.0 (Vitest), and Playwright 1.64.1 Chromium, Firefox and WebKit, each on the
page and in a dedicated worker under a CSP that adds only `'wasm-unsafe-eval'`. Playwright WebKit
is not Safari; Safari, phones and the MV3 service worker were not tested. The nonce-uniqueness
test (1,000 envelopes, 1,000 distinct nonces) detects a fixed or repeating nonce. It says nothing
about the quality of the randomness, which comes from libsodium.js's `randombytes_buf`.

## Changes after architecture validation

Status remains **Proposed**. Changes made on 2026-10-22 from
[architecture-validation.md](architecture-validation.md). No key, derivation, envelope or byte
format changed.

- §2: Ruvee checks every length itself, because libsodium.js accepts a too-short BLAKE2b key
  (V-12).
- §3.1: well-formed-string check before NFC (V-05).
- §3.2: profile 1 is marked provisional, with the single-machine measurements and their limits.
- §3.3: the `RK` length is checked by Ruvee.
- §4.4: `integrity_failure` is a single class; the AEAD cannot report which field changed.
- §6.2: `SK` rotation triggers (V-08).
- §8: rewritten (V-10). The independent implementation is `@noble/*` instead of Python and Go.
  Tests are split into four kinds. Ruvee protocol vectors stay provisional until the format is
  reviewed.

## Changes after the primitive validation harness (P2-01)

Status remains **Proposed**. Changes made on 2026-10-22 from the
[harness](../../tools/crypto-validation/README.md). No key, derivation, envelope or byte format
changed.

- §8: the Argon2 reference `test.c` vectors are added, run through libsodium with
  `crypto_pwhash_str_verify`. The Node and browser rows point to the harness instead of the spike.
- Finding V-15 ([validation §1](architecture-validation.md#1-findings)): libsodium.js 0.8.4
  returns stale memory from `crypto_kdf_derive_from_key` for subkey lengths outside 16..64. This
  design already uses only 32-byte subkeys; §2's rule that Ruvee checks every length itself now
  also covers that argument.

## Changes after the Argon2id calibration (P2-02, local part)

Status remains **Proposed**. Changes made on 2026-10-23 from
[kdf-calibration.md](kdf-calibration.md). No parameter, key or format changed; profile 1 stays
provisional.

- §3.2: the local benchmark results are linked, and the peak-memory budget is marked as needing a
  definition.

## Changes after P2-03 (`packages/crypto`)

Status remains **Proposed**; the byte format has not been reviewed. Changes made on 2026-10-24.
No key, derivation, envelope or byte format changed.

- The owner approved D-01 (the pinned libsodium.js), D-04 (`AUK` from the password **and** `SK`)
  and D-20 (the §3.1 password rule) for this development milestone.
- §10 added: what `packages/crypto` implements, the limits it applies and how they are counted,
  the library boundary, buffer ownership and memory limits, error names for §4.4 steps 1 and 3,
  interpretations to confirm in the format review, and the parts left to later milestones.

## Changes after P2-04 (web headers, crypto-only)

Status remains **Proposed**. Changes made on 2026-10-24. No key, derivation, envelope or byte
format changed.

- `KEYSET_FORMAT_VERSION` is a public export so a consumer can see the plaintext schema version
  (`v` = 1). The one-vault restriction and canonical base64url rules were confirmed against
  §5.1; they already match V1. Rollback still uses `keyset_version` in the AAD, which remains
  the caller's job.

## Changes after the web-vault crypto additions (2026-10-25)

Status remains **Proposed**; no existing key, derivation or byte format changed, and the existing
provisional vectors are unchanged. Recovery, item, manifest and local-record formats were
implemented as specified in §3.3, §4.3 and §5.2 to §5.4 (see §10).
