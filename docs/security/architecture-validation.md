# Architecture validation and compatibility spike

Status: **Proposed.** This is a **self-review** by the agent that wrote the Phase 0 design. It is
**not an independent security audit**, it approves nothing, and it does not make Ruvee secure or
production-ready. Decisions D-01 to D-09, the database schema and all implementation remain
unapproved.

Date: 2026-10-22. Baseline: commit `0a6cd24` (Phase 0 architecture). The disposable experiments
are in [`spikes/architecture-validation/`](../../spikes/architecture-validation/README.md). They
use synthetic inputs only and are not part of any workspace package.

## Contents

1. [Findings](#1-findings)
2. [What was verified, and what was not](#2-what-was-verified-and-what-was-not)
3. [Two-secret design and authentication](#3-two-secret-design-and-authentication)
4. [Pairing as a complete protocol](#4-pairing-as-a-complete-protocol)
5. [Recovery as a complete protocol](#5-recovery-as-a-complete-protocol)
6. [Library validation](#6-library-validation)
7. [Key-derivation measurements](#7-key-derivation-measurements)
8. [Test-vector plan, reassessed](#8-test-vector-plan-reassessed)
9. [Document changes made](#9-document-changes-made)
10. [Follow-up: primitive validation harness (P2-01)](#10-follow-up-primitive-validation-harness-p2-01)

## 1. Findings

Severity is about the **design as documented**, because nothing is implemented:

- **High:** a documented security claim is wrong or a protocol cannot work as written.
- **Medium:** a gap that would produce a vulnerability or a misleading claim if implemented as
  written.
- **Low:** an implementation trap or a documentation inaccuracy with limited impact.

| ID   | Severity | Finding                                                                                                                                                                                                                                                                                                                                                                                      | Evidence                                                                                                                                                                                                                                                                               | Recommended resolution                                                                                                                                                                                                                | Must be resolved before                |
| ---- | -------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------- |
| V-01 | High     | **"A stolen database allows no password guessing" is overbroad.** It holds only if the OPAQUE server setup was not captured too, and `SK` has never left an enrolled device. Host snapshots and whole-disk backups normally contain the setup file. With it, the OPAQUE record allows offline guessing that does not involve `SK` or the vault wrap.                                         | RFC 9807 §10.11; section 3.3 below                                                                                                                                                                                                                                                     | Narrow the claim everywhere to the conditions in [section 3.4](#34-the-narrowed-claim). Treat any copy that includes the setup file as server compromise (A3). Rotate `SK` when a device is reported lost (V-08).                     | Wording now; deployment guide by P2-07 |
| V-02 | High     | **Circular dependency in new-device login.** The OPAQUE server identifier is `instance_id`, and the client must supply it to `finishLogin`. A new device learns `instance_id` only from the pairing payload, which needs a login first. `POST /auth/login/start` does not return it.                                                                                                         | [api-design.md](../architecture/api-design.md#authentication); spike OP-04 (a different server identifier makes login fail)                                                                                                                                                            | Leave the OPAQUE server identity unset, so it defaults to the server public key (RFC 9807 §10.3). `instance_id` then has no protocol role.                                                                                            | P2-08                                  |
| V-03 | Medium   | **Client-side server-key pinning is redundant and creates failure modes.** The envelope already authenticates the server public key, so a substituted server setup fails at the client. A pin adds nothing against impersonation, but it turns a lost setup file into "security warning" lockouts and requires trust on first use.                                                           | RFC 9807 §4 (`CreateCleartextCredentials`); spike OP-05                                                                                                                                                                                                                                | Remove pinning from the design, the pairing payload and the recovery material.                                                                                                                                                        | P2-09                                  |
| V-04 | Medium   | **`@serenity-kit/opaque` accepts a replayed server login state.** `server.finishLogin` is stateless: the same state and finalization succeed twice.                                                                                                                                                                                                                                          | Spike OP-07 ("replay of state and finalization: ACCEPTED")                                                                                                                                                                                                                             | The application consumes `loginId` atomically (delete-and-return) before calling `finishLogin`, binds it to the username and device, and expires it after 60 s. Add a replay test. Same rule for `reauth`.                            | P2-09                                  |
| V-05 | Medium   | **Password normalization does not handle lone surrogates.** Both libraries UTF-8 encode JS strings, mapping a lone surrogate to U+FFFD, so distinct strings collide. NFC leaves lone surrogates in place.                                                                                                                                                                                    | Spike LS-09c, OP-08                                                                                                                                                                                                                                                                    | Reject strings that are not well-formed UTF-16 before NFC. Pass the same validated string to OPAQUE and to Argon2id.                                                                                                                  | P2-03                                  |
| V-06 | Medium   | **A stolen locked device can include a live session.** The threat model treats device theft as offline guessing only. The browser profile also holds the web session cookie (up to 14 days) or the extension refresh token (up to 90 days), which give everything in the stolen-session row without the password.                                                                            | [authentication.md §5](authentication.md#5-sessions)                                                                                                                                                                                                                                   | Correct T-22 and the attacker tables. Whether locking also ends the server session is an owner preference (D-23 in [open-decisions.md](../architecture/open-decisions.md)).                                                           | Wording now; D-23 by P2-10             |
| V-07 | Medium   | **Recovery gives more power, more quietly, than documented.** Anyone with the Recovery Key can call `/recovery/start` and `/recovery/material` and unwrap `AK` without completing recovery, and other devices are notified only on completion. Anyone who learns `RAK` (TLS interception, a logging mistake) can complete recovery with junk wraps, which deletes the working recovery wrap. | [account-recovery.md §3](account-recovery.md#3-recovery-with-the-recovery-key)                                                                                                                                                                                                         | Raise the recovery notice on every device at `recovery_started`, not only on completion. Document both cases. Decide between keeping `RAK` with these mitigations and a second OPAQUE registration keyed by `RK` (decision D-22).     | P2-13                                  |
| V-08 | Medium   | **Exposure of `SK` is permanent and has no rotation trigger.** After a lost device or an XSS read, a later database theft allows offline guessing of the **current** password. Neither recovery nor "lost" revocation rotates `SK`.                                                                                                                                                          | Section 3.3; [device-enrollment.md §6](device-enrollment.md#6-revocation-and-its-limits)                                                                                                                                                                                               | Rotate `SK` (an existing narrow rotation) when a device is revoked as lost, and offer it at the end of recovery after device loss.                                                                                                    | P2-11, P2-13                           |
| V-09 | Medium   | **Pairing is a custom composition and was under-specified.** Its security rests entirely on the 128-bit secret. Missing rules included: one request per pairing, a MAC failure burns the pairing, binding the request to the requesting session's device, and a ban on shortening the code.                                                                                                  | Section 4                                                                                                                                                                                                                                                                              | Adopt the complete specification in section 4. Treat the protocol as **conditionally supported at 128 bits**, subject to independent review before real data. **Any shorter code is blocked** without a reviewed PAKE implementation. | P2-12                                  |
| V-10 | Medium   | **The test-vector plan could not work as written.** The RFC 9106 KAT can't run through libsodium. `crypto_kdf`, sealed boxes and keyed BLAKE2b-256 have no published KATs. The cited "libsodium test outputs" come from the implementation under test. AEAD failures can't produce field-specific errors.                                                                                    | Section 8; spike LS-04, LS-09a/b                                                                                                                                                                                                                                                       | Use the plan in section 8: one independent implementation (`@noble/*`), four separated test categories, and no authoritative Ruvee vectors until the byte format is reviewed. P2-01 becomes a primitive validation harness.           | P2-01                                  |
| V-11 | Medium   | **MV3 constraints.** The default extension CSP blocks WebAssembly, so the manifest must declare `'wasm-unsafe-eval'`. In the extension service worker, Argon2id was about 3.7× slower than in a page worker on the same Chromium build (cause not determined).                                                                                                                               | Section 7; `results/browser.json`                                                                                                                                                                                                                                                      | Declare `content_security_policy.extension_pages` explicitly. Phase 5 measures an offscreen document or extension page worker before choosing where derivation runs.                                                                  | Phase 5                                |
| V-12 | Low      | **libsodium.js does not enforce some documented minimums.** A 15-byte BLAKE2b key is accepted (minimum is 16). `crypto_pwhash_MEMLIMIT_MAX` reads as −2³¹. Numeric `crypto_kdf` subkey ids ≥ 2³¹ throw; `bigint` works.                                                                                                                                                                      | Spike LS-01, LS-07, LS-08                                                                                                                                                                                                                                                              | `packages/crypto` checks every key and input length itself and does not read limits from library constants.                                                                                                                           | P2-03                                  |
| V-13 | Low      | **Research inaccuracies.** The OPAQUE WASM contains `opaque-ke` 4.0.1, not 4.0.0. The `@noble/hashes` audit excluded Argon2. `libsodium-wrappers-sumo` depends on `libsodium-sumo` through a caret range. libsodium.js 0.8.4 did not fall back to JavaScript when CSP blocked WebAssembly.                                                                                                   | Section 6                                                                                                                                                                                                                                                                              | Corrected in [research-sources.md](research-sources.md).                                                                                                                                                                              | Done                                   |
| V-14 | Low      | **OPAQUE configuration facts were not recorded.** In `@serenity-kit/opaque`, the KSF runs Argon2id with a zero salt (the OPRF key is the secret salt), the AKE context can't be set, the KSF must match exactly between registration and login, and no published vectors cover this KSF.                                                                                                     | Source of 1.1.0; spike OP-02; upstream `rfc9807_vectors.rs` uses the identity KSF                                                                                                                                                                                                      | Recorded in [authentication.md §2.2](authentication.md#22-configuration). Regression fixtures become the only stored-account compatibility check.                                                                                     | P2-09                                  |
| V-15 | Medium   | **`crypto_kdf_derive_from_key` returns stale memory for invalid subkey lengths.** Found by the P2-01 harness. In libsodium.js 0.8.4, a subkey length outside 16..64 is not rejected: the wrapper ignores the C error and returns uninitialized WebAssembly heap, which held a previous subkey derived with a different key, and in one probe plaintext from an earlier AEAD call.            | [Harness](../../tools/crypto-validation/README.md#finding-v-15-crypto_kdf_derive_from_key-returns-stale-memory) check `LB-KDF-SUBKEY-LENGTH-STALE-MEMORY`; upstream [libsodium.js#370](https://github.com/jedisct1/libsodium.js/issues/370), fixed on master (`86ea6ed`), not released | `packages/crypto` passes only the constant 32 and checks it before the call (proposed length rule). Track the next libsodium.js release; the harness tripwire fails when the fix ships.                                               | P2-03                                  |

Nothing was found that requires abandoning the two-secret design, OPAQUE, libsodium or
pairing with a 128-bit secret. Every High finding is a claim or a missing dependency, which can
be corrected without changing primitives.

## 2. What was verified, and what was not

### 2.1 Verified by running code

All 22 checks passed in each runtime listed below, with synthetic inputs, on one machine (Apple M5,
10 cores, 16 GiB, macOS darwin 25.5.0 arm64). Commands, pinned versions and KAT hashes are in the
[spike README](../../spikes/architecture-validation/README.md). Raw results are in
`spikes/architecture-validation/results/`.

| Runtime                                                    | Main thread | Dedicated worker | Notes                                                |
| ---------------------------------------------------------- | ----------- | ---------------- | ---------------------------------------------------- |
| Node 24.13.0 (V8 13.6)                                     | 22/22       | n/a              |                                                      |
| Playwright Chromium 156.0.8078.4, headless                 | 22/22       | 22/22            |                                                      |
| Google Chrome 155.0.8059.85 (installed), headless          | 22/22       | 22/22            |                                                      |
| Playwright Firefox 157.0 (patched build), headless         | 22/22       | 22/22            | Not a stock Firefox release                          |
| Playwright WebKit 27.2, headless                           | 22/22       | 22/22            | **Not Safari**                                       |
| Playwright Chromium 156, MV3 service worker, WASM CSP      | n/a         | 22/22            | Extension declares `'wasm-unsafe-eval'`              |
| Playwright Chromium 156, MV3 service worker, default CSP   | n/a         | fails            | WebAssembly blocked; libsodium aborts                |
| Every browser above, page CSP without `'wasm-unsafe-eval'` | fails       | fails            | Both libraries abort; no JavaScript fallback is used |

In the full runs, libsodium fails first, which stops the remaining checks. OPAQUE was then loaded on
its own in Chromium under both policies: it works with `'wasm-unsafe-eval'` and throws a WebAssembly
`CompileError` without it. The OPAQUE-only probe was not repeated in Firefox or WebKit.

With `script-src 'self' 'wasm-unsafe-eval'` nothing else was needed. No `'unsafe-eval'`, inline
script or remote origin was required by either library.

### 2.2 Verified by reading source or specifications

- `@serenity-kit/opaque` 1.1.0 source at tag `@serenity-kit/opaque@1.1.0` (commit `f6353ae`): the
  cipher suite, the KSF, its presets and defaults, identifier handling, and error behavior.
- The compiled WASM inside the published package embeds the crate versions `opaque-ke-4.0.1`,
  `voprf-0.5.0`, `argon2-0.5.3` and `curve25519-dalek-4.1.3`.
- `opaque-ke` 4.0.x CHANGELOG and README, and its RFC 9807 vector test (identity KSF only).
- RFC 9807 §4, §6, §10.3, §10.8 to §10.12.
- npm metadata for every pinned package, and the noble audit scopes in their READMEs.

### 2.3 Not verified

| Not verified                                                         | Why                                                                                                                            |
| -------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Safari (macOS or iOS)                                                | Automation needs `safaridriver --enable`, which needs the owner's approval. Playwright WebKit is not Safari.                   |
| A stock Firefox release                                              | Playwright drives only its patched build. Firefox Developer Edition is installed but was not automated.                        |
| Any phone, tablet or older laptop                                    | Not available. **No timing here applies to them.**                                                                             |
| `react-native-libsodium`, Hermes WebAssembly, OPAQUE on React Native | No React Native toolchain, simulator or device was used. Mobile support is **untested**, not supported.                        |
| MV3 offscreen document and extension-page worker                     | Not built. Only the service worker was tested.                                                                                 |
| Peak memory in browsers, p95 timings                                 | Not measured. Five runs per configuration are too few for a p95. Node's RSS after all runs was 382 MiB.                        |
| Constant-time behavior and side channels                             | Not measurable with this setup.                                                                                                |
| Timing indistinguishability of fake OPAQUE responses                 | Only the size was compared (identical). Timing needs the HTTP server, which doesn't exist yet.                                 |
| Any Ruvee protocol                                                   | Nothing of Ruvee's own format was implemented, by design. The spike tests libraries.                                           |
| SHA-256 and HPKE/PAKE libraries                                      | SHA-256 would come from Node's built-in `crypto` and was not tested. HPKE and PAKE packages were looked up on npm but not run. |

## 3. Two-secret design and authentication

### 3.1 Derivation and data flow

Notation is from [cryptographic-design.md §2](cryptographic-design.md#2-notation-and-encodings).
`P` is the validated, normalized password (section 3.5).

**Master password `P`.** It is used in two derivations that share nothing except `P`:

```
Vault side (libsodium, client only):
  PwK = crypto_pwhash(32, P, salt_pw, t = 3, m = 64 MiB, ALG_ARGON2ID13)     // p = 1, salt_pw 16 B
  AUK = MAC(SK, "ruvee/v1/auk" ‖ account_id ‖ u8(profile) ‖ salt_pw ‖ PwK)
  env_pw = Seal_AUK(AK)                         // AK_WRAP_PASSWORD, stored on the server and on the device

Authentication side (@serenity-kit/opaque, RFC 9807, ristretto255 / SHA-512):
  oprf_key   = DeriveKeyPair(oprf_seed, credential_identifier = username)   // server only
  oprf_out   = OPRF(oprf_key, P)                                            // blinded; server never sees P
  stretched  = Argon2id(oprf_out, salt = 16 zero bytes, t = 3, m = 64 MiB, p = 4)
  rwd        = HKDF-Extract("", oprf_out ‖ stretched)                       // randomized_password
  masking_key, auth_key, export_key, client AKE key pair = HKDF-Expand(rwd, …)
  envelope   = nonce ‖ MAC(auth_key, nonce ‖ server_public_key ‖ identities)
  record     = client_public_key ‖ masking_key ‖ envelope                   // 192 B, stored on the server
```

`export_key` is discarded. Nothing on the vault side uses an OPAQUE output, and nothing on the
authentication side uses `SK` or any vault key.

**Device-held Secret Key `SK`.** 32 random bytes generated by the first device. It flows:

- first device → its local store (IndexedDB on web)
- first device → `KEYSET` envelope under `K_keyset = KDF(AK, "rvkeyst1")` → server
- enrolled device → new device, inside the pairing payload (section 4)
- server keyset → a recovering device, after `RWK` unwraps `AK` (section 5)

It is never sent to the server outside the keyset envelope.

**OPAQUE client input and the server registration record.** The client's only inputs are `P`, the
username (client identity and credential identifier) and the fixed KSF preset. The server stores
the 192-byte record per account, and one **server setup** for the installation: the OPRF seed
and the server AKE key pair (128 bytes serialized). That file is outside PostgreSQL. Ruvee does
not use the OPAQUE session key. A successful server `finishLogin` is what allows the server to
issue its own random session token.

**Vault wrapping keys.**

```
AUK (password + SK) ──wraps──► AK ◄──wraps── RWK = MAC(RK, "ruvee/v1/recovery-wrap")
AK ──KDF──► K_keyset (keyset {SK, VK}), K_local, K_devlabel
VK ──wraps──► IK;  VK ──KDF──► K_manifest
```

**Recovery material.** `RK` is 16 random bytes, printed as text and QR code. `RWK` wraps `AK`
(`AK_WRAP_RECOVERY`, on the server). `RAK = MAC(RK, "ruvee/v1/recovery-auth")` is sent to the
server at recovery start, and the server stores `SHA-256(RAK)`.

### 3.2 What each attacker has

| Compromise                                                                          | What the attacker obtains                                                                                                                                                                                                                                                     | Offline password guessing?                                                                                                                                                                                | Decryption?                                                                                                                |
| ----------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| **Database theft** (dump or database-only backup)                                   | All ciphertext; `AK_WRAP_PASSWORD`; `AK_WRAP_RECOVERY`; the keyset envelope; `salt_pw` and profile; the OPAQUE record; `SHA-256(RAK)`; token hashes; the username; the device list and every metadata item in [threat-model.md §4](threat-model.md#4-what-the-server-can-see) | **No**, under the conditions in section 3.4. The vault wrap needs `SK`. The OPAQUE record needs the OPRF key. `RK` and `RAK` are 128 and 256 bits.                                                        | No                                                                                                                         |
| **Database plus server configuration and OPAQUE server setup** (or a host snapshot) | The above, plus the OPRF seed and the server AKE private key                                                                                                                                                                                                                  | **Yes, against the OPAQUE record, independently of `SK`.** One OPRF evaluation plus Argon2id (64 MiB, t = 3, p = 4) per guess. The attacker can also impersonate the server to clients (RFC 9807 §10.12). | No. A cracked password gives account access, and the password itself (reuse risk), but the vault wrap still needs `SK`.    |
| **Locked device, persistent browser storage** (web profile copied)                  | `SK`; the local `AK_WRAP_PASSWORD`, `salt_pw` and profile; encrypted local records; the checkpoint; **and possibly a valid session**: the web cookie (12 h idle, 14 days absolute) or the extension refresh token (30 days idle, 90 days absolute)                            | **Yes, against the local wrap.** One Argon2id (64 MiB, t = 3, p = 1) per guess. Success yields `AK`.                                                                                                      | Only after a successful guess. Then everything cached locally, and everything on the server if the session is still valid. |
| **Valid session** (cookie or refresh token of an active device)                     | Download of all ciphertext, both server wraps except the recovery wrap, the keyset, salt, profile and metadata. Can submit commits (clients detect bad ones), delete server-side data within the commit API, and keep the session alive until expiry                          | No. The password wrap needs `SK`. The session cannot fetch the OPAQUE record.                                                                                                                             | No. Step-up operations (password change, revocation, rotation, reset, export) are refused.                                 |
| **Web delivery server compromise** (serves modified JavaScript)                     | On the next page load: `P` as typed, `SK` from IndexedDB, decrypted items, plus everything in the second row                                                                                                                                                                  | Unnecessary: it reads `P` directly                                                                                                                                                                        | **Yes, for every user of the web app** who unlocks afterwards. Out of scope for the web app ([R-01](risk-register.md)).    |

The two guessing paths cost about the same per guess. Argon2id with p = 4 and p = 1 at the same
memory and passes does the same total work, and an attacker parallelizes across guesses anyway.
A password's resistance is therefore one Argon2id (64 MiB, t = 3) per guess on **whichever path
the attacker can reach**. The two paths do not add up.

### 3.3 Does the OPAQUE record permit guessing independently of the vault wrap?

**Yes, with the OPRF key.** The record is `client_public_key ‖ masking_key ‖ envelope`. Given
the OPRF seed, an attacker computes `oprf_key` for the username, then for each guess derives
`rwd`, the client key pair and the envelope MAC, and compares them with the record. `SK`, the
vault salt and the vault wrap are not involved. RFC 9807 §10.11 says so directly: a corrupted
server can always run this attack, and so can anyone who obtains the seed.

**No, without the OPRF key.** The OPRF output acts as a secret per-user salt (RFC 9807 §10.11),
and the record alone gives no way to test a guess. This is why the zero KSF salt in
`@serenity-kit/opaque` is acceptable.

The consequence is that the vault's offline-guessing resistance comes from `SK`, and the
password's own secrecy comes from keeping the server setup out of reach. These are two different
properties, and the documents had merged them.

### 3.4 The narrowed claim

Replace "a stolen database allows no password guessing" with:

> A copy of the database alone (a dump, a replica or a database-only backup) allows no offline
> guessing of the master password, provided that:
>
> 1. the copy does not include the OPAQUE server setup. Host snapshots, whole-disk or volume
>    backups and container images that contain the secret file count as server compromise; and
> 2. the attacker does not also hold `SK`. `SK` leaves an enrolled device if the device or its
>    storage is stolen, or if script runs in its origin (XSS). Once `SK` has leaked, a database
>    copy made at any later time allows guessing until `SK` is rotated.
>
> A live compromise of the server process is not a "database theft": it obtains the setup and
> can run offline guessing against the OPAQUE record at any time.

### 3.5 Password input

Verified behavior (LS-09c, OP-08): `crypto_pwhash` and `@serenity-kit/opaque` both accept JS
strings and UTF-8 encode them with no normalization. NFC and NFD forms of the same password
derive different keys and do not log in. A lone surrogate is encoded as U+FFFD, so
`"pass\uD800"` and `"pass\uFFFD"` derive the same keys.

Rule: reject the input unless `String.prototype.isWellFormed()` is true, then apply NFC, then
check 1 to 4,096 UTF-8 bytes. Pass that **same string** to OPAQUE, and its UTF-8 bytes to
`crypto_pwhash`.

### 3.6 How a new device gets everything it needs, without a cycle

| Step                    | What the device needs                                | Where it comes from                                                                                     |
| ----------------------- | ---------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Log in (pending device) | Server URL, username, `P`, the OPAQUE KSF preset     | The user, and the client build. **Nothing from the server is needed in advance** once V-02 is resolved. |
| Become active           | Approval from an enrolled device, or proof of `RK`   | Pairing (section 4) or recovery (section 5)                                                             |
| Unlock                  | `SK`, `salt_pw`, profile, `AK_WRAP_PASSWORD`, keyset | `SK` from the pairing payload or keyset; the rest from `GET /account/keys` once active                  |
| Detect rollback         | A checkpoint                                         | The pairing payload. A recovering device has none (T-08).                                               |

Login depends on nothing from enrollment. Pairing depends on a pending session from login.
Recovery depends only on `RK`, because it authenticates with `RAK` and then re-registers OPAQUE.
In the Phase 0 text, login depended on `instance_id`, which only enrollment delivered (V-02).
Dropping the server identity removes that cycle. The alternative is to return `instance_id` from
`login/start`. That is also safe, because a wrong value only makes login fail, but it keeps a
value with no security purpose.

## 4. Pairing as a complete protocol

### 4.1 Status

Pairing is a **Ruvee-specific composition** of standard primitives: keyed BLAKE2b as a MAC, and
`crypto_box_seal` (X25519, XSalsa20-Poly1305) to an ephemeral key. Its security argument depends
on the shared secret `S` having 128 bits from the CSPRNG. With such a key, the MACs can't be
forged and `pairing_id` reveals nothing. This self-review found no flaw at that size. It is
**not** an established protocol, has no proof and has not been reviewed independently.

- **At 128 bits:** conditionally supported, provided the rules below are adopted and the
  protocol is reviewed independently before real data
  ([roadmap §Independent review](../planning/implementation-roadmap.md#independent-review), item 4).
- **Any shorter code is blocked.** With a 6-digit code, the server would recover `S` offline
  from `pairing_id` in microseconds, forge `req_mac` over its own key, and receive `SK`. A short
  code needs a PAKE. CPace (draft) or SPAKE2 (RFC 9382) would be the established choices, but
  no maintained, audited JavaScript and React Native implementation was found. The npm packages
  named `cpace` and `spake2` are unrelated or unmaintained (2019). The short-code option stays
  blocked until such an implementation exists and is reviewed.
- **HPKE (RFC 9180) in PSK mode** could replace the reply leg with a standardized construction
  that binds the reply to both `epk_B` and `S`. Its JavaScript implementation, `hpke-js` 1.9.0
  (`@hpke/core`), passes the RFC 9180 vectors but states it is **not formally audited**, and it
  would add a dependency. It does not cover the request leg. Recorded as an alternative for the
  reviewer, not adopted.

### 4.2 Parameters

| Property         | Value                                                                                                                                                                                                                                                                  |
| ---------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Secret           | `S` = 16 bytes from `randombytes_buf` on device A. 128 bits of entropy. A new `S` for every attempt.                                                                                                                                                                   |
| Encoding         | `"PC1-"` ‖ Crockford base32 of `S ‖ H("ruvee/v1/pc-check" ‖ S)[0..2]`: 29 characters in groups of 5. The QR code contains the same text. The 16-bit checksum catches typos and adds no security.                                                                       |
| Delivery channel | A's screen to B, by the user typing it or B's camera scanning it. Never through the server, a URL, a notification or a share action. A offers no copy button.                                                                                                          |
| Lifetime         | 10 minutes. The server expires the pairing row, and A discards `S` at the same deadline regardless of the server.                                                                                                                                                      |
| Attempts         | **One request per pairing.** The server rejects a second request with `409`. A `req_mac` failure at A burns the pairing: A cancels it and needs a new code. At most 3 open pairings and 10 created per hour per account. An unknown `pairing_id` gets a generic `404`. |
| Who may request  | Only a session of the same account whose device is `pending`. The server records that session's `device_id` as `device_id_B`. B cannot choose it.                                                                                                                      |

Online guessing of `pairing_id` (128 bits) is not a meaningful threat. The limits exist to bound
abuse and make mistakes visible.

### 4.3 Messages and what authenticates them

| #   | Direction      | Content                                                                          | Authenticated by                                                                                                                                                                   | Verified by                      |
| --- | -------------- | -------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------- |
| M1  | A → server     | `pairing_id = MAC(S, "ruvee/v1/pairing-id")[0..16]`                              | A's active session                                                                                                                                                                 | Server                           |
| M2  | B → server → A | `epk_B`, `platform_B`, `req_mac`; the server adds `device_id_B` from B's session | `req_mac = MAC(K_pair, "ruvee/v1/pair-req" ‖ pairing_id ‖ device_id_B ‖ u8(platform_B) ‖ epk_B)`, with `K_pair = MAC(S, "ruvee/v1/pairing-mac" ‖ account_id)`; B's pending session | A (MAC); server (session, state) |
| M3  | A → server → B | `ct = crypto_box_seal(payload, epk_B)`, `resp_mac`, the encrypted `DEVICE_LABEL` | `resp_mac = MAC(K_pair, "ruvee/v1/pair-resp" ‖ pairing_id ‖ device_id_B ‖ epk_B ‖ ct)`; A's active session                                                                         | B                                |
| M4  | B → server     | Completion                                                                       | B's session, now active                                                                                                                                                            | Server                           |

`payload = { v: 1, accountId, deviceId: device_id_B, secretKey: SK, checkpoint: { vaultId, seq, manifestHash, keysetVersion } }`.
The Phase 0 fields `opaqueServerPublicKey` and `instanceId` are removed (V-02, V-03).

### 4.4 Properties

| Concern                                                                           | Result                                                                                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Offline guessing of the code from a recorded transcript                           | The transcript (`pairing_id`, `epk_B`, `req_mac`, `ct`, `resp_mac`) lets an attacker test guesses of `S`, so security is exactly the size of `S`. At 128 bits it is infeasible. With a short code it would be immediate, which is why shortening is blocked.                                     |
| Confidentiality of `SK` if `S` is revealed later                                  | The reply is sealed to an ephemeral key that B erases. Someone who sees the code **after** pairing completes learns nothing from the transcript. The danger window is the 10 minutes before completion.                                                                                          |
| Key substitution (server gives A its own `epk`)                                   | Fails: `req_mac` covers `epk_B` and needs `K_pair`.                                                                                                                                                                                                                                              |
| Forged or substituted reply                                                       | Fails: `resp_mac` covers `ct`. Independently, B checks that the received `SK` opens the server's password wrap with `P` and matches the keyset. The server can't build a wrap that opens with `P`.                                                                                               |
| Replay                                                                            | A request or reply moved to another pairing fails, because `pairing_id`, `epk_B` and `device_id_B` are fresh and covered by the MACs. Completed or expired pairings are deleted, and `S` is erased on both devices.                                                                              |
| Relay to another account                                                          | `K_pair` includes `account_id`, and B checks `accountId` and `deviceId` in the payload.                                                                                                                                                                                                          |
| Reflection (A's MAC presented as B's, or the reverse)                             | Different domain labels (`pair-req`, `pair-resp`).                                                                                                                                                                                                                                               |
| Session mix-up between concurrent pairings                                        | Each pairing has its own `S`. A accepts only the single request for the `pairing_id` it created. B accepts only a reply bound to its own `epk_B` and `device_id_B`.                                                                                                                              |
| Someone who saw the code **and** has a pending session (which needs the password) | Not prevented. Their request may arrive first. The one-request rule means B's request then gets `409`. B tells the user "This code was already used. Cancel on the other device", and A's approval screen shows the platform and time. The user must not approve a request they don't recognize. |

### 4.5 What each device verifies

Before A transfers anything:

1. A is unlocked and `active`, and the pairing is one A created, within its 10 minutes.
2. Exactly one request exists for it.
3. `epk_B` is exactly 32 bytes, and `req_mac` verifies with a constant-time comparison
   (`sodium.memcmp`). A failure burns the pairing and records `pairing_mac_failed`.
4. The user approves after seeing the platform and the request time, and names the device.

Before B accepts anything:

1. `resp_mac` verifies in constant time, and `ct` opens with `esk_B`.
2. The payload parses with `v = 1`, and its `accountId` and `deviceId` are B's own.
3. B fetches `GET /account/keys` (it is active now), derives `AUK` from `P` and the received `SK`,
   and unwraps `AK`.
4. The keyset decrypts with a `keyset_version` at least the checkpoint's, and
   `keyset.secretKey` equals the received `SK`.
5. Only then does B store `SK`, its wrap copy and the checkpoint, and zero `esk_B`, `S` and
   `K_pair`. Its first sync verifies the manifest against the checkpoint.

## 5. Recovery as a complete protocol

### 5.1 The Recovery Kit contains

- the Recovery Key `RK` (16 bytes) as `"RK1-"` plus 29 Crockford base32 characters, including a
  2-byte checksum, and the same text as a QR code
- the username and the server URL
- the creation date and a shortened `recovery_key_id`, to tell kits apart
- the warnings in [account-recovery.md §8](account-recovery.md#8-user-facing-wording)

It does **not** contain the password, `SK` or `AK`. The Phase 0 kit also listed `instance_id`.
That is removed, because it has no protocol role after V-02 and would wrongly suggest that the
client verifies the server with it.

### 5.2 What the kit restores, and how

| Restores                   | How                                                                                                                                                                                                     |
| -------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `AK`                       | `RWK = MAC(RK, …)` opens `AK_WRAP_RECOVERY`, which the server releases to a recovery session                                                                                                            |
| `SK`, `VK`, every item key | The keyset under `K_keyset = KDF(AK, …)`, then `VK` unwraps item keys                                                                                                                                   |
| Server authentication      | `RAK` opens a 15-minute recovery session. The client registers a new OPAQUE record for a password the user sets (`/recovery/password/start`, then `/recovery/complete`), which replaces the old record. |
| Not restored               | The old password (it may be re-entered), a trusted checkpoint (T-08), and other devices' sessions, which are ended                                                                                      |

No step needs the OPAQUE server setup that existed before. A server whose setup file was lost
can generate a new one, and the Recovery Key re-registers the account against it.

### 5.3 After losing every device

1. On a new device, run recovery with the kit and username.
2. Set a password. `RK` rotates; this is mandatory.
3. **New:** the client lists the other devices and asks the user to revoke them as lost. Lost
   devices still hold `SK` and a wrap of `AK` under the old password, so they can be guessed
   offline (V-08).
4. **New:** the client offers `SK` rotation, and later full key rotation once Phase 4 provides
   it.
5. With no checkpoint, the client shows the latest manifest's date and author device for the
   user to confirm.

If the server is also gone, restore a database backup first. The kit must be one that was
current **at the time of that backup**.

### 5.4 Limits of rotation

- Rotating `RK` changes the **current** recovery wrap only. Every older database copy still holds
  the old wrap of the **same** `AK`. Old kit plus old copy equals the vault as of that copy, and
  later data too, as long as `AK` is unchanged and the attacker can obtain new ciphertext.
- Anyone who held the old kit while it was current could already have unwrapped `AK` through
  `/recovery/material` without completing recovery (V-07). Rotating `RK` does not take `AK` back.
  Only full rotation (new `AK`, `VK`, item keys) protects data written afterwards.
- Ciphertext already downloaded, and plaintext already decrypted, stay exposed under the keys
  they were made with.

### 5.5 `RAK` as a bearer credential

`RAK` is a 256-bit value derived from `RK` and sent in the request body. Whoever learns it can
take over **account access** and replace the server's wraps with junk, which deletes the working
recovery wrap. It cannot decrypt anything. The established alternative that keeps it off the
wire is a **second OPAQUE registration** whose password is derived from `RK`. It uses the same
library and has the same implementation evidence as login, at the cost of a second record and
more endpoints. This is decision D-22; Phase 0 had already deferred it as R-08.

## 6. Library validation

| Package                                                  | Exact API used                                                                                                                                                                                                                                                           | Result                                                                                                                                                                                                                                                                                                                                                                                                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `libsodium-wrappers-sumo` 0.8.4 (libsodium 1.0.22)       | `crypto_aead_xchacha20poly1305_ietf_encrypt/decrypt`, `crypto_pwhash` (`ALG_ARGON2ID13`), `crypto_generichash`, `crypto_kdf_derive_from_key`, `crypto_box_keypair`, `crypto_box_seal(_open)`, `crypto_scalarmult`, `pad`/`unpad`, `memzero`, `randombytes_buf`, `memcmp` | All present. Every function with a published or independent reference matches it; `memcmp` and `randombytes_uniform` were checked for presence only. HKDF: constants only, no functions. Tampering of the ciphertext, tag, AAD or nonce produces one message, "ciphertext cannot be decrypted using that key". Truncation throws `TypeError`. Salts other than 16 bytes and `crypto_kdf` contexts other than 8 bytes are rejected. |
| `@serenity-kit/opaque` 1.1.0 (`opaque-ke` 4.0.1)         | `client.startRegistration/finishRegistration/startLogin/finishLogin`, `server.createSetup/createRegistrationResponse/startLogin/finishLogin/getPublicKey`, `ready`                                                                                                       | Round trip works with identifiers. Wrong password, wrong identifier and substituted server setup: client `finishLogin` returns `undefined`. Garbage input throws "opaque protocol error at deserialize …". Tampered finalization throws. A `null` record gives a same-size simulated response. **Replay accepted** (V-04).                                                                                                         |
| `@noble/hashes`, `@noble/ciphers`, `@noble/curves` 2.4.0 | `argon2id`, `blake2b` (key, salt, personalization), `xchacha20poly1305`, `hsalsa`, `xsalsa20poly1305`, `x25519`                                                                                                                                                          | Pass the published KATs and agree byte for byte with libsodium: Argon2id at p = 1 up to 64 MiB t = 3; `crypto_kdf` reconstructed from its documented BLAKE2b definition for subkey ids 0 to 2⁶⁴−1; a sealed box reconstructed and opened in both directions.                                                                                                                                                                       |

**Protocol version.** `opaque-ke` 4.0.0 "synced implementation with RFC 9807 (no core protocol
changes)", and 4.0.1 is a documentation fix. Its README says it is based on RFC 9807. Ruvee's
spike confirms behavior, not conformance. The upstream RFC 9807 vectors use the identity KSF, so
no published vector covers the Argon2id configuration Ruvee would use (V-14).

**Argon2id mapping.** `crypto_pwhash(outlen, P, salt, opslimit, memlimit, ALG_ARGON2ID13)` is
Argon2id version 0x13 with `t = opslimit`, `m = memlimit / 1024` KiB and `p = 1`, with no secret
and no associated data. This was shown by agreement with noble, which itself passes the RFC 9106
§5.3 vector. The OPAQUE KSF is a different configuration (p = 4, zero salt) inside the WASM, and
only its default selection was checked (OP-02).

**Packaging.** `libsodium-wrappers-sumo` 0.8.4 depends on `libsodium-sumo` `^0.8.0`, so only the
lockfile pins the WASM. Both packages need exact pins (INV-22). `@serenity-kit/opaque` has no
runtime dependencies. Its Cargo manifest has no lockfile in the repository, so the
`opaque-ke` patch version is fixed only by the published build.

**Audit evidence, corrected.** `@noble/hashes`: Cure53, January 2022, v1.0.0; the scope
excluded Argon2, BLAKE3, SHA-3 add-ons and SHA-1. `@noble/ciphers`: Cure53, September 2024,
v1.0.0. `@noble/curves`: Trail of Bits, August 2026, v2.3.0, among earlier audits. Since April
2026 the noble READMEs also describe "AI-assisted self-audits", which are not independent audits.
Noble is used here only as a **test oracle**, and its Argon2 is trusted only because it passes
the RFC KAT.

**Mobile and extension gaps.** Not tested: `react-native-libsodium`, OPAQUE on Hermes or through
a native binding, an MV3 offscreen document, and Safari. The research tables record these as
open; nothing here claims support for them.

## 7. Key-derivation measurements

Median of 5 runs (3 in the extension, 7 in Node), with minimum and maximum, on the Apple M5
machine only. Times are for `crypto_pwhash` (p = 1) and for one OPAQUE client `finishLogin`,
which includes Argon2id at 64 MiB, t = 3, p = 4. **These numbers say nothing about phones or
older laptops.** Main-thread runs were single samples and are omitted.

| Runtime (dedicated worker unless stated)  | 19 MiB t=2  | 64 MiB t=3 (profile 1) | 128 MiB t=3   | 256 MiB t=3 (profile 2) | OPAQUE finishLogin |
| ----------------------------------------- | ----------- | ---------------------- | ------------- | ----------------------- | ------------------ |
| Node 24.13.0                              | 14 (14–15)  | 81 (80–142)            | 164 (164–197) | 340 (334–355)           | 92 (92–96)         |
| Playwright Chromium 156                   | 14 (14–14)  | 78 (78–80)             | 172 (163–190) | 333 (332–353)           | 100 (94–114)       |
| Google Chrome 155                         | 16 (15–18)  | 85 (81–90)             | 172 (164–176) | 333 (332–349)           | 101 (91–108)       |
| Playwright Firefox 157                    | 16 (15–18)  | 100 (87–124)           | 178 (177–189) | 366 (364–379)           | 100 (97–104)       |
| Playwright WebKit 27.2                    | 14 (14–15)  | 81 (81–82)             | 167 (167–176) | 344 (343–358)           | 92 (92–94)         |
| Chromium 156 MV3 service worker, headless | 55 (53–79)  | 300 (259–328)          | 619 (535–720) | 1,305 (1,284–1,460)     | 334 (293–427)      |
| Chromium 156 MV3 service worker, headed   | 98 (89–102) | 436 (374–447)          | 793 (717–836) | 1,525 (1,482–1,658)     | 469 (410–492)      |

All values are in milliseconds. A headed run of the extension was slower still, so headless mode
is not the cause of the service-worker slowdown. Its cause was not investigated.

What this supports: on this machine, profile 1 costs about 80 ms in every engine tested, and
the documented budget (2 s median on the weakest supported device) leaves a large margin **here**.
What it does not support: any statement about the reference low-end devices, which the owner has
not named yet (D-03). **Profile 1 (64 MiB, t = 3) stays provisional** until P2-02 measures those
devices. Peak memory was not measured in browsers.

The P2-02 benchmark later repeated these measurements on the same machine with 20 samples, p95,
worker initialisation, cancellation and memory where available
([kdf-calibration.md](kdf-calibration.md)). It is still one machine.

## 8. Test-vector plan, reassessed

### 8.1 Published known-answer tests per primitive

| Primitive (as Ruvee uses it)                                  | Published vectors                                                                                            | Runs through libsodium?                                                        | Independent check                                                            |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ | ------------------------------------------------------------------------------ | ---------------------------------------------------------------------------- |
| XChaCha20-Poly1305-IETF                                       | draft-irtf-cfrg-xchacha-03 §A.3.1; Wycheproof `xchacha20_poly1305_test.json` (306 tests with 24-byte nonces) | Yes                                                                            | noble `xchacha20poly1305` also passes                                        |
| Argon2id v1.3                                                 | RFC 9106 §5.3 (p = 4, with secret and associated data)                                                       | **No**: `crypto_pwhash` has no p, secret or AD                                 | noble passes the RFC vector, then agrees with libsodium at p = 1 (chained)   |
| BLAKE2b unkeyed                                               | RFC 7693 Appendix A                                                                                          | Yes                                                                            | noble                                                                        |
| BLAKE2b keyed, 64-byte key, 64-byte output                    | BLAKE2 reference `blake2b-kat.txt`                                                                           | Yes                                                                            | noble                                                                        |
| Keyed BLAKE2b-256 with 16- or 32-byte keys (Ruvee's `MAC`)    | **None**                                                                                                     | n/a                                                                            | Cross-implementation only (noble)                                            |
| `crypto_kdf_derive_from_key` (BLAKE2b with salt and personal) | **None independent.** libsodium's own test expectations come from the implementation under test.             | n/a                                                                            | noble from the documented definition                                         |
| X25519                                                        | RFC 7748 §6.1                                                                                                | Yes                                                                            | noble                                                                        |
| `crypto_box_seal`                                             | **None**                                                                                                     | n/a                                                                            | Reconstruction from X25519, HSalsa20, BLAKE2b and XSalsa20-Poly1305 in noble |
| ISO/IEC 7816-4 padding                                        | None (an encoding)                                                                                           | n/a                                                                            | Ruvee's own implementation against `sodium_pad`                              |
| SHA-256 (`RAK` verifier, token hashes; server side)           | FIPS 180-4 examples                                                                                          | n/a (Node `crypto`)                                                            | Not needed beyond the published examples                                     |
| OPAQUE                                                        | RFC 9807 Appendix C, **identity KSF only**                                                                   | Upstream `opaque-ke` runs them; `@serenity-kit/opaque` can't inject randomness | None for the Argon2id configuration. Regression fixtures only.               |

One independent implementation is enough: `@noble/*`, which shares no code with libsodium. The
Phase 0 plan's Python (`argon2-cffi`, PyCryptodome, `hashlib`) and Go (`nacl/box`) generators
added redundancy, not coverage, and are dropped. Noble's Argon2 is outside its audit, so it is
trusted only because it passes RFC 9106.

### 8.2 Four separate kinds of tests

| Kind                                       | What it checks                                                                                                                                                   | Expected results                                                                                                                                                                                                                                                                    | When                                               |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------- |
| 1. Published primitive vectors             | Section 8.1, in Node and every browser engine, and later on mobile                                                                                               | Exact bytes from the published source. AEAD negative cases expect "authentication fails" and nothing more specific.                                                                                                                                                                 | Now (P2-01)                                        |
| 2. Ruvee protocol interoperability vectors | Derivations (`AUK`, `RWK`, `RAK`, `K_*`), envelopes, item records, manifests, digests, Recovery Key and pairing-code text                                        | Bytes agreed by two implementations, `packages/crypto` on libsodium and a noble-based reference. **Not authoritative** until the byte format is reviewed and frozen. Until then they are regenerated freely and labelled provisional.                                               | Provisional with P2-03; authoritative after review |
| 3. Parsing and tampering                   | The envelope decoder in `packages/crypto`                                                                                                                        | Typed errors only where Ruvee's parser decides before decryption: length, magic, version, algorithm, purpose, `key_id`. Anything covered by the AEAD (nonce, ciphertext, tag, any AAD or context field) yields one `integrity_failure`, never a field-specific error. Plus fuzzing. | P2-03                                              |
| 4. Application authorization and replay    | Server and client behavior: single-use `loginId`, single request per pairing, recovery-session scope, step-up, refresh-token reuse, keyset and manifest rollback | HTTP and integration tests with exact status codes, because Ruvee defines them                                                                                                                                                                                                      | With each P2 task                                  |

The Phase 0 list of negative vectors mixed kinds 3 and 4, and expected typed errors for
AEAD-covered fields, which the primitive cannot provide (LS-04). That is corrected in
[cryptographic-design.md §8](cryptographic-design.md#8-test-vectors-and-interoperability-plan).

## 9. Document changes made

Every changed document keeps the status **Proposed**, and has a "Changes after architecture
validation" section that lists what changed and why.

| Document                                                                                          | Change                                                                                                                                                                           |
| ------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| [authentication.md](authentication.md)                                                            | Narrowed claim (V-01). No server identity (V-02). No pinning (V-03). Single-use login state (V-04). Password input rule (V-05). KSF facts (V-14). Corrected `opaque-ke` version. |
| [cryptographic-design.md](cryptographic-design.md)                                                | Password input rule (V-05). Length checks (V-12). Profile 1 provisional with measurements. Error classes. §8 vector plan rewritten (V-10).                                       |
| [device-enrollment.md](device-enrollment.md)                                                      | Pairing rules, payload, verification, status and no-shortening rule (V-02, V-03, V-09). `SK` rotation on loss (V-08).                                                            |
| [account-recovery.md](account-recovery.md)                                                        | Kit contents, recovery notice at start, device-loss steps, rotation limits (V-07, V-08).                                                                                         |
| [threat-model.md](threat-model.md)                                                                | A2, T-01, T-02, T-03, T-19 and T-22 narrowed or corrected (V-01, V-06, V-08).                                                                                                    |
| [security-invariants.md](security-invariants.md)                                                  | New INV-23: server-side protocol state is single-use (V-04, V-09).                                                                                                               |
| [research-sources.md](research-sources.md)                                                        | Corrections (V-13), measurements, HPKE and PAKE evidence.                                                                                                                        |
| [risk-register.md](risk-register.md)                                                              | R-02, R-03, R-08, R-13, R-14 updated. New R-17 (`SK` exposure persists), R-18 (stolen device with live session).                                                                 |
| [api-design.md](../architecture/api-design.md)                                                    | `serverPublicKey` and `instanceId` removed from responses. Pairing request rules.                                                                                                |
| [database-design.md](../architecture/database-design.md)                                          | `server_instance` marked as unnecessary if V-02 is accepted.                                                                                                                     |
| [open-decisions.md](../architecture/open-decisions.md)                                            | The approval list is replaced by a decision table, with product preferences separated from technical claims.                                                                     |
| [implementation-roadmap.md](../planning/implementation-roadmap.md)                                | P2-01 becomes a primitive validation harness. Pinning removed from P2-09. Pairing and replay tests added.                                                                        |
| ADRs [0002](../adr/0002-libsodium-primitives.md) to [0006](../adr/0006-user-held-recovery-key.md) | Consequences and decisions corrected as above. All still Proposed.                                                                                                               |

## 10. Follow-up: primitive validation harness (P2-01)

Added on 2026-10-22 after the owner approved D-25 (the scope of P2-01 only). Everything else in
this document stays **Proposed**.

The spike's library checks are now a maintained harness in
[`tools/crypto-validation/`](../../tools/crypto-validation/README.md), outside the pnpm workspace,
with exact pins and its own lockfile. It runs in Node and in Playwright Chromium, Firefox and
WebKit, on the page and in a dedicated worker, under a CSP that adds only `'wasm-unsafe-eval'`.
It keeps the four categories separate: published known-answer tests, cross-implementation
checks, library behavior (each labelled as enforced or not enforced by the library), and proposed
Ruvee input rules (labelled Proposed). Negative controls confirm that each check fails when its
expected values, the library or its sources are altered.

Results on 2026-10-22: every check passed in Node 24, in the three Playwright engines and in
Google Chrome on macOS, and in a local Linux container that ran the CI job's commands. Remote CI
has not run. Coverage gaps (Safari, phones, older laptops, React Native, the MV3 service worker)
are listed in the harness README.

What the harness added to this report:

- **V-15** (section 1): stale WebAssembly memory from `crypto_kdf_derive_from_key` with an invalid
  subkey length.
- V-12 confirmed and extended: BLAKE2b also accepts output lengths of 1 to 15 bytes, and an
  8-byte non-ASCII `crypto_kdf` context is accepted.
- Argon2id parameter handling: invalid parameters are rejected without a large allocation, but
  `memlimit` is silently rounded down to whole KiB and there is no ceiling below the WebAssembly
  limit, so excessive parameters must be refused by the caller (proposed profile registry).
- Argon2id now has a published-vector check through libsodium: the reference `test.c` vectors
  via `crypto_pwhash_str_verify`. Raw `crypto_pwhash` with a 16-byte salt still has no published
  vector and relies on agreement with noble.
