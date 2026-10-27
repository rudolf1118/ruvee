# Stage 1: native compatibility evidence

Date: 2026-10-27. Base commit `e0a8586` plus SC-1 (`b3effd3`). Synthetic inputs only.
**Everything below ran on an Android Emulator** (task-owned AVD `ruvee-task-mobile`: Android 16,
API 36.1 Google APIs image, arm64-v8a, 4 cores, 3 GB, on an Apple-silicon Mac), debug build, Hermes.
Nothing ran on a phone. iOS was not run: there is no Xcode on the development machine.

Reproduce: [testing.md](testing.md#stage-1-compatibility-runner).

## 1. Conclusions

1. **Hermes has no WebAssembly.** React Native 0.88.0 ships Hermes V1 (`260318099.0.4`) always on;
   `typeof WebAssembly === 'undefined'` on the device, and the Hermes AAR exposes no such global.
   authentication.md's note that "Hermes V1 WebAssembly arrived with React Native 0.84" does not hold
   for this build (SC-5). D-05 option 1 (Hermes WebAssembly) is not available.
2. **libsodium.js is not usable on Hermes in practice.** Its pure-JS (wasm2js) fallback loads and
   passes the 1.0.22 pin, but one profile-1 Argon2id takes **47.9 s** against **0.23 s** natively,
   with equal output. A wasm2js translation of the OPAQUE module would cost the same per login.
3. **`react-native-libsodium` 1.7.0 cannot carry Ruvee's AEAD.** Its
   `crypto_aead_xchacha20poly1305_ietf_*` takes the additional data only as a JS string and encodes
   it as UTF-8 in C++ (`asString(runtime).utf8(runtime)`); Ruvee's AAD is binary. It also exposes no
   `crypto_hash_sha256`, `sodium_memcmp` or `sodium_version_string`.
4. **The app's primitives reproduce the web's byte for byte.** Native libsodium 1.0.21 for Argon2id,
   BLAKE2b, `crypto_kdf`, Ed25519, X25519 sealed boxes and randomness; `@noble/ciphers` 2.4.0 for
   XChaCha20-Poly1305; `@noble/hashes` 2.4.0 for SHA-256; noble `equalBytes` for constant-time
   comparison. Over them, **every portable check of `packages/crypto` passes unchanged** on the
   device, including the published XChaCha20-Poly1305 vectors (draft §A.3.1, 315 Wycheproof cases)
   and the committed provisional protocol vectors (7 password cases, every envelope purpose, item
   records, manifests, pairing).
5. **OPAQUE runs through a native binding of `opaque-ke` 4.0.1** (owner's choice for D-05,
   2026-10-27; SC-7). It interoperates with `@serenity-kit/opaque` 1.1.0 in both directions on the
   host (13/13) and logs in against the real API on the device (E2E).
6. **Argon2id profile 1 costs 0.19-0.36 s natively on the emulator** (several runs). This is an
   emulator on a fast host, not evidence for D-26's reference phones.

## 2. On-device results (compatibility runner)

`apps/mobile/app/src/compat/checks.ts`, development builds only. The table is the first recorded
full run (38 checks, 36 pass) plus the Keystore probe from the latest run, which has **37 of 39
passing**. The two failures in both runs are conclusion 1 and its consequence, kept as evidence.

| Result | Group                  | Check                                         | ms    | Detail                                                                                |
| ------ | ---------------------- | --------------------------------------------- | ----- | ------------------------------------------------------------------------------------- |
| PASS   | runtime                | engine                                        | 22    | hermes=true version=260318099.0.4 os=android api=36                                   |
| FAIL   | runtime                | webassembly                                   | 0     | WebAssembly is not defined                                                            |
| PASS   | runtime                | text-codecs                                   | 9     | TextEncoder, TextDecoder(fatal, ignoreBOM)                                            |
| PASS   | runtime                | random-source                                 | 1     | `crypto.getRandomValues` installed over native libsodium `randombytes_buf`            |
| PASS   | app-crypto             | known-answer-self-test                        | 269   | every primitive equals libsodium.js 1.0.22 output                                     |
| PASS   | libsodium.js-wasm2js   | libsodium.js-load-and-pin                     | 683   | version 1.0.22, pure-JS build                                                         |
| PASS   | app-crypto             | provisional-protocol-vectors (committed file) | 2848  | 7 password cases and every format equal the committed vectors                         |
| PASS   | app-crypto             | init-and-public-surface                       | 11    |                                                                                       |
| PASS   | app-crypto             | published-xchacha-draft-a31                   | 636   |                                                                                       |
| PASS   | app-crypto             | published-xchacha-wycheproof                  | 580   |                                                                                       |
| PASS   | app-crypto             | password-input-rule                           | 5     |                                                                                       |
| PASS   | app-crypto             | kdf-profile-floor                             | 2     |                                                                                       |
| PASS   | app-crypto             | v15-defect-present-in-pinned-library          | 626   | (tests libsodium.js itself)                                                           |
| PASS   | app-crypto             | v15-contained-by-wrapper                      | 4     |                                                                                       |
| PASS   | app-crypto             | other-library-boundaries-contained            | 2     |                                                                                       |
| PASS   | app-crypto             | envelope-parsing-and-tampering                | 59    |                                                                                       |
| PASS   | app-crypto             | keyset-plaintext-schema                       | 134   |                                                                                       |
| PASS   | app-crypto             | nonce-uniqueness                              | 448   |                                                                                       |
| PASS   | app-crypto             | decoder-fuzz                                  | 178   |                                                                                       |
| PASS   | app-crypto             | inv17-secret-key-alone-decrypts-nothing       | 572   |                                                                                       |
| PASS   | app-crypto             | padding-matches-libsodium                     | 132   |                                                                                       |
| PASS   | app-crypto             | recovery-verifier-is-sha256                   | 1     |                                                                                       |
| PASS   | app-crypto             | uuid-generation-and-encoding                  | 7     |                                                                                       |
| PASS   | app-crypto             | recovery-key-text-format                      | 2     |                                                                                       |
| PASS   | app-crypto             | recovery-wrap-round-trip-and-binding          | 2     |                                                                                       |
| PASS   | app-crypto             | item-record-round-trip-and-binding            | 75    |                                                                                       |
| PASS   | app-crypto             | items-digest-and-manifest                     | 36    |                                                                                       |
| PASS   | app-crypto             | local-record-round-trip-and-binding           | 1044  |                                                                                       |
| PASS   | app-crypto             | pairing-code-format                           | 4     |                                                                                       |
| PASS   | app-crypto             | pairing-round-trip-and-binding                | 16    |                                                                                       |
| PASS   | app-crypto             | argon2id-profile-1                            | 358   | native, 64 MiB, t = 3, p = 1                                                          |
| PASS   | app-crypto             | aead-1mib                                     | 2131  | noble seal 1260 ms, open 835 ms for 1 MiB (debug build; the `LOCAL_RECORD` maximum)   |
| PASS   | native-vs-libsodium.js | hash-kdf-sign-box                             | 593   | keyed BLAKE2b (16/32), `crypto_kdf` (4 contexts), Ed25519, sealed boxes both ways     |
| PASS   | native-vs-libsodium.js | native-aead-binary-aad                        | 6     | expected limitation: binary AAD refused, so AEAD uses noble                           |
| FAIL   | opaque                 | serenity-kit-opaque-on-hermes                 | 36    | the module cannot load without WebAssembly                                            |
| PASS   | opaque                 | native-opaque-binding                         | 37    | binding loaded; message sizes match; malformed input refused (full login: E2E)        |
| PASS   | runtime                | keystore-round-trip-and-level (latest run)    | 187   | AES-GCM key in AndroidKeyStore; the platform reports `secure_software` (not hardware) |
| PASS   | device-proof           | device-proof-sign-verify                      | 2     | DSI signature verifies; a changed nonce does not                                      |
| PASS   | libsodium.js-wasm2js   | argon2id-profile-1-pure-js                    | 48124 | pure JS 47891 ms vs native 231 ms; outputs equal                                      |

Notes on the method:

- The package's own `provisional-protocol-vectors` check also recomputes every vector with the
  pure-JS noble reference (eight 64 MiB Argon2id runs), which takes too long on Hermes. On the device
  the package's outputs over the app's primitives are compared with the committed vector file
  instead; Node and three browsers verify that file against noble on every run.
- The portable checks get their operations from `initRuveeCrypto()`; in the development bundle
  that name resolves to the app's builder (`src/compat/portable-index.ts`), so every check exercises
  the app's crypto, not libsodium.js. The checks that test libsodium.js itself (V-15, padding against
  `sodium_pad`) still use libsodium.js.
- The vector files are embedded at build time (`scripts/embed-compat-vectors.mjs`) and checked
  against the SHA-256 in `sources.json` before use, as everywhere else.
- Every app start also runs a fast known-answer test (`src/crypto/ruvee-crypto.ts`, about 0.3 s on
  the emulator, including an 8 MiB Argon2id) and refuses to open the vault on any mismatch.

## 3. OPAQUE

| Evidence                                    | Where                                 | Result                                                                                                                                                                                                                                         |
| ------------------------------------------- | ------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Binding's own round trip (opaque-ke server) | `cargo test` in `native/opaque`, host | Pass: right password, wrong password, substituted server setup, malformed input                                                                                                                                                                |
| Against @serenity-kit/opaque 1.1.0 (Node)   | `scripts/opaque-interop.mjs`, host    | 13/13: binding-registered record logs in through the web client and the binding; web-registered record logs in through the binding; wrong password, substituted setup, tampered response, malformed input refused; ASCII and non-BMP passwords |
| On the device, against the real API         | E2E suite                             | See [implementation-status.md](implementation-status.md#3-test-results)                                                                                                                                                                        |

The binding reproduces `@serenity-kit/opaque` 1.1.0's client functions (`src/lib.rs` at tag
`@serenity-kit/opaque@1.1.0`, read from the published repository): ristretto255 OPRF and group,
Triple-DH over SHA-512, the "memory-constrained" KSF (Argon2id v1.3, t = 3, m = 2¹⁶ KiB, p = 4,
16-byte zero salt), no identifiers, unpadded URL-safe base64, a client-detected login failure
returned as "no result". Passwords cross JNI as UTF-8 bytes, never as JNI strings (whose modified
UTF-8 would encode non-BMP characters differently).

## 4. Dependency provenance

| Component                     | Version (exact pin)             | Source and build                                                                                                                                                | Audit status                                                                                                 |
| ----------------------------- | ------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| React Native / Hermes         | 0.88.0 / 260318099.0.4          | npm, Maven (prebuilt AARs)                                                                                                                                      | n/a                                                                                                          |
| react-native-libsodium        | 1.7.0                           | npm; ships libsodium 1.0.21 prebuilt by the package (`libsodium/build.sh`: release tarball verified with minisign, built with libsodium's `dist-build` scripts) | libsodium widely reviewed; this binding and its prebuilt binaries are not audited; binaries not rebuilt here |
| @noble/ciphers, @noble/hashes | 2.4.0, 2.4.0                    | npm, pure TypeScript; the repository's existing reference implementation                                                                                        | noble-ciphers and noble-hashes have published third-party audits of earlier versions                         |
| opaque-ke                     | 4.0.1                           | crates.io, compiled here (`Cargo.lock` committed)                                                                                                               | NCC Group audit of v0.5.0 (2021); 4.0.1 not audited                                                          |
| argon2 (RustCrypto)           | 0.5.3                           | crates.io                                                                                                                                                       | not audited as far as the author knows                                                                       |
| jni (Rust)                    | 0.21.1                          | crates.io                                                                                                                                                       | n/a                                                                                                          |
| The binding itself            | `apps/mobile/app/native/opaque` | Ruvee code, ~250 lines Rust + Kotlin                                                                                                                            | **Not reviewed** (D-19)                                                                                      |
| react-native-keychain         | 10.0.0 (2025-03-23)             | npm; Android `AES_GCM_NO_AUTH` cipher storage                                                                                                                   | not audited; last release 19 months old                                                                      |
| @op-engineering/op-sqlite     | 19.0.1                          | npm; bundled SQLite                                                                                                                                             | not audited; stores ciphertext only                                                                          |
| Rust toolchain                | 1.99.1 stable                   | rustup-init verified against its published SHA-256, installed in the task-owned toolchain folder                                                                | n/a                                                                                                          |
| Android NDK / CMake           | 27.1.12297006 (r27b) / 3.22.1   | dl.google.com archives verified against the SHA-1 in Google's repository manifest, task-owned folder                                                            | n/a                                                                                                          |

## 5. Limits of this evidence

- Emulator only: no phone, no StrongBox or TEE, no biometric hardware, no system autofill.
- Debug build with Metro; release-build behaviour (Hermes bytecode, `FLAG_SECURE`, no cleartext)
  is configured but not exercised by these runs.
- The prebuilt native libsodium binaries in `react-native-libsodium` were not rebuilt from source.
- Timing figures are from one emulator on one host and vary run to run (Argon2id 0.19-0.36 s).
