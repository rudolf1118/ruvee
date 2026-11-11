# Architecture validation spike (disposable)

Throwaway compatibility experiments for the Proposed Phase 0 security architecture. Findings are written up in [`docs/security/architecture-validation.md`](../../docs/security/architecture-validation.md).

This directory is **not** a workspace package, is not imported by any app, and must not be copied into production code. Every input is synthetic: no real passwords, credentials, network services or external infrastructure are used. The checks show that libraries behave as documented on one machine. They are not a security audit and they do not test any Ruvee protocol.

## Pinned dependencies

Installed with npm into this directory only (`.npmrc`: `save-exact=true`, `ignore-scripts=true`). `package-lock.json` pins the full tree.

| Package                   | Version | Purpose                                                                                      |
| ------------------------- | ------- | -------------------------------------------------------------------------------------------- |
| `libsodium-wrappers-sumo` | 0.8.4   | Proposed primitive library (libsodium 1.0.22 WASM); depends on `libsodium-sumo` via `^0.8.0` |
| `libsodium-sumo`          | 0.8.4   | Pinned explicitly so the caret range cannot drift                                            |
| `@serenity-kit/opaque`    | 1.1.0   | Proposed OPAQUE library (WASM embeds `opaque-ke` 4.0.1)                                      |
| `@noble/hashes`           | 2.4.0   | Independent BLAKE2b and Argon2id for cross-checks                                            |
| `@noble/ciphers`          | 2.4.0   | Independent XChaCha20-Poly1305, HSalsa20, XSalsa20-Poly1305                                  |
| `@noble/curves`           | 2.4.0   | Independent X25519                                                                           |
| `esbuild`                 | 0.28.2  | Browser bundles                                                                              |
| `playwright-core`         | 1.64.1  | Browser driver (browser builds are downloaded separately)                                    |

## Commands

```sh
cd spikes/architecture-validation
npm ci --no-audit --no-fund
BENCH_RUNS=5 node src/run-node.mjs          # writes results/node.json, exit 1 on any failure

npx --no-install playwright-core install chromium firefox webkit
node src/build-browser.mjs                  # dist/page.js, dist/worker.js, dist/extension-*/
BENCH_RUNS=5 node src/run-browser.mjs       # writes results/browser.json
ONLY=extension node src/run-browser.mjs     # re-run a subset and merge into results/browser.json
EXT_HEADED=1 ONLY=extension node src/run-browser.mjs   # headed extension run
ONLY=opaque-csp node src/run-browser.mjs  # OPAQUE alone under strict and nowasm CSP (Chromium)
```

`run-browser.mjs` serves `dist/` and `kat/` from `127.0.0.1` on a random port. Every response carries one of two Content Security Policies:

- `strict`: `default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; connect-src 'self'; worker-src 'self'; ...`
- `nowasm`: the same without `'wasm-unsafe-eval'`.

The checks run on the page main thread and in a dedicated Web Worker. Both MV3 extension variants (the default extension CSP, and `extension_pages` with `'wasm-unsafe-eval'`) run in the extension service worker of Playwright's Chromium. Main-thread benchmark rows use a single sample.

## Environment of the recorded results

- Apple M5, 10 cores, 16 GiB RAM, macOS (darwin 25.5.0, arm64)
- Node 24.13.0 (V8 13.6), npm 11.6.2
- Playwright Chromium 156.0.8078.4 (Chrome for Testing build 1248), headless
- Google Chrome 155.0.8059.85 (installed stable channel), headless
- Playwright Firefox 157.0 (build 1555): a patched Playwright build, not a stock Firefox release
- Playwright WebKit 27.2 (build 2370): a Playwright WebKit build, **not Safari**

## Checks

| ID     | What is checked                                                                              | Reference                                                |
| ------ | -------------------------------------------------------------------------------------------- | -------------------------------------------------------- |
| LS-01  | Required libsodium functions and constants exist; HKDF exposure                              | libsodium.js exports                                     |
| LS-02  | XChaCha20-Poly1305 IETF, libsodium and noble                                                 | draft-irtf-cfrg-xchacha-03 §A.3.1                        |
| LS-03  | Wycheproof XChaCha20-Poly1305 (306 tests with 192-bit nonces) through libsodium decrypt      | Wycheproof `7a32593`                                     |
| LS-04  | Tampered tag, ciphertext, AAD, nonce, key, truncation: error surface                         | none (behaviour record)                                  |
| LS-05  | BLAKE2b-512 of "abc"                                                                         | RFC 7693 Appendix A                                      |
| LS-06  | Keyed BLAKE2b-512, 256 entries                                                               | BLAKE2 reference `blake2b-kat.txt` (`ed1974e`)           |
| LS-07  | Keyed BLAKE2b-256 (16, 32, 64-byte keys) vs noble; 15-byte key behaviour                     | cross-implementation                                     |
| LS-08  | `crypto_kdf_derive_from_key` = BLAKE2b(key, salt = LE64(id)‖0⁸, personal = ctx‖0⁸) vs noble  | cross-implementation (no published KAT)                  |
| LS-09a | noble Argon2id                                                                               | RFC 9106 §5.3                                            |
| LS-09b | libsodium `crypto_pwhash` ARGON2ID13 vs KAT-validated noble at p = 1, including 64 MiB t = 3 | chained cross-check                                      |
| LS-09c | Password string handling: NFC/NFD, lone surrogates, salt length                              | behaviour record                                         |
| LS-10  | X25519                                                                                       | RFC 7748 §6.1                                            |
| LS-11  | `crypto_box_seal` both directions vs an independent noble reconstruction                     | cross-implementation (no published KAT)                  |
| LS-12  | Padding, `memzero`, `randombytes_buf`                                                        | behaviour record                                         |
| OP-01  | OPAQUE registration and login with identifiers                                               | round trip                                               |
| OP-02  | Default key stretching equals `memory-constrained`; a mismatched preset fails                | behaviour record                                         |
| OP-03  | Wrong password                                                                               | behaviour record                                         |
| OP-04  | Server identifier mismatch                                                                   | behaviour record                                         |
| OP-05  | Server key substitution with the stolen record                                               | RFC 9807 §4 (server public key in cleartext credentials) |
| OP-06  | Unknown user: simulated response                                                             | RFC 9807 §10.9                                           |
| OP-07  | Malformed and tampered messages; replay of server login state                                | behaviour record                                         |
| OP-08  | Lone surrogate vs U+FFFD; NFD vs NFC                                                         | behaviour record                                         |

There are no published vectors for the Argon2id KSF configuration of `@serenity-kit/opaque`: the upstream `opaque-ke` RFC 9807 vectors use the identity KSF. The OPAQUE checks therefore show behaviour only, not conformance.

## Known-answer test sources

| File                                          | Source                                                                                                      | SHA-256                                                            |
| --------------------------------------------- | ----------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------ |
| `kat/rfc9106.txt`                             | https://www.rfc-editor.org/rfc/rfc9106.txt                                                                  | `855c06f060379e34285e83a217e9069b5c72e161a1e54df9af5cd88dbb231f31` |
| `kat/rfc7693.txt`                             | https://www.rfc-editor.org/rfc/rfc7693.txt                                                                  | `c943754888364fe29bbd0bb3c71c6658ef392371497eaa4a9d9dde015b0721e5` |
| `kat/rfc7748.txt`                             | https://www.rfc-editor.org/rfc/rfc7748.txt                                                                  | `279ca0ecc5e92e2962e27b846986aeb74729d9dd34bd4a04a362f80dcb596ad3` |
| `kat/draft-irtf-cfrg-xchacha-03.txt`          | https://www.ietf.org/archive/id/draft-irtf-cfrg-xchacha-03.txt                                              | `fa796b50265eeee383d40e82fed880267c7835e1b3d64c50c4f06162adaa1cfd` |
| `kat/wycheproof-xchacha20_poly1305_test.json` | C2SP/wycheproof `testvectors_v1/xchacha20_poly1305_test.json` at `7a325932231bd7a724c791c8b0d65ea4d6d2f435` | `a79de072571b90eb40c3a63ce0c7f75dcb4b62323c8870228e1f61dcc61d63a9` |
| `kat/blake2b-kat.txt`                         | BLAKE2/BLAKE2 `testvectors/blake2b-kat.txt` at `ed1974ea83433eba7b2d95c5dcd9ac33cb847913`                   | `82fcb3cabe8ff6e1452849e3b2a26a3631f1e2b51beb62ffb537892d2b3e364f` |
