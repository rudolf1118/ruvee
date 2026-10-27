# Shared-change requests from the mobile branch

Branch `mobile/vault-app`, from base `e0a8586`. The mobile work owns `apps/mobile` and
`docs/mobile`. Everything below touches code or documents shared with the web app, the
extension or the API, or concerns a security decision, so it is listed here for the owner and the
security-review session to accept, change or reject. Only SC-1 and SC-6 are committed on this
branch, each in its own commit; nothing else outside `apps/mobile` and `docs/mobile` was changed.

| Id   | What                                                                 | Status on this branch                                                               | Blocks without it                                          |
| ---- | -------------------------------------------------------------------- | ----------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| SC-1 | `ios` and `android` as login and pairing platforms                   | **Committed** (`b3effd3`), approved by the owner as a minimal flagged change        | Every mobile login, pairing and sync                       |
| SC-2 | Export a primitives-injected builder from `@ruvee/crypto`            | Worked around in `apps/mobile` (Metro alias)                                        | Nothing now; the workaround reaches into package internals |
| SC-3 | How a native client passes the CSRF `Origin` check                   | Worked around in `apps/mobile` (sends the server origin)                            | Login and refresh from the app                             |
| SC-4 | `EngineDeps.store` as an interface, not the IndexedDB class          | Worked around in `apps/mobile` (type cast)                                          | Nothing at runtime                                         |
| SC-5 | Corrections to the design documents (evidence from Stage 1)          | Proposed text only                                                                  | Nothing; the documents are wrong about mobile              |
| SC-6 | Root `.prettierignore` entries for mobile lockfiles and build output | **Committed** (`f4c178a`)                                                           | Root `pnpm format:check` on a tree with a mobile build     |
| SC-7 | D-05 resolution: a Ruvee-maintained native `opaque-ke` binding       | Implemented in `apps/mobile/app/native/opaque`, owner chose the option (2026-10-27) | Mobile authentication                                      |

## SC-1: `ios` and `android` log in and pair as token platforms (committed)

**Change** (commit `b3effd3`, three lines and the regenerated OpenAPI file):

- `packages/contracts/src/auth.ts`: `platformSchema = z.enum(['web', 'extension', 'ios', 'android'])`.
- `apps/api/src/auth/login-state.store.ts`: `PendingLogin.platform` takes the same four values.
- `packages/vault/src/vault-engine.ts`: `EngineDeps.platform` takes the same four values.

**Why it is safe as far as the author can see:** the API already gives bearer tokens to every
platform other than `web` (`auth.service.ts`, `loginFinish`); the pairing request MAC already codes
ios 3 and android 4 (`PLATFORM_CODES`); `devicePlatformSchema` and the database already store both;
the web pairing screen already names them ("Android device"). OPAQUE, device proof, CSRF and
the pairing messages are unchanged. Contracts, API and vault unit tests pass; API, vault, web and
extension type-check.

**Still to decide:** whether the security session wants an integration test of an `android`
token login in `apps/api/test/tokens.int-spec.ts` (the mobile E2E exercises it against the real
API, but not in the API's own suite).

## SC-2: a primitives-injected builder in `@ruvee/crypto`

`initRuveeCrypto()` is the only public way to get `RuveeCrypto`, and it loads libsodium.js's
WebAssembly build. Hermes has no WebAssembly, and libsodium.js's pure-JS fallback takes ~48 s for
one profile-1 Argon2id on the emulator (native: ~0.2-0.4 s). The package already has the right
seam, `RawPrimitives` + `guardPrimitives` + `buildRuveeCrypto`, but does not export it.

**Requested interface** (`packages/crypto/src/index.ts`):

```ts
export type { RawPrimitives } from './primitives.js';
/** The operations over caller-supplied primitives, behind the same guard as initRuveeCrypto. */
export function createRuveeCrypto(raw: RawPrimitives): RuveeCrypto {
  const p = guardPrimitives(raw);
  return buildRuveeCrypto(p, randomNonces(p));
}
```

**Today:** `apps/mobile/app/metro.config.js` maps `@ruvee/crypto-internal/<module>` to
`packages/crypto/src/<module>.ts`, and only `apps/mobile/app/src/crypto/ruvee-crypto.ts` uses it, to
do exactly the two lines above. It is the same source, not a fork, but it depends on internal
module paths. With SC-2 the alias goes away.

## SC-3: the CSRF `Origin` check for a native client

authentication.md §6 says bearer clients (extension and mobile) are outside CSRF. As built, the
API still applies the `Origin` check to the unauthenticated writes a token client makes
(`login/start`, `login/finish`, `refresh`): it accepts `PUBLIC_ORIGIN`, or a listed
`chrome-extension://` origin on routes marked for the extension, and nothing else. A native
HTTP client sends no `Origin`.

**What the app does:** it sends `Origin: <the server origin the user configured>` on requests to
that server's `/api/` (`apps/mobile/app/src/platform/transport.ts`), with no cookie
(`credentials: 'omit'`). That passes the check unchanged. It grants nothing new: the check defends
browsers against cross-site requests that carry ambient credentials; any non-browser client can
already send any `Origin`, and a token client has no ambient credential.

**Decision requested** from the security session. Options:

1. Keep this, and document in authentication.md §6 that native clients send the public origin.
2. Accept a missing `Origin` on the token-platform unauthenticated routes when no cookie is
   present (an API change; a browser always sends `Origin` on a cross-origin POST).
3. A mobile marker like `EXTENSION_METADATA` (an API change, and the marker would be forgeable).

The author recommends 1: it changes no server code and the reasoning above holds.

## SC-4: `EngineDeps.store` as an interface

`EngineDeps.store` is typed as the IndexedDB `DeviceStore` class, which has private members, so no
other implementation is assignable. The mobile store (`apps/mobile/app/src/storage/device-store.ts`,
SQLite plus the Keystore) has the same public surface and is passed with a cast
(`asDeviceStore()`). **Requested:** export an interface with the nine methods the engine calls
(`device`, `putDevice`, `records`, `imports`, `importsCount`, `manifest`, `local`, `apply`, `wipe`)
and type `EngineDeps.store` with it. Type-only; no runtime change.

## SC-5: design documents that are wrong about mobile (proposed text)

Evidence: `docs/mobile/native-compatibility.md` (runs on the Android emulator, 2026-10-27).

- **authentication.md §2.1 and research notes** say "Hermes V1 WebAssembly arrived with React Native
  0.84". On React Native 0.88.0 for Android, Hermes V1 (`260318099.0.4`) is always on and **has no
  `WebAssembly` global**: `typeof WebAssembly === 'undefined'`, and `@serenity-kit/opaque` fails to
  load. Proposed: "Hermes (React Native 0.88, Android) exposes no WebAssembly; option 1 is not
  available."
- **cryptographic-design.md §1** says "Mobile uses `react-native-libsodium`". Proposed: "Mobile uses
  native libsodium through `react-native-libsodium` for Argon2id, BLAKE2b, `crypto_kdf`, Ed25519,
  X25519 sealed boxes and the CSPRNG, and `@noble/ciphers` / `@noble/hashes` (the repository's
  reference implementation, pinned) for XChaCha20-Poly1305, SHA-256 and constant-time comparison,
  because `react-native-libsodium` 1.7.0 accepts AEAD additional data only as text and exposes no
  `crypto_hash_sha256` or `sodium_memcmp`." The provisional vectors and every portable check pass
  over this combination on the device.
- **D-05** (open-decisions.md): record the owner's choice of option 2 (SC-7) and that it is
  implemented for development, unreviewed.
- **D-26 / D-03:** first phone-class measurement: profile 1 (64 MiB, t = 3, p = 1) takes
  0.19-0.36 s natively on the arm64 emulator. An emulator on an Apple-silicon host is not a phone;
  the reference devices are still unmeasured.

## SC-6: root `.prettierignore` (committed, `f4c178a`)

Root `pnpm format:check` runs Prettier over the whole tree. The mobile npm lockfiles are written by
npm in a layout Prettier rewrites, and the Android and Rust build outputs contain JSON. Added, as
for `tools/crypto-validation`: `apps/mobile/*/package-lock.json`,
`apps/mobile/app/android/app/build`, `apps/mobile/app/android/build`,
`apps/mobile/app/native/opaque/target`, `/.mobile-toolchain`.

## SC-7: D-05, the native OPAQUE binding (implemented in `59bfb0f`, unreviewed)

The owner chose option 2 of authentication.md §2.3 on 2026-10-27 after the Stage 1 evidence.
`apps/mobile/app/native/opaque` is a Rust crate binding `opaque-ke` 4.0.1 (the version in
@serenity-kit/opaque 1.1.0) with exactly that package's client configuration, exposed to the app
through JNI and a synchronous React Native module, so the engine's `OpaqueClient` is unchanged.

- Host interoperability against `@serenity-kit/opaque` 1.1.0's Node build: 13/13 checks
  (`apps/mobile/app/scripts/opaque-interop.mjs`): binding-registered records log in through the
  web client and vice versa, including a non-ASCII password outside the BMP; wrong password,
  substituted server setup, tampered response and malformed input are refused.
- Device: logins against the real API in the E2E suite.
- **Needs independent review (D-19)** with the rest of mobile: the binding is Ruvee-maintained
  code (about 250 lines of Rust and Kotlin), not covered by any audit.
- iOS needs the same crate built as an XCFramework with a Swift module; not done (no Xcode).
