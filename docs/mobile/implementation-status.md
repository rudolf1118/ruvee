# Mobile implementation status

Updated 2026-10-27. **Development build, synthetic data only, not reviewed.** D-19 (independent
review) is open and is **not** complete; nothing here makes Ruvee ready for real data.

## 1. Where the work is

| Item          | Value                                                                                                                                                                                                                           |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Branch        | `mobile/vault-app` (local only; nothing pushed, merged, published or deployed)                                                                                                                                                  |
| Worktree      | `../ruvee-mobile` next to the main checkout                                                                                                                                                                                     |
| Base commit   | `e0a8586356696f7b8fabee7544369da408df5556` (`vault/web-vault`, "docs(review): §13 legacy-account hardening and device names; checklist at d04e211", 2026-10-27 17:21 +0400)                                                     |
| Parallel work | The security-review session continues on `vault/web-vault` in the main checkout. None of its later or uncommitted work is on this branch. **Tests here validate the base commit plus this branch, not later security changes.** |

Commits on the branch, in order (local only):

| Commit    | What                                                                                        |
| --------- | ------------------------------------------------------------------------------------------- |
| `b3effd3` | SC-1: `ios` and `android` as login and pairing platforms (contracts, API type, engine type) |
| `f4c178a` | SC-6: root `.prettierignore` entries for mobile lockfiles and build output                  |
| `59bfb0f` | The native OPAQUE binding (`apps/mobile/app/native/opaque`) and its host interop test       |
| `6db0f35` | The React Native app: adapters, Stage 1 runner, storage, lifecycle, screens                 |
| `cbd0cea` | The end-to-end suite (`apps/mobile/e2e`)                                                    |
| (this)    | `docs/mobile`                                                                               |

## 2. What exists, by evidence level

Levels: **Implemented** (code exists) · **Emulator** (tested on the Android Emulator) · **Hardware**
(tested on a physical phone) · **Unverified**.

| Area                                                                         | Level                                                                                                      | Notes                                                                                                                                                                 |
| ---------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Argon2id, XChaCha20-Poly1305, BLAKE2b, `crypto_kdf`, Ed25519, X25519, CSPRNG | Emulator                                                                                                   | Native libsodium + noble; every portable check of `packages/crypto` and the committed vectors pass on the device ([native-compatibility.md](native-compatibility.md)) |
| Hermes WebAssembly (D-05 option 1)                                           | Emulator: **absent**                                                                                       | No `WebAssembly` global in Hermes 260318099.0.4 (RN 0.88)                                                                                                             |
| OPAQUE (D-02) through a native `opaque-ke` 4.0.1 binding (D-05 option 2)     | Emulator + host interop                                                                                    | Host: 13/13 against @serenity-kit/opaque 1.1.0. Device: logins against the real API in E2E                                                                            |
| D-31 device proof                                                            | Emulator                                                                                                   | Sign/verify on device; proven sessions against the real API (login with proof, session proof after pairing and after a password change)                               |
| Server address (HTTPS; loopback HTTP in debug only)                          | Emulator                                                                                                   |                                                                                                                                                                       |
| Enrollment by pairing (device B, existing 128-bit code)                      | Emulator                                                                                                   | The web approves "a new Android device"                                                                                                                               |
| Enrollment by recovery on the phone                                          | **Not built**                                                                                              | The API's recovery is web-only (`webPlatformSchema`); changing it was out of scope                                                                                    |
| Unlock, lock, wrong password                                                 | Emulator                                                                                                   |                                                                                                                                                                       |
| Logins and secure notes: list, search, view, reveal, create, edit            | Emulator                                                                                                   | Trash, favorites, tags, copy to clipboard, the generator: not built                                                                                                   |
| Sync with the web, both directions                                           | Emulator                                                                                                   |                                                                                                                                                                       |
| Offline edits, kept across a process restart                                 | Emulator                                                                                                   |                                                                                                                                                                       |
| Conflicts (keep mine / theirs / both)                                        | Emulator (keep mine)                                                                                       |                                                                                                                                                                       |
| Lifecycle: background lock, idle lock, process death, session end            | Emulator (background, process death, session end after password change); idle lock implemented, not tested |                                                                                                                                                                       |
| Password changed on another device with a pending edit                       | Emulator                                                                                                   |                                                                                                                                                                       |
| Revocation                                                                   | Emulator                                                                                                   | Local copy erased at the next request                                                                                                                                 |
| Logout                                                                       | Implemented                                                                                                | Not exercised by the E2E suite                                                                                                                                        |
| SQLite store (envelopes only), `SK` and refresh token in Keystore            | Emulator                                                                                                   | Android reports `secure_software` on the emulator: not hardware-backed                                                                                                |
| Backup and device-transfer exclusion                                         | Implemented                                                                                                | Manifest and rules only; not tested with a real backup                                                                                                                |
| `FLAG_SECURE`, no cleartext, system CAs only (release)                       | Implemented                                                                                                | No release build was run                                                                                                                                              |
| Biometric unlock                                                             | **Not built**                                                                                              | D-11 open; outside V1 per device-enrollment.md §5                                                                                                                     |
| iOS (Keychain, Swift module for the OPAQUE binding)                          | **Unverified**                                                                                             | Template project renamed only; nothing built (no Xcode)                                                                                                               |
| System autofill (Android Autofill, iOS Credential Provider)                  | **Not built**                                                                                              | Later milestone                                                                                                                                                       |
| Any physical device, biometric hardware, StrongBox/TEE                       | **Not tested**                                                                                             |                                                                                                                                                                       |

## 3. Test results

All local, 2026-10-27, on branch `mobile/vault-app` at the commits listed in §1 and below.
Emulator: task-owned AVD `ruvee-task-mobile` (Android 16, API 36.1 Google APIs image, arm64-v8a)
on an Apple-silicon Mac; debug build with Metro. **Nothing was run on a phone, and nothing on iOS.**

| Check                                                                                                                                         | Where                          | Result                                                                                                         |
| --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------ | -------------------------------------------------------------------------------------------------------------- |
| Stage 1 compatibility runner (`scripts/compat-run.sh`)                                                                                        | Emulator                       | **37/39 pass**; the 2 failures are the expected evidence (no WebAssembly, so @serenity-kit/opaque cannot load) |
| Keystore probe in the runner                                                                                                                  | Emulator                       | Round trip and removal pass; Android reports the AES-GCM key as **`secure_software`** (not hardware)           |
| OPAQUE binding unit test (`cargo test`)                                                                                                       | Host                           | Pass                                                                                                           |
| OPAQUE interop with @serenity-kit/opaque 1.1.0 (`scripts/opaque-interop.mjs`)                                                                 | Host                           | **13/13**                                                                                                      |
| End-to-end suite (`apps/mobile/e2e`, 12 steps)                                                                                                | Emulator + real API + Chromium | **12/12, twice in a row** (about 85 s per run); no `ruvee_e2e_*` database left behind                          |
| App type-check (`npx tsc --noEmit`, includes the shared sources it bundles)                                                                   | Host                           | Pass                                                                                                           |
| E2E harness type-check                                                                                                                        | Host                           | Pass                                                                                                           |
| SC-1 in the shared packages: contracts tests (42), API unit tests (84), vault tests (97, 1 skipped); type-check of API, vault, web, extension | Host                           | Pass                                                                                                           |
| Root `pnpm format:check` (whole tree, with SC-6)                                                                                              | Host                           | Pass                                                                                                           |
| Root `pnpm lint`, `pnpm typecheck`, `pnpm test`                                                                                               | —                              | Not run in full; the mobile packages are outside the pnpm workspace and SC-1's packages were checked as above  |
| API integration tests, web Playwright suites, extension suite                                                                                 | —                              | **Not run** on this branch                                                                                     |

E2E steps, each against the real API, database and web app:

1. Web: account setup with the Recovery Kit check, a login and a secure note.
2. Phone: a plain-HTTP non-loopback address refused; a wrong master password refused; login as a
   new pending device (native OPAQUE against the Node server).
3. Pairing: code shown on the web, typed on the phone, approved on the web as "a new Android
   device"; the phone's session proven with its device key (D-31); both items arrive.
4. Web → phone: fields shown; the password hidden until "Reveal".
5. Phone → web: a login created and a note renamed on the phone appear on the web, with the
   password the phone set.
6. Lock: lock button; wrong password refused; unlock.
7. Lifecycle: home button locks ("left the screen"); a killed process starts locked and unlocks.
8. Offline: an edit made with the network cut is pending, survives a process restart, and syncs
   when the network returns.
9. Conflict: the same item changed offline on the phone and on the web; the phone shows the
   conflict and keeps its version; the web receives it.
10. Password changed on the web while the phone holds an unsynced edit: the old password still
    opens the local copy but cannot sign in (notice shown); the new password moves the phone over
    with its own `SK` (session proof) and the pending edit syncs.
11. No synthetic secret (master passwords, item passwords, note text, Recovery Key, pairing code)
    in any logcat buffer, in any file of the app's data directory (SQLite, WAL, DataStore, caches)
    or in the API and web server output; no Secret Key in SQLite. The scan excludes the lines of
    the test instrumentation itself (Appium's UiAutomator2 server), which logs the screen text it
    reads back, revealed passwords included; it keeps every app and system line.
12. Revocation: the web removes the phone; the phone's next request erases its local copy and it
    starts at sign-in again.

Bugs found and fixed by these runs: React Native's fetch adds `_=<time>` to GET URLs for
`cache: 'no-store'`, which the API's strict query schemas refuse (sync failed as "offline"); a
token refresh that failed for lack of network deleted the refresh token, so going offline became a
logout ("session ended" at the next request).

Not covered by any test: idle lock after 15 minutes, logout, "keep theirs" and "keep both",
release builds, backups, biometrics, iOS, a physical phone.

## 4. Dependencies

Exact pins; provenance and audit status in [native-compatibility.md §4](native-compatibility.md#4-dependency-provenance).

| Where         | Dependencies                                                                                                                                                                                                                                                                                                                                                                                                          |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app` runtime | react-native 0.88.0, react 19.3.0, react-native-libsodium 1.7.0, @noble/ciphers 2.4.0, @noble/hashes 2.4.0, react-native-keychain 10.0.0, @op-engineering/op-sqlite 19.0.1, zod 4.6.7, @serenity-kit/opaque 1.1.0 (compatibility runner and host interop only; it cannot load on Hermes), libsodium-wrappers-sumo / libsodium-sumo 0.8.4 (compatibility runner only; replaced by a throwing module in the app bundle) |
| `app` native  | Rust: opaque-ke 4.0.1, argon2 0.5.3, sha2 0.10.9, rand_core 0.6.4, base64 0.22.1, zeroize 1.8.2, jni 0.21.1 (`Cargo.lock` committed)                                                                                                                                                                                                                                                                                  |
| `app` build   | @react-native/* 0.88.0, @react-native-community/cli 20.2.0, Babel 7.29, TypeScript 6.0.3, Gradle 9.4.1, NDK 27.1.12297006, CMake 3.22.1, Rust 1.99.1                                                                                                                                                                                                                                                                  |
| `e2e`         | appium 3.8.0, appium-uiautomator2-driver 8.7.0, webdriverio 10.0.2, playwright-core 1.64.1, pg 8.23.1                                                                                                                                                                                                                                                                                                                 |

## 5. Blockers and limits

- **iOS:** no Xcode and about 12-18 GB free disk on the development machine; nothing iOS was built.
- **No physical device:** every result is from the emulator.
- **Recovery on the phone:** not possible without an API change (recovery accepts only `web`).
- **Release build** not exercised (`FLAG_SECURE`, no cleartext, bundled Hermes bytecode).
- **The OPAQUE binding and the mobile primitive composition are unreviewed** Ruvee code (D-19).
- **E2E runs a debug build with Metro;** a release-like E2E build type is future work.

## 6. Shared-change requests

[shared-change-requests.md](shared-change-requests.md): SC-1 (committed, owner-approved),
SC-2 to SC-5 (proposed), SC-6 (committed, formatting ignores), SC-7 (D-05 resolution).

## 7. Commands

[testing.md](testing.md).
