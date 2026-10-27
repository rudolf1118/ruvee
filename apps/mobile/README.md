# Ruvee mobile (development build)

The React Native client (Phase 6). **Development build: synthetic data only, not reviewed (D-19).**
Android runs on an emulator; iOS is not built (no Xcode on the development machine). System
autofill (iOS Credential Provider, Android Autofill) is a later milestone and is not here.

Status, platform results and blockers: [docs/mobile/implementation-status.md](../../docs/mobile/implementation-status.md).
How to build, run and test: [docs/mobile/testing.md](../../docs/mobile/testing.md).

| Path                 | Contents                                                                                                                                                                                                            |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `app/`               | The React Native 0.88 app (TypeScript, Hermes). Its own npm lockfile; not part of the pnpm workspace. Uses `packages/vault`, `packages/crypto` and `packages/contracts` from their sources through Metro, unchanged |
| `app/src/crypto/`    | Ruvee's `RawPrimitives` over native libsodium and noble, the startup known-answer test, and the OPAQUE client over the native binding                                                                               |
| `app/src/storage/`   | The device store: SQLite for envelopes, the Keystore for `SK`                                                                                                                                                       |
| `app/src/platform/`  | Randomness, the Keystore-backed secure store, the token transport, the server-address rule                                                                                                                          |
| `app/src/vault/`     | The shared engine with the mobile adapters, and the app's lock and lifecycle state machine                                                                                                                          |
| `app/src/ui/`        | Screens: server, log in, pairing, unlock, items, item, editor                                                                                                                                                       |
| `app/src/compat/`    | The Stage 1 compatibility runner (development builds only)                                                                                                                                                          |
| `app/native/opaque/` | Rust: the JNI binding of `opaque-ke` 4.0.1 with the D-02 configuration (D-05)                                                                                                                                       |
| `app/android/`       | The Android project: network security configs, backup exclusion, `FLAG_SECURE` in release, the OPAQUE module                                                                                                        |
| `app/ios/`           | The iOS project from the React Native template, renamed. **Never built**                                                                                                                                            |
| `e2e/`               | Appium + WebdriverIO + Playwright suite against a real API and a throwaway database. Its own lockfile                                                                                                               |
