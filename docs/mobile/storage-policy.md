# Mobile storage and lifecycle policy

Status: **development build, not reviewed** (D-19). Android only; iOS is designed below but not
built or run. Synthetic data only.

This applies [device-enrollment.md §5](../security/device-enrollment.md#5-where-sk-is-stored-on-each-platform),
[sync-protocol.md §12 and §Memory and lock](../architecture/sync-protocol.md#12-local-storage) and
[authentication.md §5](../security/authentication.md) to the React Native app in `apps/mobile/app`.
Nothing here changes a key, a format or a protocol.

## 1. What is stored where

| Data                                                                                       | Where                                                                                    | Protection at rest                                                                                                                                              |
| ------------------------------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SK` (Secret Key)                                                                          | Secure store item `sk.<random>` (`src/platform/secure-store.ts`)                         | Android: AES-256-GCM key generated in AndroidKeyStore (StrongBox tried first), non-exportable; only ciphertext is written, to the app's private DataStore file. |
| Refresh token (rotating, 30 days idle)                                                     | Secure store item `refresh-token`                                                        | As `SK`. It decrypts nothing (INV-06).                                                                                                                          |
| Access token (10 minutes)                                                                  | Process memory only                                                                      | Gone with the process; a restart refreshes it.                                                                                                                  |
| Device record: ids, username, KDF profile and salt, password wrap of `AK`, keyset envelope | SQLite `ruvee-device.sqlite`, table `kv`, store `device` (`src/storage/device-store.ts`) | The wrap and keyset are AEAD envelopes (`AK` under the password and `SK`); ids and username are not secret (same as the web's IndexedDB).                       |
| Item records, manifest, `LOCAL_RECORD` envelopes (checkpoint, pending queue, conflicts)    | SQLite, stores `records`, `meta`, `local`, `imports`                                     | Exactly the envelopes the web stores; never plaintext (INV-16).                                                                                                 |
| Server address                                                                             | SQLite, store `settings`                                                                 | Not secret.                                                                                                                                                     |
| `AK`, `VK`, `K_local`, `DSK`, item keys, decrypted items, the search filter                | Process memory, inside the engine (`packages/vault`), only while unlocked                | Zeroed on lock (`wipeMemory`, INV-15); never written anywhere.                                                                                                  |

- **No other persistent storage** is used: no AsyncStorage, no MMKV, no files of our own, no
  clipboard. Copying a password is not built.
- **SQLite** runs with `secure_delete = ON` and WAL; after a revocation wipe the WAL is
  checkpointed and truncated so no earlier page version remains. The database file is not
  encrypted again as a whole: everything confidential in it is already an authenticated envelope.
- **Backups and device transfer:** `allowBackup="false"`, `fullBackupContent="false"` and
  `dataExtractionRules` excluding every domain from cloud backup and from device-to-device transfer
  (Android 12+ ignores `allowBackup` for transfer). A restored or migrated phone therefore has no
  `SK` and must be enrolled again, as device-enrollment.md §5 requires.
- **Keystore is not assumed to be hardware.** The app records what Android reports for its key
  (`KeyInfo.isInsideSecureHardware`, through react-native-keychain's `getSecurityLevel`); the
  Stage 1 runner prints it. An emulator's Keystore is software. Nothing in Ruvee's claims depends on
  hardware backing: `SK` alone decrypts nothing (INV-17); it is defence in depth against copying the
  app's files.
- **Strings cannot be zeroed in JavaScript.** `SK` and the refresh token pass through the JS heap as
  base64 strings while they are read or written; passwords typed into the UI are JS strings. This is
  the same class of exposure as the web, where `SK` is read from IndexedDB into the worker.

### iOS (designed, not built or run here)

`react-native-keychain` with `ACCESSIBLE.WHEN_UNLOCKED_THIS_DEVICE_ONLY` gives the Keychain class
device-enrollment.md §5 names (`kSecAttrAccessibleWhenUnlockedThisDeviceOnly`); the SQLite file
needs `NSFileProtectionComplete` and exclusion from iCloud backup (`isExcludedFromBackup`). Neither
is implemented or tested: there is no Xcode on the development machine.

## 2. Lock and lifecycle

| Event                                     | What happens                                                                                                                       |
| ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| User taps **Lock**                        | `engine.wipeMemory()`: every key buffer zeroed, decrypted items dropped (INV-15). The UI drops its item list.                      |
| App goes to the background (`background`) | Locks at once. During pairing it also drops the pairing (the password kept for it goes with the lock).                             |
| `inactive` (system dialog, app switcher)  | The vault is covered by an opaque view; not locked.                                                                                |
| 15 minutes without a touch (D-10)         | Locks.                                                                                                                             |
| Process killed (by the OS or the user)    | Every key was only in memory; the next start is locked. The refresh token survives, so unlocking does not need a new OPAQUE login. |
| Session ends (`ended: session_expired`)   | Locks; unlocking signs in again (OPAQUE with the device proof).                                                                    |
| Device revoked (`ended: device_revoked`)  | The engine wipes the store (SQLite rows, `SK` items); the app forgets the tokens and shows "This device was removed".              |
| Logout                                    | Ends the server session, forgets the tokens, locks. The encrypted local copy stays (as the web).                                   |
| Release builds                            | `FLAG_SECURE`: no screenshots, recordings or recent-apps thumbnail. Debug builds allow them so tests can capture the screen.       |

**Biometric unlock is not built** (D-11 is open and device-enrollment.md §5 places it outside V1).
When it is, it must wrap `AK` under a separate user-authentication-bound Keystore key and never
bypass the master-password derivation for anything else; it must not store `AK` or a password
in a form that unlocks without the OS check.

## 3. Network

- Release and every non-debug build: HTTPS only, system CAs only (no user CAs), no cleartext
  (`res/xml/network_security_config.xml`). TLS verification is never disabled.
- Debug builds only (`src/debug/res/xml/network_security_config.xml`): cleartext to `127.0.0.1`,
  `localhost` and `10.0.2.2` (the emulator's alias for the host loopback), for Metro and the local
  test server. The server-address screen accepts `http://` only for `127.0.0.1` or `localhost` and
  only when `__DEV__`.
- Requests use bearer tokens with `credentials: 'omit'`; `Origin` is set to the configured server
  origin on requests to that server's API (shared-change request SC-3).

## 4. Other apps that can read the screen

- **Autofill:** the editor's item fields are marked `importantForAutofill="no"`, so the system
  Autofill service (Google's, or another password manager's) is not offered an item's username or
  password to save. The sign-in and unlock fields keep the platform default. Android still opens an
  Autofill session for the activity (seen in logcat on the emulator).
- **Accessibility services** can read any text on screen, including a password after "Reveal". This
  is how the Android platform works and how the E2E driver reads the screen; Ruvee cannot prevent
  it for a service the user enabled. Passwords are shown only on request and hidden again on lock.
- **Screenshots and the recent-apps thumbnail:** blocked in release builds (`FLAG_SECURE`); while
  `inactive`, the vault is covered.

## 5. Logging

The app logs no secrets: no password, key, token, Recovery Key, pairing code or item content is
passed to `console.*`. The development compatibility runner logs only check ids, timings and error
names. The E2E suite scans every logcat buffer, every file in the app's data directory and the
server's output for the synthetic secrets it uses (`apps/mobile/e2e/tests/mobile-vault.test.ts`);
it excludes only the test instrumentation's own lines, identified by its Android UID.
