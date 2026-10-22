# Device enrollment

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed, not implemented.

A device is **enrolled** when it holds the Secret Key `SK` and can therefore unlock the vault
with the master password. Logging in does not enroll a device: a server session never grants
decryption ([INV-06](security-invariants.md)). There are exactly three ways a device obtains
`SK`:

1. It created the account (first device).
2. An enrolled, unlocked device transferred `SK` through pairing (section 3).
3. The user entered the Recovery Key (section 4).

Key definitions are in [cryptographic-design.md](cryptographic-design.md). Endpoints are listed
in [api-design.md](../architecture/api-design.md#devices-and-pairing). The design is recorded in
[ADR-0005](../adr/0005-device-pairing.md).

## 1. Device records

Each client installation is one device with its own random `device_id`. A web browser profile,
the extension in the same browser, and each mobile app are separate devices.

| State     | Meaning                      | Allowed                                                                                  |
| --------- | ---------------------------- | ---------------------------------------------------------------------------------------- |
| `pending` | Logged in, but not enrolled. | Reading its own device record, making pairing requests, starting recovery. Nothing else. |
| `active`  | Enrolled.                    | Everything its session allows.                                                           |
| `revoked` | Revoked by the user.         | Nothing. Every request returns `401` with the code `device_revoked`.                     |

The server records platform (`web`, `extension`, `ios`, `android`), enrollment method, which
device approved it, timestamps and status. The user-chosen name is stored encrypted
(`DEVICE_LABEL`). A pending device's encrypted-data endpoints return `403`, which is a
second line of defense. Encrypted data alone would not let it decrypt anything.

## 2. First device (account creation)

This is part of the account bootstrap in
[authentication.md §3](authentication.md#3-account-bootstrap). On the first device, the client:

1. Generates `account_id`, `device_id`, `SK`, `AK` (with `ak_id`, `ak_epoch` = 1), `VK` (with
   `vk_id`), `RK` (with `recovery_key_id`) and `salt_pw`, all from the CSPRNG.
2. Derives `PwK`, `AUK`, `RWK` and `RAK`.
3. Builds `AK_WRAP_PASSWORD`, `AK_WRAP_RECOVERY` and `KEYSET` (`keyset_version` = 1).
4. Shows the Recovery Kit and requires the user to confirm the Recovery Key
   ([account-recovery.md](account-recovery.md#2-creating-the-recovery-kit)).
5. Sends the OPAQUE registration record together with the wraps, keyset, `SHA-256(RAK)`, KDF
   profile and salt, and its device record.
6. Stores locally: `SK`, the `AK_WRAP_PASSWORD` copy, salt and profile, ids, the server's
   OPAQUE public key pin and `instance_id`.
7. Creates the vault and its first manifest in Phase 3; see
   [sync-protocol.md](../architecture/sync-protocol.md).

## 3. Adding a device by pairing

Device **A** is enrolled and unlocked. Device **B** is new. The user has both in front of them.

### 3.1 Values

```
S          = randombytes_buf(16)                                      // pairing secret, generated on A
code       = "PC1-" ‖ CrockfordBase32(S ‖ H("ruvee/v1/pc-check" ‖ S)[0..2])   // 29 characters, typed or scanned into B
pairing_id = MAC(S, "ruvee/v1/pairing-id")[0..16]                     // routing id given to the server
K_pair     = MAC(S, "ruvee/v1/pairing-mac" ‖ account_id)
```

`H` and `MAC` are as defined in [cryptographic-design.md §2](cryptographic-design.md#2-notation-and-encodings).
The server learns `pairing_id` but not `S`; it cannot recover `S` from `pairing_id`.

### 3.2 Steps

| Step | Where | Action                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| ---- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1    | B     | The user logs in with username and password (OPAQUE). B's device record is `pending`. B keeps `P` in its crypto worker for at most 10 minutes for step 9, or asks for it again.                                                                                                                                                                                                                                                                                                                                                                                                                           |
| 2    | A     | The user chooses **Add a device**. A generates `S`, computes `pairing_id` and calls `POST /api/v1/pairings { pairingId }`. The server records it for A's account, with a 10-minute expiry.                                                                                                                                                                                                                                                                                                                                                                                                                |
| 3    | A     | A shows the code as text and as a QR code. The QR content is the code itself, not a URL, so it is never fetched or logged.                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| 4    | B     | The user types or scans the code. B checks the checksum, derives `S`, `pairing_id` and `K_pair`, and generates an ephemeral X25519 key pair with `crypto_box_keypair`.                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| 5    | B     | `req_mac = MAC(K_pair, "ruvee/v1/pair-req" ‖ pairing_id ‖ device_id_B ‖ u8(platform_B) ‖ epk_B)`. B calls `POST /api/v1/pairings/{pairingId}/request { epk, platform, mac }`. The server checks that B's session is on the same account and that B is `pending`, then stores the request. B sends no device name, because the server must not see names in plaintext.                                                                                                                                                                                                                                     |
| 6    | A     | A receives the request through SSE or polling. It **verifies `req_mac`** in constant time. If verification fails, A aborts, shows "This request did not come from the device you are pairing", and records a security event.                                                                                                                                                                                                                                                                                                                                                                              |
| 7    | A     | A shows **"Approve a new &lt;platform&gt; device?"**. The platform is covered by the MAC, so the server cannot change it. The user names the device on A, with a default such as "Web browser". The user approves.                                                                                                                                                                                                                                                                                                                                                                                        |
| 8    | A     | `payload` (JSON): `{ v: 1, accountId, deviceId: device_id_B, secretKey: SK, checkpoint: { vaultId, seq, manifestHash, keysetVersion }, opaqueServerPublicKey, instanceId }`. `ct = crypto_box_seal(payload, epk_B)`. `resp_mac = MAC(K_pair, "ruvee/v1/pair-resp" ‖ pairing_id ‖ device_id_B ‖ epk_B ‖ ct)`. A calls `POST /api/v1/pairings/{pairingId}/approve { ciphertext: ct, mac: resp_mac, label }` (A's active session), where `label` is the name encrypted as a `DEVICE_LABEL` envelope. The server marks B `active`, with `enrolled_via = pairing` and `approved_by = A`, and stores the label. |
| 9    | B     | B fetches the reply and **verifies `resp_mac`**, opens the sealed box with `esk_B`, and checks that `accountId` and `deviceId` are its own. It then fetches the account key material, derives `AUK` from `P` and `SK`, unwraps `AK`, decrypts the keyset, and checks that `keyset.secretKey` equals the received `SK`.                                                                                                                                                                                                                                                                                    |
| 10   | B     | B stores `SK`, its wrap copy, the server public-key pin and the **checkpoint**. The checkpoint lets B detect rollback from its first sync ([sync-protocol.md](../architecture/sync-protocol.md#checkpoints)). B zeroes `esk_B`, `S` and `K_pair`, then calls `POST /api/v1/pairings/{pairingId}/complete`. The server deletes the pairing.                                                                                                                                                                                                                                                                |

Pairings expire after 10 minutes, can be used once, and are limited to 3 open per account
([authentication.md §7](authentication.md#7-rate-limiting-and-brute-force-protection)). Either
device can cancel.

### 3.3 Why the server cannot substitute keys

| Attack by the server                                                                                     | Why it fails                                                                                                |
| -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------- |
| Give A its own public key instead of `epk_B`, so that A seals `SK` to the server                         | `req_mac` covers `epk_B` and needs `K_pair`, which needs `S`. `S` is only on A's screen and in B.           |
| Send B a payload it made itself (a fake `SK`, to make B encrypt future data under keys the server knows) | `resp_mac` covers the ciphertext. B also checks the received `SK` against the keyset it decrypts with `AK`. |
| Show A a misleading device type                                                                          | The platform is inside `req_mac`, and the name is chosen on A.                                              |
| Guess `S`, or derive it from `pairing_id`                                                                | `S` is 128 bits of CSPRNG output, and `pairing_id` is a keyed one-way function of it.                       |
| Replay an old pairing                                                                                    | Every pairing uses a fresh `S`, `pairing_id` and ephemeral key. Pairing records are single-use and expire.  |

What is **not** prevented:

- **The user typing the code into the wrong device.** Someone who sees A's screen and also has
  the master password could pair their own device. The approval screen (step 7) is the defense.
- **A compromised device A or B.** Enrollment assumes both endpoints are trusted
  ([threat-model.md §7](threat-model.md#7-assumptions)).
- **A malicious web app on B.** If B is the web app, a malicious server can serve code that
  captures `SK` after it arrives ([threat-model.md §6](threat-model.md#6-the-web-client-delivery-problem)).
  Pairing protects the key exchange, not the code running at either end.

### 3.4 Alternatives considered

- **Short numeric code with a PAKE (CPace or SPAKE2).** This would allow a 6–8 digit code
  instead of 29 characters. It was rejected for V1 because there is no maintained, audited
  JavaScript and React Native implementation in the selected libraries, and Ruvee must not
  implement one. It may be revisited later.
- **Comparing a key fingerprint instead of typing a secret.** This relies on users carefully
  comparing strings, which is unreliable, and it still needs an authenticated channel for the
  reply.
- **Enrolling with the password alone**, which stores a password-only wrap of `AK` on the server.
  That makes database theft (T-01) an offline-guessing attack. Rejected in
  [ADR-0003](../adr/0003-two-secret-key-derivation.md).

## 4. Adding a device with the Recovery Key

If no enrolled device is available, a new device can enroll by entering the Recovery Key. This
also covers losing every device. The flow is part of recovery because it gives access to
everything: [account-recovery.md §3](account-recovery.md#3-recovery-with-the-recovery-key). The
resulting device has no trusted checkpoint
([sync-protocol.md §Limits](../architecture/sync-protocol.md#limits)).

## 5. Where `SK` is stored on each platform

| Platform                    | Storage                                                                                                       | Protection at rest                                                                                                                                                                                                                                                                                               |
| --------------------------- | ------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Web app (Phase 2)           | IndexedDB in the web app's origin, along with the wrap copy and ids.                                          | **Only the browser profile and OS account protect it.** The web platform has no OS-protected key store. Script in the same origin (XSS) can read it ([T-19](threat-model.md#5-threats-and-outcomes)). This is recorded as a deviation from "use OS-protected secure storage where available": none is available. |
| Browser extension (Phase 5) | IndexedDB in the extension's origin. Not `chrome.storage.local`, which content scripts can access by default. | The same as web. Web pages and content scripts cannot reach the extension origin's IndexedDB.                                                                                                                                                                                                                    |
| iOS (Phase 6)               | Keychain item with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.                                            | OS data protection. "ThisDeviceOnly" keeps it out of backups and transfers, so a restored phone must re-enroll.                                                                                                                                                                                                  |
| Android (Phase 6)           | Encrypted with a non-exportable Android Keystore key. The app's storage is excluded from backups.             | Keystore (TEE or StrongBox where available). A restored phone must re-enroll.                                                                                                                                                                                                                                    |

`SK` is never stored in `localStorage`, `sessionStorage`, cookies, URLs or synced browser
storage. Biometric unlock (Phase 6) adds a separate OS-protected key that wraps `AK` locally. It
does not replace `SK`, and it is outside V1.

## 6. Revocation and its limits

The user revokes a device from another active device. This requires step-up
([INV-14](security-invariants.md)).

1. The server sets the device to `revoked`, revokes all its sessions, cancels any open pairing,
   and records a security event.
2. If the revoked device comes online, every request returns `401 device_revoked`. A
   well-behaved client then wipes its local store: `SK`, wraps, encrypted cache and pending
   changes. It shows that it was removed and that unsynced edits from it are lost. The revoke
   screen warns about this in advance and shows when the device last synced.
3. Before revoking, the user chooses whether the device is merely retired or **lost or possibly
   compromised**. For the second case, the client continues with steps 4 and 5.
4. Change the master password ([authentication.md §9](authentication.md#9-password-change)).
5. Rotate keys fully, once that exists (Phase 4;
   [cryptographic-design.md §6.3](cryptographic-design.md#63-full-rotation-new-ak-vk-and-every-ik)),
   and change the important passwords stored in the vault.

What revocation **cannot** do:

- **Reach an offline device.** It learns about the revocation only when it next connects. Until
  then it keeps unlocking its local copy with the password it knows.
- **Erase a compromised device.** It can ignore the wipe. It holds `SK`, a wrap of `AK` and every
  record it downloaded. With the password, or a successful offline guess, it can decrypt all of
  it, permanently.
- **Undo past decryption.** Anything already decrypted, copied or photographed stays exposed.
- **Protect future data without rotation.** If the device ever unlocked, it may hold `AK`.
  Only full rotation makes data written after the rotation unreadable to it.

The user-facing text must say this, and must not describe revocation as erasing data.
