# Threat model

Status: **Proposed (Phase 0).** Not owner-approved and not independently reviewed. It describes
the design, not shipped behavior. Nothing described here is implemented yet.

Scope: V1 is one user with one personal vault on several devices. Clients ship in this order: web
app, browser extension (Chromium MV3), then iOS and Android. The server is self-hosted, preferably
reachable only over a private network (Tailscale or WireGuard). Shared vaults and passkeys are out
of scope. Mobile is in scope only where it constrains formats and protocols now.

Mechanisms are specified in the linked documents. This file names threats and says what the
design achieves against each one.

## 1. Assets

| Asset                                                             | Why it matters                                                                |
| ----------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Vault plaintext: item contents, titles, URLs, notes, TOTP secrets | The product's whole purpose. Disclosure is the worst outcome.                 |
| Master password                                                   | Unlocks every device; often reused or memorable.                              |
| Secret Key (`SK`), Account Key (`AK`), vault and item keys        | Each enables decryption with fewer or no further secrets.                     |
| Recovery Key (`RK`)                                               | On its own, decrypts the vault and resets account access.                     |
| Session tokens and refresh tokens                                 | Server access: download ciphertext, change or delete data, enroll devices.    |
| Integrity and freshness of vault data                             | A rolled-back or altered vault can reinstate an old password or hide an item. |
| Availability of the vault                                         | Losing access to all passwords is serious harm even without disclosure.       |
| Metadata: item count, sizes, timing, device list, IP addresses    | Reveals usage patterns. Not protected by encryption (section 4).              |

Key definitions are in [cryptographic-design.md](cryptographic-design.md#3-secrets-and-keys).

## 2. Attackers

| ID  | Attacker                                     | Capabilities assumed                                                                                                                       |
| --- | -------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| A1  | Network attacker                             | Observes and modifies traffic. Cannot break TLS unless the TLS deployment is misconfigured.                                                |
| A2  | Database thief                               | Has a copy of the PostgreSQL database or a database backup, but not server secrets kept outside the database.                              |
| A3  | Full server compromise or malicious operator | Controls the API process, database, configuration, OPAQUE server secret and **the web app code served to browsers**.                       |
| A4  | Holder of a stolen session                   | Has a valid session cookie or refresh token for the account, but no password, `SK` or keys.                                                |
| A5  | Malicious web page                           | Any site the user visits. Can run script in its own origin, frame other pages and craft deceptive forms. Relevant mostly to the extension. |
| A6  | XSS in the Ruvee web origin                  | Can run script in the Ruvee web app's origin.                                                                                              |
| A7  | Stolen or lost device, at rest               | Has the device's storage: browser profile, app sandbox and backups. Locked or powered off.                                                 |
| A8  | Compromised client device                    | Malware running as the user, a malicious browser extension, or physical access to an unlocked session.                                     |
| A9  | Revoked device                               | A device the user revoked, which still holds its local store and may come back online.                                                     |
| A10 | Supply-chain attacker                        | Compromises a dependency, build pipeline or extension or app distribution channel.                                                         |

## 3. Trust boundaries

```
 ┌──────────────── User's trusted device (each enrolled client) ───────────────────┐
 │  UI ── crypto worker (libsodium) ── local encrypted store                       │
 │  holds: P (briefly), SK, AK/VK/IK while unlocked                                │
 └──────────────┬───────────────────────────────────────────────────────▲─────────┘
                │ TLS (private network preferred)                       │ web app code (JS)
                ▼                                                       │ ← served by the server
 ┌──────────── Server (untrusted for confidentiality) ───────────────────┴─────────┐
 │  Caddy ── NestJS API ── PostgreSQL         OPAQUE server secret (outside DB)    │
 │  sees: ciphertext, metadata, OPAQUE records, session tokens (hashed)            │
 └─────────────────────────────────────────────────────────────────────────────────┘
 Browser only:  web pages and content scripts  ──(untrusted)──►  extension service worker
```

The boundaries are:

1. **Client and server.** The server is trusted for availability and for enforcing access
   control on ciphertext. It is **not** trusted for the confidentiality or integrity of vault
   contents. Integrity of vault data is checked by clients
   ([security invariants](security-invariants.md) INV-01 to INV-08).
2. **Web app code delivery.** The web client's code comes from the same server it should not
   have to trust. This boundary is broken by design for the web app (section 6).
3. **Web page and extension.** Content scripts run in pages the attacker may control. They are
   treated as untrusted and never hold keys or the vault (Phase 5 design constraint).
4. **UI and crypto worker** inside a client. A process boundary only on native platforms. In a
   browser it is a code-organization boundary, not a security boundary against XSS.
5. **Device at rest and device unlocked.** At rest, the local store is protected by the
   password-derived key and `SK`. While unlocked, keys are in memory.

## 4. What the server can see

Encryption does not hide these. The product must not describe them as protected.

| Data                                                                              | Visible to         | Notes                                                                                                             |
| --------------------------------------------------------------------------------- | ------------------ | ----------------------------------------------------------------------------------------------------------------- |
| Username                                                                          | Server             | Account identifier for login and recovery. Chosen by the user; it need not be an email address.                   |
| IP addresses, user agent, request times and sizes                                 | Server, Caddy logs | Inherent to HTTP. Logging policy minimizes retention ([api-design.md](../architecture/api-design.md#logging)).    |
| Number of items, record sizes (padded to 256 B), revision numbers                 | Server             | Reveals how many items exist and roughly how large they are.                                                      |
| When items change, and which device committed the change                          | Server             | Commit records include the device id.                                                                             |
| Tombstones: that an item id was permanently deleted, and when                     | Server             | Soft delete (Trash) is inside the ciphertext and is not visible.                                                  |
| Device list: ids, platform type, enrollment time, last seen, status               | Server             | Device **names** are encrypted (`DEVICE_LABEL`).                                                                  |
| Session count, times and expiry                                                   | Server             |                                                                                                                   |
| KDF profile id, password salt, `ak_epoch`, `keyset_version`, key ids              | Server             | Needed for clients to derive keys. Not secret.                                                                    |
| Security events: login failures, password change, recovery use, device enrollment | Server             | Stored so the user can review account activity.                                                                   |
| OPAQUE registration record and server static key                                  | Server             | Lets the server run OPAQUE. With the OPAQUE server secret, it allows offline password guessing (section 5, T-02). |

The server never sees `P`, `SK`, `AK`, `VK`, `IK`, `RK`, `RWK`, item plaintext (titles, URLs,
usernames, notes, tags, favorites, trash state) or device names
([INV-10](security-invariants.md)).

## 5. Threats and outcomes

Each threat is classified with one of these outcomes:

- **Mitigated:** the design prevents it, under the stated assumptions.
- **Detected:** the design does not prevent it but a client notices and warns.
- **Limited:** it is partly mitigated, and the residual risk is stated.
- **Out of scope:** not achievable by Ruvee's design. Stated so nobody assumes otherwise.

| ID   | Threat                                                                                                      | Attacker | Outcome                                 | Mechanism, or why not                                                                                                                                                                                                                                                                                                                    |
| ---- | ----------------------------------------------------------------------------------------------------------- | -------- | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T-01 | Database theft leads to decrypted vault                                                                     | A2       | Mitigated                               | Everything stored needs `SK` (password wrap), `RK` (recovery wrap) or vault keys. None are in the database, and none are guessable ([cryptographic design §3](cryptographic-design.md#3-secrets-and-keys), [ADR-0003](../adr/0003-two-secret-key-derivation.md)).                                                                        |
| T-02 | Database theft leads to offline guessing of the password                                                    | A2       | Mitigated                               | The OPAQUE record needs the OPAQUE server secret, which is kept outside the database and outside database backups ([authentication.md](authentication.md#server-secrets)). If the secret is also stolen, this becomes T-03.                                                                                                              |
| T-03 | Full server compromise leads to offline guessing of the password from OPAQUE data                           | A3       | Limited                                 | Each guess costs one OPAQUE Argon2id evaluation. A cracked password gives account **access** but not decryption, which still needs `SK`. A malicious server also has the stronger attack T-10.                                                                                                                                           |
| T-04 | Server reads vault contents from data it stores                                                             | A3       | Mitigated                               | Same as T-01. All vault content is client-encrypted.                                                                                                                                                                                                                                                                                     |
| T-05 | Server substitutes its own key during device enrollment                                                     | A3       | Mitigated                               | The new device's key and the reply are MACed with a pairing secret shown only on the existing device ([device-enrollment.md](device-enrollment.md#33-why-the-server-cannot-substitute-keys)).                                                                                                                                            |
| T-06 | Server alters ciphertext, moves it between items or revisions, or changes its purpose                       | A3       | Detected                                | AEAD with context in the AAD ([cryptographic design §4](cryptographic-design.md#4-encryption-envelope-format-version-1)). The client rejects the item and keeps its local copy.                                                                                                                                                          |
| T-07 | Server replays older ciphertext or rolls back the whole vault                                               | A3       | Detected (on devices with a checkpoint) | An authenticated manifest has a monotonic sequence number and a digest of every item, and each device keeps a checkpoint ([sync-protocol.md](../architecture/sync-protocol.md#rollback-and-deletion-detection)). **AEAD alone does not detect replay.**                                                                                  |
| T-08 | Server rolls back the vault for a device with no checkpoint (a fresh device restored from the Recovery Kit) | A3       | Limited                                 | That device cannot tell a consistent older state from the latest one. Devices enrolled by pairing receive the checkpoint from the existing device. Recovery shows the manifest's date and author device for the user to judge ([sync-protocol.md §Limits](../architecture/sync-protocol.md#limits)).                                     |
| T-09 | Server hides recent changes (freeze) or shows different devices different histories (fork)                  | A3       | Limited                                 | Within one device's view, any rollback below its checkpoint is detected. A freeze above the checkpoint, or a fork between devices that never compare checkpoints, is not detected. Comparing checkpoints is proposed for a later phase ([sync-protocol.md §Limits](../architecture/sync-protocol.md#limits)).                            |
| T-10 | **Server serves modified web app JavaScript** that captures the password, `SK` or plaintext                 | A3, A10  | Out of scope for the web app            | See section 6. No browser mechanism lets a web page verify the code it was served by its own origin. The extension and the mobile apps are not affected by this threat, but have their own supply-chain risk (T-21).                                                                                                                     |
| T-11 | Server deletes data or denies service                                                                       | A3       | Detected, not prevented                 | Devices keep encrypted local copies. Deletion of items is detected by the manifest digest. Restoration requires a backup or another device ([account-recovery.md](account-recovery.md#7-restoring-from-backups)).                                                                                                                        |
| T-12 | Stolen session reads the vault                                                                              | A4       | Mitigated                               | A session yields only ciphertext and metadata. Decryption needs `P` and `SK` ([authentication.md](authentication.md#8-what-a-stolen-session-can-and-cannot-do)).                                                                                                                                                                         |
| T-13 | Stolen session enrolls a device it controls                                                                 | A4       | Mitigated                               | Enrollment needs the pairing secret from an unlocked existing device, or the Recovery Key.                                                                                                                                                                                                                                               |
| T-14 | Stolen session damages or deletes data, revokes devices or changes the password                             | A4       | Limited                                 | Destructive and account-changing operations need fresh step-up authentication. Commits with bad data are detected by clients (T-06, T-07). An attacker can still delete server-side data within the commit API; local copies and backups remain.                                                                                         |
| T-15 | Online password guessing against the login endpoint                                                         | A1, A4   | Mitigated                               | Per-account and per-IP throttling, plus OPAQUE's per-guess client cost ([authentication.md](authentication.md#7-rate-limiting-and-brute-force-protection)). Private-network deployment removes internet exposure.                                                                                                                        |
| T-16 | Username enumeration                                                                                        | A1       | Limited                                 | Login returns OPAQUE fake responses for unknown users (RFC 9807 §10.9). Account registration is disabled after bootstrap, so it is not an oracle. Recovery start returns a generic response.                                                                                                                                             |
| T-17 | CSRF against the web API                                                                                    | A5       | Mitigated                               | `SameSite=Strict` cookie, exact `Origin` check, and JSON-only bodies with a custom header ([authentication.md](authentication.md#6-csrf)).                                                                                                                                                                                               |
| T-18 | XSS in the Ruvee web app while the vault is unlocked                                                        | A6       | Out of scope once the code runs         | Script in the origin can read what the app can read. **Mitigated in likelihood only:** strict CSP, no third-party script, no HTML rendering of item content, React escaping, Trusted Types. Defined in [api-design.md](../architecture/api-design.md#web-app-security-headers).                                                          |
| T-19 | XSS while locked: steals `SK` and wrapped `AK` for later offline guessing                                   | A6       | Limited                                 | `SK` is in the origin's IndexedDB and readable by script in that origin. The attacker still needs the password. The same likelihood mitigations as T-18 apply.                                                                                                                                                                           |
| T-20 | Malicious page tricks the extension into filling credentials or reads the vault through the extension       | A5       | Mitigated (design constraint; Phase 5)  | Content scripts never hold keys or the vault. Fill requires exact origin matching, the public suffix list, top-frame or same-origin frame checks, and user action. Messages from content scripts are validated by sender and treated as untrusted. Detailed in the Phase 5 design.                                                       |
| T-21 | Supply-chain compromise of a dependency, the extension or an app build                                      | A10      | Limited                                 | Lockfile, pinned versions, a minimum-release-age policy, few crypto dependencies, reproducible builds as a goal, and review of every crypto dependency update. Cannot be prevented completely.                                                                                                                                           |
| T-22 | Stolen device, at rest                                                                                      | A7       | Limited                                 | Local store needs `P`. `SK` is on the device, so it is one Argon2id evaluation per guess. A weak password is guessable. Mitigations: profile 1 cost, password strength guidance, revoke the device, and rotate keys (T-24).                                                                                                              |
| T-23 | Compromised device while unlocked: malware, malicious extension or shoulder access                          | A8       | Out of scope                            | Anything the user can see, the attacker can see. Auto-lock reduces the window. Memory clearing in JavaScript is best-effort only ([sync-protocol.md](../architecture/sync-protocol.md#memory-and-lock)).                                                                                                                                 |
| T-24 | Revoked device keeps decrypting                                                                             | A9       | Limited                                 | Revocation stops the server serving that device. It cannot erase data already on the device, and an offline device never learns it was revoked until it connects. Its local copy decrypts with the password. Only full key rotation protects **future** data ([device-enrollment.md](device-enrollment.md#6-revocation-and-its-limits)). |
| T-25 | Recovery Kit stolen                                                                                         | Physical | Out of scope                            | The Recovery Key alone can decrypt and reset the account by design. The Kit must be stored like a house key. Rotation invalidates the old Kit for future server state only ([account-recovery.md](account-recovery.md#5-recovery-key-rotation)).                                                                                         |
| T-26 | Clipboard exposure of copied passwords                                                                      | A8       | Limited (Phase 3 and later)             | Clear the clipboard after a timeout where the platform allows; mark content as sensitive on Android. Other applications can still read the clipboard while it is set.                                                                                                                                                                    |
| T-27 | Secrets in logs, URLs, error messages or crash reports                                                      | Any      | Mitigated                               | Allow-listed log fields, no secrets in URLs, structured errors without values, no third-party error reporting ([INV-12](security-invariants.md), [api-design.md](../architecture/api-design.md#logging)).                                                                                                                                |
| T-28 | Downgrade of KDF parameters or envelope format by the server                                                | A3       | Mitigated                               | Clients accept only known profile ids at or above the floor, and only format version 1 ([cryptographic design §3.2, §4.4](cryptographic-design.md#32-argon2id-profiles)).                                                                                                                                                                |
| T-29 | Server sends a different keyset, or an older one                                                            | A3       | Detected                                | The keyset is AEAD-encrypted under a key derived from `AK`, and `keyset_version` is monotonic per device ([cryptographic design §5.1](cryptographic-design.md#51-keyset-keyset)).                                                                                                                                                        |

## 6. The web-client delivery problem

The web app is JavaScript downloaded from the Ruvee server at every visit. If the server is
compromised (A3) or the build is tampered with (A10), the next page load can run code that reads
the password as it is typed, reads `SK` from IndexedDB, and sends plaintext anywhere. TLS,
Subresource Integrity and CSP do not help, because the attacker controls the HTML that declares
them. Ruvee cannot make the web app safe against its own server.

What the design does about it:

1. **Says so.** Documentation and the security page in the app state that the web app trusts
   the server that delivers it, and that the browser extension and mobile apps do not depend on
   the server for their code.
2. **Shrinks exposure.** Private-mode deployment, the default, means only the user's own
   devices on the private network can reach the server, which reduces A3 to compromise of the
   user's own host. The vault UI is a static client bundle with no server-rendered vault data,
   which makes changes easier to spot in reviews and diffs.
3. **Provides a higher-assurance client.** The browser extension's code is installed as a
   package and updated through its own channel, not served per visit by the Ruvee server.
   Phase 5 should consider letting the extension host the full vault UI on an extension page.
   Users who want protection from the server should use the extension or mobile apps.
4. **Does not pretend.** No "verified" or "secure" badge in the web UI implies the code was
   verified.

Classification: **outside the achievable guarantees for the web app**. It is recorded as risk
[R-01](risk-register.md).

## 7. Assumptions

- The client devices the user enrolls are not compromised at the time of enrollment.
- The OS and browser random number generators work. libsodium uses them.
- libsodium, libsodium.js, react-native-libsodium, opaque-ke and @serenity-kit/opaque implement
  their algorithms correctly. Audit coverage is partial and dated
  ([research-sources.md](research-sources.md)); this is a risk, [R-02](risk-register.md).
- TLS terminates at the user's Caddy instance with a valid certificate, or traffic stays on the
  private network.
- The user keeps the Recovery Kit offline and does not photograph it into a cloud photo library.
- The user chooses a password that resists offline guessing at about one Argon2id (64 MiB, t=3)
  evaluation per guess. Strength guidance is a UX requirement ([D-09](../architecture/open-decisions.md)).

## 8. Out of scope for V1

- Multi-user threats: sharing, organizations, insider administrators of other users.
- Passkeys and WebAuthn credential storage.
- Coercion: Ruvee provides no plausible deniability.
- Traffic analysis beyond the padding of item sizes.
- Hardware attacks on the device: cold boot, or extraction from secure enclaves.
