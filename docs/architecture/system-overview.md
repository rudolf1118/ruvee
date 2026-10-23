# System overview

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed. A recommendation in
these documents is not owner approval and not a security review.

This is the entry point to the Phase 0 architecture. It summarizes the design and walks through
the key scenarios, but it specifies nothing itself. Each topic links to the one document that is
authoritative for it.

## Scope of V1

- One user, one personal vault, multiple devices. Self-hosted, with private-network mode as
  the default.
- Delivered in this order: **web app**, then the **browser extension** (Chrome first), then
  **mobile** (iOS and Android). The protocol and formats are already designed for mobile.
- Item types in V1: logins and secure notes (Phase 3). Cards, identities, TOTP, attachments,
  import and export follow in Phase 7.
- **Deferred:** shared vaults, organizations, passkeys, attachments, version history, breach
  checks. The master prompt's full scope is in
  [master-engineering-prompt.md](../planning/master-engineering-prompt.md). The phase plan is in
  [implementation-roadmap.md](../planning/implementation-roadmap.md).

## Components

```
 Clients (trusted when enrolled)                     Server (untrusted for confidentiality)
 ┌──────────────────────────────────┐                ┌───────────────────────────────────────┐
 │ apps/web       Next.js UI        │                │ Caddy  (TLS, same-origin routing)     │
 │ apps/extension MV3 (Phase 5)     │   HTTPS JSON   │ apps/api  NestJS                      │
 │ apps/mobile    RN (Phase 6)      │ ─────────────► │   auth · sessions · devices · pairing │
 │   └ crypto worker                │ ◄───────────── │   recovery · sync · security events   │
 │       packages/crypto (libsodium)│      SSE       │ PostgreSQL (ciphertext + metadata)    │
 │       packages/opaque-client     │                │ OPAQUE server setup (secret file)     │
 │   └ encrypted local store        │                └───────────────────────────────────────┘
 └──────────────────────────────────┘
```

| Concern                                 | Summary                                                                                                                                                    | Authoritative document                                               |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| Assets, attackers, guarantees           | The server is trusted for availability only. The web-delivery limit is stated openly.                                                                      | [threat-model.md](../security/threat-model.md)                       |
| Properties that must always hold        | INV-01 to INV-23                                                                                                                                           | [security-invariants.md](../security/security-invariants.md)         |
| Encryption and keys                     | libsodium: XChaCha20-Poly1305, Argon2id, BLAKE2b. Two-secret key derivation (password plus a device-held Secret Key). Versioned envelopes. Manifest chain. | [cryptographic-design.md](../security/cryptographic-design.md)       |
| Login and sessions                      | OPAQUE through `@serenity-kit/opaque`. HttpOnly cookie for web, rotating tokens elsewhere. Kept separate from unlocking.                                   | [authentication.md](../security/authentication.md)                   |
| Adding devices                          | Pairing with a code shown on an enrolled device, MAC-authenticated so that the server cannot substitute keys.                                              | [device-enrollment.md](../security/device-enrollment.md)             |
| Recovery and reset                      | A user-held Recovery Kit. No administrator recovery.                                                                                                       | [account-recovery.md](../security/account-recovery.md)               |
| Sync, offline, conflicts, local storage | Linear commit sequence, revision preconditions, explicit conflicts, checkpoints.                                                                           | [sync-protocol.md](sync-protocol.md)                                 |
| Tables                                  | Columns with confidentiality classes                                                                                                                       | [database-design.md](database-design.md)                             |
| Endpoints, headers, errors, logging     |                                                                                                                                                            | [api-design.md](api-design.md)                                       |
| Residual risks                          |                                                                                                                                                            | [risk-register.md](../security/risk-register.md)                     |
| Library and platform evidence           | Versions, audits and limitations, with dates checked                                                                                                       | [research-sources.md](../security/research-sources.md)               |
| Validation of this design               | Self-review and compatibility spike: findings, attacker tables, protocol details, measurements. Not an independent audit.                                  | [architecture-validation.md](../security/architecture-validation.md) |
| Primitive library checks                | Published vectors, cross-implementation checks and library behavior for libsodium.js, in Node and browsers (P2-01). Tests the libraries, not this design.  | [tools/crypto-validation](../../tools/crypto-validation/README.md)   |
| Argon2id calibration                    | Benchmark of profile 1 and candidates on the available computer (P2-02, local part). Provisional; reference devices not measured.                          | [kdf-calibration.md](../security/kdf-calibration.md)                 |
| Decisions for the owner                 |                                                                                                                                                            | [open-decisions.md](open-decisions.md)                               |
| Decision records                        | All Proposed                                                                                                                                               | [ADR index](../adr/README.md)                                        |

### Planned packages

This extends the Phase 1 monorepo. Only `packages/contracts` exists so far (P2-05).

| Package                  | Contents                                                                                                                                                                                                                                                                               | First phase |
| ------------------------ | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- |
| `packages/crypto`        | Envelope encode and decode, key derivations, wraps, records, manifests, padding, Recovery Key and pairing codes. Platform-neutral TypeScript over an injected libsodium interface (libsodium.js on web and extension, `react-native-libsodium` on mobile). No network or storage code. | 2           |
| `packages/opaque-client` | A thin wrapper over `@serenity-kit/opaque` with Ruvee's fixed configuration. A mobile implementation is added in Phase 6.                                                                                                                                                              | 2           |
| `packages/contracts`     | Zod request and response schemas shared by the API and clients. Binary fields are typed as opaque bytes. **Exists:** the health responses, the error shape and the transport limits; the OpenAPI document is generated from it.                                                        | 2           |
| `packages/vault-core`    | Client-side vault state, the sync engine, conflict handling, the lock manager and the storage interface. No UI.                                                                                                                                                                        | 3           |
| `tools/crypto-vectors`   | The independent vector generator (Python and Go). It is not a dependency of any app.                                                                                                                                                                                                   | 2           |

`apps/api` must not depend on `packages/crypto` ([INV-01](../security/security-invariants.md)).
It sees only opaque bytes.

## Scenario walkthroughs

Each scenario links to the steps in the authoritative document. These walkthroughs were used to
check the documents against each other.

### 1. First account and vault creation

1. The operator runs `ruvee-admin bootstrap-token` on the server host
   ([authentication.md §3](../security/authentication.md#3-account-bootstrap)).
2. In the web app, the user enters the token, username and master password. The crypto worker
   generates `SK`, `AK`, `VK` and `RK`, derives the wraps, and builds the keyset
   ([device-enrollment.md §2](../security/device-enrollment.md#2-first-device-account-creation)).
3. The Recovery Kit is shown, and the user must type the Recovery Key back before continuing
   ([account-recovery.md §2](../security/account-recovery.md#2-creating-the-recovery-kit)).
4. OPAQUE registration and the key material are stored in one transaction. Registration then
   closes, and the device is `active` with `enrolled_via = bootstrap`.
5. Phase 3: `POST /vaults`, then the genesis commit at `seq = 1`. The device stores its first
   checkpoint ([sync-protocol.md §5](sync-protocol.md#checkpoints)).

**The server ends up holding** the OPAQUE record, the wraps, the keyset envelope, `SHA-256(RAK)`
and metadata. None of these decrypt anything without `SK` and the password, or `RK`.

### 2. Adding a second device

1. On device B, the user logs in. B is `pending`, and its encrypted-data endpoints return `403`.
2. On device A, which is unlocked, the user chooses **Add a device**, and A shows a pairing
   code. The user enters it on B.
3. B sends its ephemeral public key, MACed with `K_pair`. A verifies the MAC, the user names B
   and approves, and A seals `SK` and the checkpoint to B
   ([device-enrollment.md §3.2](../security/device-enrollment.md#32-steps)).
4. B verifies the reply MAC, unwraps `AK` with the password and `SK`, checks the keyset, and
   stores `SK` and the checkpoint.
5. B's first sync is verified against that checkpoint, so it detects rollback from the start.

The server cannot place its own key in either direction
([device-enrollment.md §3.3](../security/device-enrollment.md#33-why-the-server-cannot-substitute-keys)).

### 3. A stolen server session

An attacker with a stolen cookie or refresh token can download ciphertext and metadata, and can
submit commits. It cannot decrypt anything, enroll a device, produce a manifest that clients
accept, or use any step-up action
([authentication.md §8](../security/authentication.md#8-what-a-stolen-session-can-and-cannot-do)).

If the attacker uploads commits, the server accepts them structurally, but every honest device
fails manifest verification on its next pull. It keeps its local state, goes read-only and warns
([sync-protocol.md §5](sync-protocol.md#rollback-and-deletion-detection)).

The user revokes the session from device management or the activity screen, which takes effect
immediately. If server state was damaged, an honest device re-seeds it
([sync-protocol.md §11](sync-protocol.md#server-restored-from-an-older-backup); Phase 4).
Until re-seeding exists, the damage is detected but cannot be repaired automatically. This is
noted in the roadmap.

### 4. Forgotten master password

1. On any device, the user chooses **Use Recovery Kit** and enters the username and Recovery Key.
2. `RAK` opens a 15-minute recovery session. `RWK` unwraps `AK` locally.
3. The user sets a new password. OPAQUE is re-registered and a new password wrap is made.
4. The Recovery Key is rotated, which is mandatory, and the new kit is verified.
5. Every other session is ended. Other devices show a "recovery was used" notice at their next
   login. The notice is raised when recovery **starts**, because the recovery material alone
   lets the kit holder unwrap `AK`.

Full steps: [account-recovery.md §3](../security/account-recovery.md#3-recovery-with-the-recovery-key).
Without the Recovery Kit, a forgotten password means the data is lost
([account-recovery.md §4](../security/account-recovery.md#4-what-the-user-has-and-what-happens)).

### 5. Loss of every device

- **The user has the Recovery Kit:** the same flow as scenario 4, on a new device. The user may
  keep the same password. The new device has no checkpoint, so it shows the vault's last change
  date and author device and asks the user to confirm
  ([sync-protocol.md §Limits](sync-protocol.md#limits)). It then asks the user to revoke the lost
  devices and offers `SK` rotation, because the lost devices still hold `SK` and a wrap of `AK`
  ([account-recovery.md §3](../security/account-recovery.md#3-recovery-with-the-recovery-key)).
- **Password only:** the user can log in but cannot decrypt. The only option is a vault reset,
  which destroys the data and starts again
  ([account-recovery.md §6.1](../security/account-recovery.md#61-vault-reset-by-the-user)).
- **Neither:** account access can only be regained by the operator deleting the account.

### 6. Master-password change

On an unlocked device, with step-up: the client derives a new `AUK` and re-wraps the **same**
`AK`. OPAQUE is re-registered. No item is re-encrypted. The server replaces both in one
transaction and ends every other session
([authentication.md §9](../security/authentication.md#9-password-change),
[cryptographic-design.md §6.1](../security/cryptographic-design.md#61-password-change-and-kdf-upgrade-re-wrap-only)).

Offline devices keep unlocking with the old password until they reconnect.

A password change **does not** revoke anything already copied: old database backups still open
with the old password and `SK`, and any device or attacker that held `AK` keeps it. Only full
rotation protects future data
([cryptographic-design.md §6.4](../security/cryptographic-design.md#64-what-changing-a-password-does-not-do)).

### 7. A revoked device comes back online

Every request returns `401 device_revoked`. A well-behaved client wipes `SK`, the wraps, the
local cache and pending changes, and says that unsynced edits are lost.

A compromised client ignores the wipe. It can keep decrypting what it already has, with the
password, permanently, and it could decrypt future data until a full key rotation happens
([device-enrollment.md §6](../security/device-enrollment.md#6-revocation-and-its-limits)). The
server cannot accept anything from it, because its sessions are revoked.

### 8. Two offline devices edit the same item

The device that commits first wins the sequence. The second receives `409 seq_conflict`, pulls,
sees that the item's revision changed, and turns its edit into an explicit conflict for the user
to resolve. Nothing is overwritten silently
([sync-protocol.md §6](sync-protocol.md#6-conflicts)).

### 9. A malicious server replays older ciphertext

An older record still decrypts, because AEAD proves only that it was made with the key. It
cannot pass as a newer revision, because the revision is in the AAD. The manifest digest no
longer matches, so the device rejects the update, stays on its verified state, and warns.

Whole-vault rollback below a device's checkpoint is detected by `seq` and the hash chain. A
fresh device with no checkpoint, a freeze, or a fork between devices is **not** fully detected
([sync-protocol.md §5](sync-protocol.md#rollback-and-deletion-detection),
[§Limits](sync-protocol.md#limits); risk R-07).

### 10. Restoring an encrypted backup onto a clean device

- **Server database backup** (restore tooling in Phase 7, tests in Phase 9): the operator
  restores PostgreSQL and the separately backed-up OPAQUE server setup. A clean device then
  enrolls through the Recovery Key that was valid **at backup time**, or logs in and pairs from a
  device that still works.
  - The clean device has no checkpoint, which is the limit in scenario 9.
  - Existing devices with newer checkpoints see the server as behind them, warn, and can re-seed
    ([account-recovery.md §7](../security/account-recovery.md#7-restoring-from-backups)).
- **Portable encrypted export** (Phase 7; format is D-13): restored with the Recovery Key and
  without a server. The device shows the export's authenticated date.

## Cross-cutting properties

- **Authentication is not decryption.** Logging in never yields a key
  ([INV-06](../security/security-invariants.md), [INV-11](../security/security-invariants.md)).
- **No administrator recovery.** Reset destroys; it never decrypts ([INV-18](../security/security-invariants.md)).
- **Freshness comes from manifests and checkpoints, not from AEAD** ([INV-07](../security/security-invariants.md)).
- **The web app trusts the server that serves it.** The extension and mobile apps don't depend
  on it for their code (R-01).

## Changes after architecture validation

Status remains **Proposed**. On 2026-10-22, scenarios 4 and 5 and the document table were updated to match
[account-recovery.md](../security/account-recovery.md): the recovery notice is raised at recovery
start, and recovery after device loss prompts revocation and `SK` rotation
([architecture-validation.md](../security/architecture-validation.md), V-07 and V-08).
