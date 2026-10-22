# Account recovery

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed, not implemented.

Recovery in Ruvee depends on secrets the **user** holds. There is no administrator, support or
server-side recovery of vault contents ([INV-18](security-invariants.md)). This is recorded in
[ADR-0006](../adr/0006-user-held-recovery-key.md). Key formats are in
[cryptographic-design.md](cryptographic-design.md).

## 1. Two different things called "recovery"

| Kind                          | Meaning                                       | Needs                                                                                                                      | Who can perform it                                                   |
| ----------------------------- | --------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- |
| **Account access recovery**   | Being able to log in to the server again.     | The password (normal login), or the Recovery Key (re-registers OPAQUE), or an operator reset that **deletes** the account. | The user, or the operator by deleting the account and starting over. |
| **Vault decryption recovery** | Being able to read the encrypted vault again. | The password together with `SK` (an enrolled device, or pairing from one), **or** the Recovery Key.                        | Only the user. Nobody else holds these secrets.                      |

Having one does not imply the other. Someone who knows the password but has lost every device
and the Recovery Kit can **log in but cannot decrypt anything**. An operator can always give
back account access by resetting the account, but **never** the data.

## 2. Creating the Recovery Kit

At account creation ([device-enrollment.md §2](device-enrollment.md#2-first-device-account-creation)),
the first device generates the 128-bit Recovery Key `RK` and shows the **Recovery Kit**:

- the Recovery Key in its text form `RK1-…` (29 characters in groups of 5) and as a QR code
  ([cryptographic-design.md §5.4](cryptographic-design.md#54-recovery-key-display-format))
- the username, the server URL and `instance_id`
- the creation date and `recovery_key_id` (shortened), so the user can tell kits apart
- the warnings in section 8

The user can print it or save it as a PDF generated **locally**. The kit is never uploaded and
never stored by Ruvee on any device after setup.

**Verification is required before setup completes.** The user types the full Recovery Key back.
The client checks the checksum, derives `RWK` and decrypts the new `AK_WRAP_RECOVERY` locally.
Setup cannot finish until this succeeds. Later, **Settings → Check Recovery Kit** repeats the same
check on an unlocked device, offline. It tells the user whether the kit they hold still matches
the current recovery wrap.

## 3. Recovery with the Recovery Key

This flow is used when the password is forgotten, when every device is lost, or both. It can run
on a new device or on an existing one.

1. The user chooses **Use Recovery Kit** and enters the username and Recovery Key. The client
   checks the checksum offline.
2. The client derives `RAK` and `RWK`, then calls `POST /api/v1/recovery/start { username, recoveryAuthKey: RAK }`.
   - The server throttles the request ([authentication.md §7](authentication.md#7-rate-limiting-and-brute-force-protection)),
     compares `SHA-256(RAK)` with the stored verifier in constant time, and returns the same
     generic error for an unknown username or a wrong key.
   - On success it creates a **recovery session**: 15 minutes, usable only for the recovery
     endpoints, and bound to a device record that is `pending` or new.
3. The client fetches the recovery material: `AK_WRAP_RECOVERY`, the keyset, `ak_id`,
   `ak_epoch` and `keyset_version`. It unwraps `AK` with `RWK`, decrypts the keyset, and obtains
   `SK` and `VK`. A failure here is an integrity failure, not a wrong key, because `RAK` already
   matched.
4. The user sets a master password. Re-entering the old one is allowed. The client makes a new
   `salt_pw` and `AK_WRAP_PASSWORD`, and runs OPAQUE registration for the password.
5. **The Recovery Key is rotated, and this step cannot be skipped.** The key has been typed into
   this device and may have been exposed. The client generates a new `RK'`, shows and verifies
   the new kit (section 2), and builds the new recovery wrap and verifier.
6. `POST /api/v1/recovery/complete` replaces, in one transaction: the OPAQUE record, the password
   wrap, the recovery wrap and its verifier. It also deletes the old recovery wrap, ends **every**
   other session, marks this device `active` with `enrolled_via = recovery`, and records a
   security event. Other enrolled devices stay enrolled but must log in with the new password.
   On their next login they show a prominent notice that recovery was used, with time and
   platform.
7. The device stores `SK` and its wrap. It has **no trusted checkpoint**
   ([sync-protocol.md §Limits](../architecture/sync-protocol.md#limits)). It shows the vault's
   latest manifest date and the device that wrote it, and asks the user to confirm the vault looks
   current.

`RAK` is sent to the server, so a malicious server, or anyone who breaks TLS, learns it. `RAK`
only grants the right to run this flow; it is domain-separated from `RWK` and decrypts nothing.
Someone who abuses it can take over **account access** by re-registering a password, but cannot
read the vault. Other devices would then see the recovery notice. This risk is recorded as
[R-08](risk-register.md).

## 4. What the user has, and what happens

| Password | Enrolled device | Recovery Kit | Outcome                                                                                                                                                                                           |
| -------- | --------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Yes      | Yes             | Any          | Normal unlock. Add more devices by pairing.                                                                                                                                                       |
| Yes      | No              | Yes          | Recovery flow (section 3). The user may keep the same password.                                                                                                                                   |
| Yes      | No              | No           | **Can log in, cannot decrypt. The data is unrecoverable.** The only option is a vault reset (section 6.1).                                                                                        |
| No       | Yes             | Yes          | Recovery flow on that device.                                                                                                                                                                     |
| No       | Yes             | No           | **Unrecoverable** in V1. A device needs the password to unlock. A future mobile biometric unlock could allow a password reset from an unlocked phone ([D-11](../architecture/open-decisions.md)). |
| No       | No              | Yes          | Recovery flow on a new device.                                                                                                                                                                    |
| No       | No              | No           | **Unrecoverable, including account access.** The operator can delete the account (section 6.2).                                                                                                   |

## 5. Recovery-key rotation

Rotation is available in **Settings** on an unlocked device and needs step-up. It is mandatory
after the Recovery Key has been used.

1. The client generates `RK'` and `recovery_key_id'`, and derives `RWK'` and `RAK'`.
2. It builds a new `AK_WRAP_RECOVERY` and shows and verifies the new kit (section 2).
3. `PUT /api/v1/account/recovery` replaces the wrap and the verifier, conditioned on
   `account_keys.row_version`. It deletes the old wrap and records a security event.

**What rotation revokes:** the old kit no longer works against the **current** server. **What it
does not revoke:** any **database backup** taken before the rotation still contains the old
recovery wrap of the **same** `AK`. Old kit plus old backup equals the vault as of that backup,
and future data too if `AK` has not changed since. Rotating `RK` therefore protects only against
someone who has the old kit **but not** an old backup. To also cut off old backups, do a full key
rotation ([cryptographic-design.md §6.3](cryptographic-design.md#63-full-rotation-new-ak-vk-and-every-ik)).
The UI must explain this whenever the reason for rotation is a lost or stolen kit.

## 6. Reset

Both kinds of reset **destroy** encrypted data. Neither decrypts it.

### 6.1 Vault reset by the user

Used when the user can log in but has lost all means of decryption.

- Requires login, step-up and typing the username as confirmation, and shows the warnings.
- The server deletes every item record, manifest, keyset and wrap of the account, and revokes
  every device except the current one.
- The current device then runs the first-device key setup again
  ([device-enrollment.md §2](device-enrollment.md#2-first-device-account-creation)), with a new
  `SK`, `AK`, `VK` and Recovery Kit. The account id and OPAQUE record remain.
- Other devices that come back online are revoked and wipe themselves. If they still have
  unlocked local copies, they are told that the vault was reset elsewhere. Phase 4 must define
  whether they may export their local copy before wiping ([D-12](../architecture/open-decisions.md)).

### 6.2 Operator reset

For a self-hosted single-user server, the operator (usually the same person) can run
`ruvee-admin delete-account` on the server host. It requires typing the username. It deletes the
account and every row belonging to it, and re-opens bootstrap. It is the documented way to
regain **account access** when every secret is lost, and it destroys the data. There is no admin
command that reads, exports or decrypts vault contents.

## 7. Restoring from backups

**Server backups** (implementation Phase 7, restore tests Phase 9) hold only what the database
holds: ciphertext, wraps, OPAQUE records and metadata
([database-design.md](../architecture/database-design.md)).

- Restoring them needs the **OPAQUE server secret**, which is backed up separately
  ([authentication.md §Server secrets](authentication.md#server-secrets)). Without it, logins fail,
  and the user re-registers OPAQUE through the Recovery Key flow.
- Decrypting restored data still needs the password and `SK`, or `RK`, **as they were at backup
  time**. If the password or Recovery Key was changed after the backup, the user needs the old
  ones. The backup guide must tell the user to keep old Recovery Kits for as long as old backups
  exist, or to rotate keys fully and then delete old backups.
- A server restored to an older state looks like a rollback to every device whose checkpoint is
  newer. Those devices stop and warn ([INV-07](security-invariants.md)). Re-seeding the server
  from a device's newer local copy is specified in
  [sync-protocol.md §Server restore](../architecture/sync-protocol.md#server-restored-from-an-older-backup).

**Portable encrypted exports** are planned for Phase 7, and their format is not yet specified
([D-13](../architecture/open-decisions.md)). Constraints fixed now:

- An export must contain the encrypted records, the manifest and the keyset, together with a wrap
  of `AK` that the **Recovery Key** can open, so that it can be restored without the server and
  without an enrolled device.
- It must never contain plaintext.
- Restoring it onto a clean device has no trusted checkpoint. The client shows the export's
  manifest date and author device, which are authenticated values, and treats the content as of
  that date.

## 8. User-facing wording

The prototype's lock screen says Ruvee "can't reset or recover your master password". The master
prompt requires a recovery key, recovery procedure, account reset and device-loss recovery.
These are consistent once the wording is precise.

**Recommended wording** for the unlock and setup screens:

> Ruvee can't see, reset or recover your master password, and nobody can recover your data for
> you. If you forget your password or lose all your devices, your **Recovery Kit** is the only way
> back in. Without your password and an enrolled device, or your Recovery Kit, your data is
> permanently lost.

Rules for every recovery-related screen:

- Never say "Forgot password? Reset it", which suggests server-side reset. Say "Use your Recovery
  Kit".
- Show the unrecoverable-data warning at setup (before the kit is generated), at Recovery Kit
  verification, before vault reset and before operator reset.
- Never describe revocation, password change or Recovery Key rotation as removing data from
  devices or backups ([cryptographic-design.md §6.4](cryptographic-design.md#64-what-changing-a-password-does-not-do)).
