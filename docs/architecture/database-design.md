# Database design (V1)

Status: **Proposed (Phase 0).** Not independently reviewed. On 2026-10-25 the owner asked for the
minimal schema to be implemented for the web-vault development milestone; that is authorization to
build it, not a design review. The first migration
(`apps/api/prisma/migrations/20261025120000_web_vault_initial`) creates the tables marked
**implemented** below. `server_instance` (dropped by V-02), `refresh_tokens` (token clients,
Phase 5) and `pairings` (P2-12) are not created yet.

V1 serves one user with one personal vault. Only the tables that V1 needs are listed. Sharing,
organizations, attachments, passkeys and audit exports come later, with their own designs.

## Conventions

- PostgreSQL 18 through Prisma 7 (Phase 1 setup). Table and column names are `snake_case`, and
  Prisma models map to them.
- Client-chosen identifiers (`account_id`, `device_id`, `vault_id`, `item_id`, `commit_id`) are
  random UUIDv4 values. The server validates their format and uniqueness.
- Binary values are `bytea` with a `CHECK` on length wherever the length is fixed. Envelope
  sizes are taken from
  [cryptographic-design.md §4.3](../security/cryptographic-design.md#43-purposes).
- Timestamps are `timestamptz` set by the server.
- Deleting an account cascades to every row that references it.

**Confidentiality classes**, which INV-10 requires for every column:

| Class | Meaning                                                                                                                     |
| ----- | --------------------------------------------------------------------------------------------------------------------------- |
| `M`   | Plaintext metadata. Must appear in [threat-model.md §4](../security/threat-model.md#4-what-the-server-can-see).             |
| `C`   | Ciphertext produced by a client. The server can't decrypt it.                                                               |
| `V`   | A verifier: a hash of a high-entropy secret, such as a token or `RAK`. It can't be reversed, and it is not a password hash. |
| `O`   | OPAQUE protocol data. With the OPAQUE server secret, it allows offline password guessing (T-02, T-03).                      |
| `S`   | Server-internal operational data with no user content, such as counters and expiry times.                                   |

## Phase 2 tables

### `server_instance`

There is exactly one row.

| Column        | Type        | Class | Purpose                                                                                                                      |
| ------------- | ----------- | ----- | ---------------------------------------------------------------------------------------------------------------------------- |
| `instance_id` | uuid PK     | M     | OPAQUE server identifier, created at first start ([authentication.md §2.2](../security/authentication.md#22-configuration)). |
| `created_at`  | timestamptz | S     |                                                                                                                              |

The OPAQUE server setup is **not** stored here or anywhere else in the database ([INV-21](../security/security-invariants.md)).

**Likely unnecessary.** If validation finding V-02 is accepted, OPAQUE uses no server identifier,
and no protocol uses `instance_id`. This table would then be dropped from the Phase 2 schema
([architecture-validation.md](../security/architecture-validation.md#1-findings)). The schema
is not approved either way.

### `accounts`

**Implemented** in the first migration.

| Column                | Type        | Class | Purpose                                            |
| --------------------- | ----------- | ----- | -------------------------------------------------- |
| `id`                  | uuid PK     | M     | `account_id`, chosen by the client.                |
| `username_normalized` | text UNIQUE | M     | NFC, lowercase, 1–64 characters. Login identifier. |
| `created_at`          | timestamptz | M     |                                                    |

### `opaque_credentials`

**Implemented** in the first migration.

| Column                | Type        | Class | Purpose                                                                                                                                       |
| --------------------- | ----------- | ----- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| `account_id`          | uuid PK, FK | M     |                                                                                                                                               |
| `registration_record` | bytea       | O     | Output of OPAQUE `finishRegistration`.                                                                                                        |
| `config_id`           | text        | M     | Fixed configuration label, for example `serenity-opaque-1/ristretto255-sha512/memory-constrained`. Lets a later migration detect old records. |
| `updated_at`          | timestamptz | M     | Shown as "password last changed".                                                                                                             |

### `account_keys`

**Implemented** in the first migration.

There is one row per account. Changes are compare-and-swap on `row_version`.

| Column                | Type             | Class | Purpose                                                                                                         |
| --------------------- | ---------------- | ----- | --------------------------------------------------------------------------------------------------------------- |
| `account_id`          | uuid PK, FK      | M     |                                                                                                                 |
| `kdf_profile`         | smallint         | M     | Argon2id profile id ([cryptographic-design.md §3.2](../security/cryptographic-design.md#32-argon2id-profiles)). |
| `salt_pw`             | bytea (16)       | M     | Password salt.                                                                                                  |
| `ak_id`               | bytea (16)       | M     | Current `AK` id.                                                                                                |
| `ak_epoch`            | integer          | M     | Incremented by full rotation.                                                                                   |
| `wrapped_ak_password` | bytea (93)       | C     | `AK_WRAP_PASSWORD` envelope.                                                                                    |
| `recovery_key_id`     | bytea (16)       | M     |                                                                                                                 |
| `wrapped_ak_recovery` | bytea (93)       | C     | `AK_WRAP_RECOVERY` envelope.                                                                                    |
| `recovery_verifier`   | bytea (32)       | V     | `SHA-256(RAK)`.                                                                                                 |
| `keyset_version`      | bigint           | M     | Monotonic ([INV-09](../security/security-invariants.md)).                                                       |
| `keyset`              | bytea (≤ 16,445) | C     | `KEYSET` envelope.                                                                                              |
| `row_version`         | bigint           | S     | Optimistic concurrency for password change, recovery rotation and key rotation.                                 |
| `updated_at`          | timestamptz      | M     |                                                                                                                 |

### `devices`

**Implemented** in the first migration.

| Column                                                    | Type                                          | Class | Purpose                                                                      |
| --------------------------------------------------------- | --------------------------------------------- | ----- | ---------------------------------------------------------------------------- |
| `id`                                                      | uuid PK                                       | M     | `device_id`, chosen by the client.                                           |
| `account_id`                                              | uuid FK                                       | M     |                                                                              |
| `platform`                                                | enum `web, extension, ios, android`           | M     |                                                                              |
| `status`                                                  | enum `pending, active, revoked`               | M     | [device-enrollment.md §1](../security/device-enrollment.md#1-device-records) |
| `enrolled_via`                                            | enum `bootstrap, pairing, recovery`, nullable | M     | Null while `pending`.                                                        |
| `approved_by_device_id`                                   | uuid FK, nullable                             | M     | The approving device, for pairing.                                           |
| `label`                                                   | bytea (≤ 189), nullable                       | C     | `DEVICE_LABEL` envelope.                                                     |
| `created_at`, `enrolled_at`, `last_seen_at`, `revoked_at` | timestamptz                                   | M     | `last_seen_at` is updated at most once a minute.                             |

A `pending` device that is never enrolled is deleted after 24 hours.

### `sessions`

**Implemented** in the first migration.

One row per session. For token clients, the session is also the refresh-token family.

| Column                                   | Type                                                                                              | Class | Purpose                                                                                      |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------- | ----- | -------------------------------------------------------------------------------------------- |
| `id`                                     | uuid PK                                                                                           | M     |                                                                                              |
| `account_id`                             | uuid FK                                                                                           | M     |                                                                                              |
| `device_id`                              | uuid FK                                                                                           | M     | Revoking the device revokes its sessions.                                                    |
| `kind`                                   | enum `cookie, token, recovery`                                                                    | M     | `recovery` sessions can call only the recovery endpoints.                                    |
| `secret_hash`                            | bytea (32) UNIQUE                                                                                 | V     | `SHA-256` of the cookie value, the current access token, or the recovery token.              |
| `access_expires_at`                      | timestamptz, nullable                                                                             | S     | Token kind: access-token expiry (10 minutes).                                                |
| `auth_at`                                | timestamptz                                                                                       | S     | Last OPAQUE authentication, used for step-up ([INV-14](../security/security-invariants.md)). |
| `created_at`, `last_used_at`             | timestamptz                                                                                       | M     |                                                                                              |
| `idle_expires_at`, `absolute_expires_at` | timestamptz                                                                                       | S     | [authentication.md §5](../security/authentication.md#5-sessions)                             |
| `revoked_at`                             | timestamptz, nullable                                                                             | M     |                                                                                              |
| `revoke_reason`                          | enum `logout, user, device_revoked, password_changed, recovery, refresh_reuse, expired`, nullable | M     |                                                                                              |

Rows are deleted 30 days after they expire or are revoked.

### `refresh_tokens`

**Implemented** in `20261025160000_token_sessions` (Phase 5). The same migration adds the check that
exactly the `token` sessions have an `access_expires_at`.

| Column       | Type                  | Class | Purpose                                                                                                                   |
| ------------ | --------------------- | ----- | ------------------------------------------------------------------------------------------------------------------------- |
| `token_hash` | bytea (32) PK         | V     | `SHA-256(refresh token)`.                                                                                                 |
| `session_id` | uuid FK               | M     | The family.                                                                                                               |
| `created_at` | timestamptz           | S     |                                                                                                                           |
| `rotated_at` | timestamptz, nullable | S     | Set when this token is exchanged. Presenting a token that already has `rotated_at` revokes the session (`refresh_reuse`). |

### `auth_throttle`

**Implemented** in the first migration.

| Column          | Type                                       | Class | Purpose                                                                                                                                                                                        |
| --------------- | ------------------------------------------ | ----- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `scope`         | enum `login, recovery, bootstrap, pairing` | S     |                                                                                                                                                                                                |
| `subject_hash`  | bytea (32)                                 | S     | `SHA-256` of the normalized username, the account id, or a constant for bootstrap. Unknown usernames are throttled the same way as real ones, and the username a person typed is never stored. |
| `failure_count` | integer                                    | S     |                                                                                                                                                                                                |
| `window_start`  | timestamptz                                | S     |                                                                                                                                                                                                |
| `blocked_until` | timestamptz, nullable                      | S     |                                                                                                                                                                                                |

The primary key is (`scope`, `subject_hash`). Limits are in [authentication.md §7](../security/authentication.md#7-rate-limiting-and-brute-force-protection).
Per-address, wrong-code and per-session request rates are counted in `rate_windows`, not in this
table (below).

### `rate_windows`

**Implemented** in `20261029090000_shared_limits` (follow-up review §17.2 option B). Transient:
a backup holds the table's definition but no rows, and a restore empties it.

| Column         | Type                                | Class | Purpose                                                                                                                          |
| -------------- | ----------------------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------- |
| `scope`        | enum `address, wrong_code, session` | S     |                                                                                                                                  |
| `key_hash`     | bytea (32)                          | S     | `SHA-256(scope ‖ 0x00 ‖ key)`: the normalized client address (IPv6 by /64) or the session id; a constant for the overflow window |
| `window_start` | timestamptz                         | S     | Database time                                                                                                                    |
| `hits`         | integer, 0 to 1000                  | S     | Counted up to the limit plus one                                                                                                 |

The primary key is (`scope`, `key_hash`), with an index on (`scope`, `window_start`). At most
10,000 live windows per scope (plus the overflow window, and at most the number of statements
running at the same moment). The runtime role may select, insert, update and delete rows.

### `login_states`

**Implemented** in `20261029090000_shared_limits`. Transient, like `rate_windows`.

| Column           | Type                         | Class | Purpose                                                                                                           |
| ---------------- | ---------------------------- | ----- | ----------------------------------------------------------------------------------------------------------------- |
| `id_hash`        | bytea (32), primary key      | V     | `SHA-256(loginId)`; the 128-bit `loginId` itself is never stored                                                  |
| `purpose`        | enum `login, reauth, reopen` | S     | Checked against `session_id` and `reopen_code_id`                                                                 |
| `login_subject`  | bytea (32)                   | S     | `SHA-256("login" ‖ 0x00 ‖ normalized username)`, as in `auth_throttle`; the typed name is never stored            |
| `account_id`     | uuid, nullable, FK           | M     | Null for an unknown username (such a login never succeeds); required for step-up and reopening                    |
| `device_id`      | uuid, nullable               | M     | The device the client named                                                                                       |
| `platform`       | enum `device_platform`       | M     |                                                                                                                   |
| `session_id`     | uuid, nullable, FK           | M     | Step-up only: the session it may finish on                                                                        |
| `reopen_code_id` | uuid, nullable               | S     | Reopening only: the code it was started with                                                                      |
| `sealed`         | bytea, 64 to 1024 bytes      | O     | AES-256-GCM of the device challenge and the OPAQUE server login state, bound to every column above and the expiry |
| `created_at`     | timestamptz                  | S     | Database time                                                                                                     |
| `expires_at`     | timestamptz                  | S     | 60 s after `created_at` (a CHECK allows at most 5 minutes)                                                        |

The sealing key is HKDF-SHA-256 of the OPAQUE server setup (label `ruvee/login-state-seal/v1`)
and is never in the database. The runtime role may select, insert and delete rows, never update
them. At most 10,000 live states.

### `bootstrap_tokens`

**Implemented** in the first migration.

| Column                     | Type                  | Class | Purpose     |
| -------------------------- | --------------------- | ----- | ----------- |
| `id`                       | uuid PK               | S     |             |
| `token_hash`               | bytea (32) UNIQUE     | V     |             |
| `created_at`, `expires_at` | timestamptz           | S     | 60 minutes. |
| `used_at`                  | timestamptz, nullable | S     |             |

### `pairings`

The row is deleted when the pairing completes, is cancelled or expires.

| Column                     | Type                             | Class | Purpose                                        |
| -------------------------- | -------------------------------- | ----- | ---------------------------------------------- |
| `pairing_id`               | bytea (16) PK                    | M     | `MAC(S, …)[0..16]`; reveals nothing about `S`. |
| `account_id`               | uuid FK                          | M     |                                                |
| `initiator_device_id`      | uuid FK                          | M     | Device A.                                      |
| `state`                    | enum `open, requested, approved` | S     |                                                |
| `requester_device_id`      | uuid FK, nullable                | M     | Device B.                                      |
| `request_platform`         | enum, nullable                   | M     |                                                |
| `request_epk`              | bytea (32), nullable             | M     | B's ephemeral X25519 public key.               |
| `request_mac`              | bytea (32), nullable             | S     | Checked by A only.                             |
| `response_ciphertext`      | bytea (≤ 4,096), nullable        | C     | Sealed box containing `SK`.                    |
| `response_mac`             | bytea (32), nullable             | S     | Checked by B only.                             |
| `created_at`, `expires_at` | timestamptz                      | S     | 10 minutes.                                    |

### `security_events`

**Implemented** in the first migration.

The user sees these on the account activity screen. They contain no secrets
([INV-12](../security/security-invariants.md)).

| Column       | Type                   | Class | Purpose                                                                                                                                                                                                                                                                                                                                      |
| ------------ | ---------------------- | ----- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`         | uuid PK                | S     |                                                                                                                                                                                                                                                                                                                                              |
| `account_id` | uuid FK, nullable      | M     | Null for events before an account exists, such as failed bootstrap attempts.                                                                                                                                                                                                                                                                 |
| `device_id`  | uuid FK, nullable      | M     |                                                                                                                                                                                                                                                                                                                                              |
| `type`       | enum                   | M     | `login_succeeded, login_failed, session_revoked, refresh_reuse, password_changed, recovery_started, recovery_failed, recovery_completed, recovery_key_rotated, secret_key_rotated, device_pairing_requested, device_enrolled, device_revoked, pairing_mac_failed, vault_reset, bootstrap_used, bootstrap_failed, integrity_warning_reported` |
| `ip`         | inet, nullable         | M     | Client IP, determined as in [authentication.md §7](../security/authentication.md#7-rate-limiting-and-brute-force-protection).                                                                                                                                                                                                                |
| `user_agent` | text (≤ 256), nullable | M     |                                                                                                                                                                                                                                                                                                                                              |
| `details`    | jsonb                  | M     | Only allow-listed fields for each type, such as a revoked device id. Never request bodies.                                                                                                                                                                                                                                                   |
| `created_at` | timestamptz            | M     |                                                                                                                                                                                                                                                                                                                                              |

Events are kept for 365 days (owner decision [D-15](open-decisions.md)).

## Phase 3 and Phase 4 tables

### `vaults`

**Implemented** in the first migration.

| Column                     | Type        | Class | Purpose                                                  |
| -------------------------- | ----------- | ----- | -------------------------------------------------------- |
| `id`                       | uuid PK     | M     | `vault_id`, the same value as in the keyset.             |
| `account_id`               | uuid FK     | M     | Exactly one vault per account in V1 (unique constraint). |
| `vk_id`                    | bytea (16)  | M     | Current vault key id.                                    |
| `current_seq`              | bigint      | M     | [sync-protocol.md §1](sync-protocol.md#1-model)          |
| `created_at`, `updated_at` | timestamptz | M     |                                                          |

### `vault_items`

**Implemented** in the first migration.

| Column                     | Type                       | Class | Purpose                                             |
| -------------------------- | -------------------------- | ----- | --------------------------------------------------- |
| `vault_id`                 | uuid FK                    | M     | The primary key is (`vault_id`, `item_id`).         |
| `item_id`                  | uuid                       | M     |                                                     |
| `revision`                 | bigint                     | M     | [sync-protocol.md §3](sync-protocol.md#3-revisions) |
| `record`                   | bytea (≤ 65,702), nullable | C     | The item record. Null for a tombstone.              |
| `tombstone`                | boolean                    | M     | `CHECK (tombstone = (record IS NULL))`.             |
| `updated_seq`              | bigint                     | M     | Index (`vault_id`, `updated_seq`) for pulls.        |
| `created_at`, `updated_at` | timestamptz                | M     |                                                     |

### `vault_commits`

**Implemented** in the first migration.

| Column           | Type                            | Class | Purpose                                                                      |
| ---------------- | ------------------------------- | ----- | ---------------------------------------------------------------------------- |
| `vault_id`       | uuid FK                         | M     | The primary key is (`vault_id`, `seq`).                                      |
| `seq`            | bigint                          | M     |                                                                              |
| `commit_id`      | uuid                            | M     | Unique per vault, for idempotency.                                           |
| `request_hash`   | bytea (32)                      | S     | `SHA-256` of the canonical request body, used to detect a reused `commitId`. |
| `device_id`      | uuid FK                         | M     | The committing device.                                                       |
| `manifest`       | bytea (198)                     | C     | `MANIFEST` envelope. The current manifest is the one at `current_seq`.       |
| `mutation_count` | integer                         | M     |                                                                              |
| `kind`           | enum `normal, reseed, rotation` | M     |                                                                              |
| `created_at`     | timestamptz                     | M     |                                                                              |

Every commit is kept in V1 ([sync-protocol.md §Limits](sync-protocol.md#limits)). Phase 4 adds a
staging table for full key rotation, with its own design review.

## What the database never contains

- The master password, `PwK`, `AUK`, `SK`, `AK`, `VK`, any `IK`, `RK`, `RWK`, `RAK` itself, or item
  plaintext ([INV-01](../security/security-invariants.md)).
- The OPAQUE server setup ([INV-21](../security/security-invariants.md)).
- Session tokens, refresh tokens or the bootstrap token in raw form. Only their hashes are stored.
- Device names in plaintext.
- Request bodies in any log or event table.

## Backups

Database backups contain exactly the tables above. What restoring them means for clients is in
[account-recovery.md §7](../security/account-recovery.md#7-restoring-from-backups).

## Changes after architecture validation

Status remains **Proposed**, and the schema is not approved. On 2026-10-22, `server_instance` was
marked as likely unnecessary (V-02). No other table changed.

## Changes after the first migration (2026-10-25)

- The tables marked implemented exist, with Prisma models in `apps/api/prisma/schema.prisma`.
  Fixed byte lengths, the tombstone rule, `revoked_at`/`revoke_reason` consistency and "pending
  devices have no `enrolled_via`" are `CHECK` constraints in the migration SQL.
- Interpretations: `opaque_credentials.registration_record` is bounded to 1 to 1,024 bytes (the
  1.1.0 record is 192 bytes); `account_keys.keyset_version` is bounded to u32, as in the AAD;
  `vault_commits.device_id` uses `NO ACTION` so an account deletion can cascade through devices
  and vaults in one statement.
- Every column's confidentiality class is in `apps/api/src/database/column-classes.ts`. The
  migration integration test fails if the database and that list differ (INV-10), and checks
  that `down.sql` reverses the migration on a database the test creates and drops itself.
