# Sync protocol and local storage

Status: **Proposed (Phase 0).** Not owner-approved, not independently reviewed, not implemented.
Item storage is built in Phase 3; multi-device sync in Phase 4.

Formats such as records, manifests, digests and envelope purposes are defined in
[cryptographic-design.md §5](../security/cryptographic-design.md#5-plaintext-formats). Endpoints
are in [api-design.md](api-design.md#sync); tables in [database-design.md](database-design.md).
The design is recorded in [ADR-0007](../adr/0007-sync-manifest-chain.md).

## 1. Model

- V1 has one vault. Every change to it is a **commit**. Commits form a single linear sequence
  numbered `seq` = 1, 2, 3 and so on. The server assigns no ordering of its own; it only accepts a
  commit whose `baseSeq` equals its current `seq`.
- Each commit carries a set of item mutations and a new **manifest**. The manifest is encrypted
  and authenticated under `K_manifest`. It states its `seq`, the hash of the previous manifest,
  and a digest of every item's revision and record hash after the commit.
- The server stores records and manifests and enforces preconditions. It cannot read either,
  and it cannot produce a manifest that clients accept.

A single linear sequence is simple to reason about and enough for one user. Every concurrent
write costs at most one extra round trip to rebase (section 6). Shared vaults would keep one
sequence per vault.

## 2. Item boundaries and server-visible metadata

One item (login, note, card or identity) is one **record**: an `ITEM_KEY` envelope and an
`ITEM_BODY` envelope. Everything the user typed, plus favorite, archive, trash, tags and
timestamps, is inside `ITEM_BODY`.

| Per item, visible to the server                | Why it is needed                                |
| ---------------------------------------------- | ----------------------------------------------- |
| `item_id` (random UUID chosen by the client)   | Addressing, and preconditions                   |
| `revision` (u64)                               | Optimistic concurrency                          |
| Record size, padded to 256 bytes               | Storage; unavoidable                            |
| `updated_seq`, the commit that last changed it | Incremental sync cursor                         |
| Tombstone flag                                 | Permanent deletion without keeping ciphertext   |
| Server receive time                            | Operations and debugging; not used for ordering |

Item type, title, URLs and folder are **not** visible. Search runs on the client after unlock.

## 3. Revisions

- A new item has revision 1. Every change, including moving to Trash, is revision + 1. The
  client picks `newRevision = baseRevision + 1`, and the server checks it.
- The revision is in the `ITEM_BODY` AAD. An old record therefore cannot be presented as a
  newer revision. It still decrypts as itself, which is why replay detection needs the manifest
  (section 5).
- Revisions never decrease. A permanently deleted item becomes a tombstone at the next revision,
  and its `item_id` is never reused.

## 4. Commits

### 4.1 Client side

1. Build each mutation: `{ itemId, baseRevision, newRevision, record | tombstone }`, using
   `baseRevision = 0` for a new item.
2. Compute the vault state that would result: the local synced state plus the mutations. Compute
   `items_digest` and the counts.
3. Build the manifest for `seq = baseSeq + 1`, with `prev_manifest_hash` equal to the current
   manifest's hash, `author_device_id`, `created_at_ms` and `commit_id`. Encrypt it.
4. Send `POST /api/v1/sync/commits { commitId, baseSeq, mutations, manifest }`.

### 4.2 Server side

In one database transaction, holding a row lock on the vault:

1. If `commitId` was already accepted for this vault, return the stored result when the request
   hash matches, or `409 idempotency_mismatch` when it does not.
2. If `baseSeq ≠ vaults.current_seq`, return `409 seq_conflict { currentSeq }`.
3. For each mutation:
   - `baseRevision = 0` requires that the item does not exist.
   - Otherwise the item must exist, must not be a tombstone, and must be at `baseRevision`.
   - `newRevision` must be `baseRevision + 1`.
   - Records and the manifest must pass **structural** checks only: magic bytes, version,
     purpose byte, length limits ([cryptographic-design.md §4.4](../security/cryptographic-design.md#44-parsing-rules)).
     The server cannot and does not check the contents.
   - Any failure returns `409 revision_conflict` listing every conflicting item and its current
     revision.
4. Write the items with `updated_seq = baseSeq + 1`, insert the commit (`seq`, `commit_id`,
   device, manifest, request hash), and set `vaults.current_seq` and the current manifest.
5. After commit, notify listeners (section 9).

Limits: at most 100 mutations and 2 MiB per commit. Larger batches, such as imports or
rotation, are split into several commits.

### 4.3 Idempotency and retries

`commitId` is a random UUID created **once per logical commit**, persisted in the local pending
queue before the first attempt, and reused for every retry. A timeout or network error is
retried with the same body and `commitId`. A `409 seq_conflict` means the commit was not applied:
the client rebases (section 6) and creates a **new** commit id for the rebased commit.

A reply never lowers the checkpoint (predeployment-review R5, 2026-10-26). The client moves its
checkpoint on a commit reply only if the commit was built on that checkpoint (`baseSeq` equals
`checkpoint.seq`) and the reply's `seq` is `checkpoint.seq + 1`; any other reply (an earlier
commit's idempotent answer, replayed or delayed) is an integrity error, `stale_commit_reply`. A
pull whose verified chain contains the in-flight commit's manifest hash clears that commit: it
landed and only its reply was lost, so it is not sent again. The in-flight commit is persisted,
so the same holds after a restart.

## 5. Pulling changes and verifying them

### 5.1 Pull

`GET /api/v1/sync/changes?since=<seq>&limit=<n>` returns:

- `currentSeq`
- the item rows with `updated_seq > since`, latest state only: record or tombstone, revision and
  `updated_seq`
- every manifest envelope with `since < seq ≤ currentSeq`
- `nextCursor` when the page is truncated

The cursor is opaque to clients but encodes `seq`. Pages are collected into a staging area, and
**nothing is applied until all pages up to `currentSeq` have arrived and verified.**

### Checkpoints

Each device stores a **checkpoint** `{ vaultId, seq, manifestHash, keysetVersion }` as a
`LOCAL_RECORD`. It is the latest state the device has verified. A device enrolled by pairing gets
its first checkpoint from the approving device
([device-enrollment.md §3.2](../security/device-enrollment.md#32-steps)).

### Rollback and deletion detection

Before applying staged changes, the client checks all of the following (INV-07):

1. Every staged manifest decrypts under `K_manifest`, and its plaintext `vault_id` and `seq`
   match its position.
2. The `seq` values are consecutive starting from `checkpoint.seq + 1`.
3. The first staged manifest's `prev_manifest_hash` equals `checkpoint.manifestHash`, and each
   later manifest chains to the one before it.
4. `currentSeq ≥ checkpoint.seq`. If `currentSeq = checkpoint.seq`, the current manifest's hash
   equals `checkpoint.manifestHash`.
5. After merging the staged item rows into the local synced state, the computed `items_digest`,
   `live_count` and `tombstone_count` equal those in the newest manifest.
6. Every staged record decrypts with the revision the server claims (AAD).

| Server misbehavior                                         | Detected by                                                                                 |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------- |
| Serves an older record for an item                         | Check 5 (digest mismatch). The old record also decrypts only as its own revision (check 6). |
| Omits an item or tombstone, or adds one                    | Check 5 (digest and counts)                                                                 |
| Rolls back the whole vault below the checkpoint            | Check 4                                                                                     |
| Rolls back to the checkpoint while claiming it is current  | Not a rollback; nothing is hidden relative to what the device verified                      |
| Rewrites history: different manifests after the checkpoint | Check 3 (chain)                                                                             |
| Moves a record to another item or vault                    | Check 6 (AAD includes `vault_id` and `item_id`)                                             |
| Forges a manifest                                          | Check 1. It needs `K_manifest`.                                                             |

On any failure the client applies nothing, keeps its local state, switches to read-only, and
shows an integrity warning ([cryptographic-design.md §7](../security/cryptographic-design.md#7-corruption-and-failure-handling)).
On success it applies the changes atomically in local storage and advances the checkpoint.

**AEAD alone does not prevent replay or rollback.** It proves only that a record was produced by
someone holding the key at some time. Freshness comes from the manifest chain together with the
local checkpoint, and only within the limits below.

### Limits

- **Fresh device with no checkpoint**, for example enrolled through the Recovery Key or restored
  from an export. It can verify the chain from `seq = 1` (genesis), which proves the history is
  internally consistent. It **cannot** tell whether the server stopped the history early: a
  correctly chained older state looks current. Mitigation: the client shows the newest manifest's
  `created_at_ms` and author device, and asks the user to confirm. Devices enrolled by pairing
  avoid this problem because they receive a checkpoint.
- **Freeze.** The server can stop showing new commits to a device. The device sees a valid but
  stale state. It is not detected unless the user notices a missing change. Proposed later
  mitigation: show "last change: <time> on <device>" prominently; checkpoint comparison below.
- **Fork.** The server can show two devices different histories that both extend an old common
  checkpoint. Each device is internally consistent. It is detected only when the devices compare
  checkpoints. Proposed for a later phase: devices write their latest verified checkpoint into the
  encrypted keyset or a dedicated encrypted record, so each can see the others' last-known state;
  alternatively, a manual "compare devices" screen. Recorded as [D-14](open-decisions.md).
- **A device whose keys leaked.** Anyone holding `VK` can create valid manifests. Revoking the
  device does not stop this if the server colludes; only full rotation does
  ([device-enrollment.md §6](../security/device-enrollment.md#6-revocation-and-its-limits)).
- **Retention.** All manifests are kept in V1. Each is 198 bytes, so 100,000 commits take about
  20 MB. Pruning would weaken check 3 for devices that were offline for a long time, and is
  deferred.

## 6. Conflicts

A conflict exists when the client has a pending mutation for an item whose remote revision is no
longer the mutation's `baseRevision`. Timestamps are shown to the user but never decide the
outcome (INV-08).

After a `409`, the client pulls and verifies (section 5). Then, for each pending mutation:

| Local pending    | Remote change since base | Result                                                                                                                                                                                                                                                                                                                                                                                                                          |
| ---------------- | ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Edit             | None                     | No conflict. Re-encrypt only if the revision changed, then rebuild the commit on the new `baseSeq`.                                                                                                                                                                                                                                                                                                                             |
| Edit             | Edit                     | **Conflict.** The remote version becomes the current item. The local edit is kept as an encrypted conflict draft, not uploaded. The UI shows "Edited on two devices", naming the other device (from the manifest's `author_device_id`), and offers: keep this device's version, keep the other, or keep both. "Keep both" saves the local edit as a new item. The chosen result is a new mutation based on the remote revision. |
| Edit             | Permanently deleted      | **Conflict.** The UI says the item was deleted on another device. It offers to restore it with the local changes as a **new item** (tombstoned ids are never reused) or to discard the changes.                                                                                                                                                                                                                                 |
| Permanent delete | Edit                     | **Conflict.** The UI says the item changed on another device after it was deleted here. It offers to keep the changed item or to delete it again, based on the new remote revision.                                                                                                                                                                                                                                             |
| Permanent delete | Permanently deleted      | No conflict. The local mutation is dropped.                                                                                                                                                                                                                                                                                                                                                                                     |
| Create           | Not applicable           | Item ids are random UUIDs, so creates never collide. A collision would return `409` and is treated as a bug.                                                                                                                                                                                                                                                                                                                    |

Moving an item to Trash, restoring it, favoriting and archiving are ordinary edits inside the
ciphertext, so they follow the edit rows above.

**Scenario: two offline devices edit the same item.** Phone and laptop both edit item X at
revision 4 while offline. The laptop reconnects first and commits revision 5. The phone
reconnects and sends `baseSeq = n` with X `4 → 5`. The server returns `409 seq_conflict`. The
phone pulls, verifies, and sees X at revision 5 by the laptop. Its pending edit becomes a
conflict draft. Its other non-conflicting pending changes are rebased and committed. The user
resolves X on the phone, which commits X `5 → 6`.

## 7. Offline writes

- Edits are applied to the local view immediately and appended to the **pending queue**. The
  queue is a `LOCAL_RECORD` holding fully built encrypted mutations, their `commitId` and their
  base state. It survives restarts.
- The vault can be unlocked and edited offline. Unlocking needs only the local wrap.
- When back online, the client pulls first, then commits the queue (section 6). Retries back off
  exponentially, and the sync status in the UI says "N changes waiting to sync".
- A pending queue on a device that is then revoked is lost
  ([device-enrollment.md §6](../security/device-enrollment.md#6-revocation-and-its-limits)).

## 8. Tombstones and Trash

- **Trash** is a field in the item body. A trashed item is an ordinary encrypted record, and the
  server cannot tell it is trashed.
- **Permanent deletion** (from Trash only) replaces the record with a tombstone at the next
  revision. The server drops the ciphertext and keeps `item_id`, revision, `updated_seq` and the
  tombstone flag. The manifest digest includes tombstones, so the server cannot hide a deletion,
  and cannot forge one either.
- V1 keeps tombstones forever (a few dozen bytes each). Compaction would need every device to be
  past the deletion, which a single user cannot guarantee for lost devices.

## 9. Change notifications

`GET /api/v1/sync/events` is a Server-Sent Events stream authenticated like any API call. It sends
only `event: vault-changed` with `data: {"seq": <n>}`, plus keep-alive comments. It never carries
item content, ids, sizes or device names. Clients react by pulling. If SSE is unavailable, clients
poll every 60 seconds while unlocked and visible. The MV3 extension cannot hold a connection while
its service worker is suspended, and will rely on polling with `chrome.alarms` (Phase 5).

## 10. Keyset updates

The keyset (`SK` and vault keys) has its own `keyset_version`, stored with the account key
material. Clients fetch it when the version they see in a sync response is higher than their
checkpoint's, and reject a lower one (INV-09). It changes on vault creation, `SK` rotation and full
rotation.

## 11. Exceptional procedures (Phase 4 to finalize)

### Server restored from an older backup

A device whose checkpoint `seq_c` is higher than the server's `currentSeq` (`seq_s`) reports that
the **server is behind this device**. It never silently accepts the older state. If the user
confirms, with step-up, that the server was restored, the device can **re-seed**:

- It uploads its full synced state, its checkpoint manifest (`seq_c`) and a new manifest at
  `seq_c + 1` chained to it, through `POST /api/v1/sync/reseed { expectedServerSeq: seq_s, … }`.
- The server replaces the vault's items and appends the two manifests.
- Devices whose checkpoint is between `seq_s` and `seq_c` see a gap in the chain they can't
  verify. They accept it only after the user confirms, with the reseeding device and time shown.

Changes that existed only on the lost server after the backup are lost, unless another device
still has them.

### Full key rotation

Rotation ([cryptographic-design.md §6.3](../security/cryptographic-design.md#63-full-rotation-new-ak-vk-and-every-ik))
uploads every re-encrypted record into a rotation staging area across several requests. A final
commit then atomically swaps every record, the keyset (`keyset_version` + 1), both wraps, and a
manifest under the new `K_manifest`, chained to the last old manifest. Devices pick up the new
keyset through section 10. This needs a detailed specification and review before Phase 4.

## 12. Local storage

| Platform     | Store                                                                                                                                                                                           | Contents                                                                                                                                                                                                                      |
| ------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Web          | IndexedDB in the web app's origin                                                                                                                                                               | `device` (`SK`, wrap copy, ids, pins); `records` (item records exactly as received); `manifests` (current and checkpoint); `local` (`LOCAL_RECORD` envelopes: checkpoint, pending queue, conflict drafts, sensitive settings) |
| Extension    | IndexedDB in the extension origin. While unlocked, `AK` and `VK` in `chrome.storage.session` (memory-only, not exposed to content scripts), so service-worker restarts don't force a re-unlock. | Same as web                                                                                                                                                                                                                   |
| iOS, Android | App sandbox database excluded from backup; `SK` in Keychain or Keystore ([device-enrollment.md §5](../security/device-enrollment.md#5-where-sk-is-stored-on-each-platform))                     | Same as web                                                                                                                                                                                                                   |

The search index, decrypted items and anything else derived from plaintext exist **only in
memory** after unlock, and are never written to disk, `localStorage`, `sessionStorage`, the
Cache API or service-worker caches (INV-16). API responses carry `Cache-Control: no-store`
([api-design.md](api-design.md#cache-control)).

## Memory and lock

**Lock triggers:**

- the user locks
- inactivity, default 15 minutes, configurable ([D-10](open-decisions.md))
- the tab or app closes
- OS lock or sleep where the platform reports it (extension `idle` API, mobile lifecycle)
- the session expires, the user logs out, or the device is revoked

**On lock, the client:**

1. Calls `memzero` on every key buffer it holds (`AK`, `VK`, `IK`s, `K_*`).
2. Drops every reference to decrypted items and the search index, and clears UI state and query
   caches.
3. Clears the clipboard if it still contains a value Ruvee copied.
4. Terminates and recreates the crypto worker, which releases its WebAssembly memory.
5. Removes keys from `chrome.storage.session` in the extension.
6. Shows the unlock screen.

**Limits of memory clearing in JavaScript.** These steps are best-effort and are not a
guarantee:

- JavaScript strings are immutable and garbage-collected. The master password typed into an
  input, decrypted field values and JSON produced while parsing cannot be zeroed. They stay in
  the heap until collected, and may be paged to disk.
- The DOM, the rendering pipeline, framework dev tools, browser form history and crash dumps can
  all hold copies.
- `memzero` clears a `Uint8Array`, but not copies that libraries, structured cloning or
  `postMessage` made.

So the design keeps keys as `Uint8Array` inside the worker, gives the UI only what it displays,
and relies on the lock timeout to shorten exposure. It does not claim that secrets are gone from
memory after locking ([threat model T-23](../security/threat-model.md#5-threats-and-outcomes)).
