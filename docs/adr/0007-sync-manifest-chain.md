# ADR-0007: Linear commits with an encrypted manifest chain

- Status: Proposed
- Date: 2026-10-22
- Specification: [sync-protocol.md](../architecture/sync-protocol.md)

## Context

AEAD proves only that a record was produced with the key. It does not prove the record is
current, nor that none are missing. A malicious server could replay old records, hide deletions
or roll back the vault. Concurrent offline edits must never be lost silently.

## Decision

- Each vault has one linear commit sequence with compare-and-swap on `baseSeq`.
- Every item mutation carries a revision precondition.
- Every commit carries a manifest encrypted under a key derived from `VK`. The manifest holds
  `seq`, the previous manifest's hash and a digest of every item's revision and record hash.
- Each device keeps a checkpoint and verifies the chain before applying anything.
- Conflicts are explicit and never decided by timestamps.

## Consequences

- Replay, dropped items, forged deletions and rollback below a checkpoint are detected (T-07).
- A device without a checkpoint, a freeze, and a fork between devices are not fully detected
  (R-07).
- Every concurrent write costs a rebase round trip, which is acceptable for one user.
- Manifests are kept forever, at about 198 bytes per commit.

## Alternatives considered

- **Per-item versions only.** Can't detect omitted items or rollback.
- **CRDTs.** More complex, and they still need an authenticated state digest for rollback
  detection.
- **A Merkle tree over items.** Smaller proofs, but not needed when the client holds the full
  vault.
