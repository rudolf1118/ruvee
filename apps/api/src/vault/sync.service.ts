import { Injectable } from '@nestjs/common';
import { manifestStructureProblem, parseItemRecord } from '@ruvee/crypto';
import {
  MAX_COMMIT_RECORD_BYTES,
  SYNC_MANIFESTS_PER_PAGE_MAX,
  type CommitRequest,
  type SyncChangesResponse,
  type VaultStateResponse,
} from '@ruvee/contracts';
import { ApiException } from '../common/api-exception.js';
import { fromBase64url, sha256, toBase64url, type Bytes } from '../common/secrets.js';
import { PrismaService } from '../database/prisma.service.js';
import { Prisma } from '../generated/prisma/client.js';

const KEY_ID = { start: 5, end: 21 } as const;

function sameKeyId(envelope: Uint8Array, keyId: Uint8Array): boolean {
  return Buffer.compare(envelope.subarray(KEY_ID.start, KEY_ID.end), keyId) === 0;
}

interface CheckedMutation {
  readonly itemId: string;
  readonly baseRevision: number;
  readonly newRevision: number;
  readonly record: Bytes | null;
}

/**
 * The server half of sync-protocol §4.2 and §5.1. It enforces sequence and revision
 * preconditions and checks only the framing and headers of records and manifests: it can read
 * neither, and it cannot produce a manifest that clients accept.
 */
@Injectable()
export class SyncService {
  constructor(private readonly prisma: PrismaService) {}

  private async vaultFor(accountId: string, tx: Prisma.TransactionClient = this.prisma) {
    const vault = await tx.vault.findUnique({ where: { accountId } });
    if (!vault) throw new ApiException('not_found');
    return vault;
  }

  async state(accountId: string): Promise<VaultStateResponse> {
    const vault = await this.vaultFor(accountId);
    return {
      vaultId: vault.id,
      vkId: toBase64url(vault.vkId),
      currentSeq: Number(vault.currentSeq),
    };
  }

  /** Structural checks before any database work; failures are `400 invalid_request`. */
  private checkCommit(body: CommitRequest, vkId: Uint8Array): CheckedMutation[] {
    const manifest = fromBase64url(body.manifest);
    if (manifestStructureProblem(manifest) !== undefined || !sameKeyId(manifest, vkId))
      throw new ApiException('invalid_request');
    const seen = new Set<string>();
    return body.mutations.map((m) => {
      if (seen.has(m.itemId) || m.newRevision !== m.baseRevision + 1)
        throw new ApiException('invalid_request');
      seen.add(m.itemId);
      if (m.record === null) {
        // A tombstone replaces an existing item; there is nothing to delete at revision 0.
        if (m.baseRevision === 0) throw new ApiException('invalid_request');
        return { ...m, record: null };
      }
      const record = fromBase64url(m.record);
      const parsed = parseItemRecord(record);
      if (!parsed.ok || !sameKeyId(parsed.parts.itemKeyEnvelope, vkId))
        throw new ApiException('invalid_request');
      return { ...m, record };
    });
  }

  async commit(accountId: string, deviceId: string, body: CommitRequest): Promise<{ seq: number }> {
    const preliminary = await this.vaultFor(accountId);
    if (preliminary.id !== body.vaultId) throw new ApiException('not_found');
    const mutations = this.checkCommit(body, preliminary.vkId);
    const recordBytes = mutations.reduce((n, m) => n + (m.record?.length ?? 0), 0);
    if (recordBytes > MAX_COMMIT_RECORD_BYTES) throw new ApiException('payload_too_large');
    // The validated body has the schema's key order, so this is a canonical form of the request.
    const requestHash = sha256(JSON.stringify(body));

    return this.prisma.$transaction(async (tx) => {
      // Row lock: commits to one vault are applied strictly one after another.
      await tx.$queryRaw`SELECT id FROM vaults WHERE id = ${body.vaultId}::uuid FOR UPDATE`;
      const vault = await this.vaultFor(accountId, tx);

      const previous = await tx.vaultCommit.findUnique({
        where: { vaultId_commitId: { vaultId: vault.id, commitId: body.commitId } },
      });
      if (previous) {
        if (Buffer.compare(previous.requestHash, requestHash) !== 0)
          throw new ApiException('idempotency_mismatch');
        return { seq: Number(previous.seq) };
      }

      const currentSeq = Number(vault.currentSeq);
      if (body.baseSeq !== currentSeq) throw new ApiException('seq_conflict', { currentSeq });

      const existing = await tx.vaultItem.findMany({
        where: { vaultId: vault.id, itemId: { in: mutations.map((m) => m.itemId) } },
        select: { itemId: true, revision: true, tombstone: true },
      });
      const byId = new Map(existing.map((row) => [row.itemId, row]));
      const conflicts = mutations.flatMap((m) => {
        const row = byId.get(m.itemId);
        const ok =
          m.baseRevision === 0
            ? row === undefined
            : row !== undefined && !row.tombstone && Number(row.revision) === m.baseRevision;
        return ok
          ? []
          : [
              {
                itemId: m.itemId,
                currentRevision: row ? Number(row.revision) : null,
                tombstone: row?.tombstone ?? false,
              },
            ];
      });
      if (conflicts.length > 0) throw new ApiException('revision_conflict', { conflicts });

      const seq = currentSeq + 1;
      const now = new Date();
      for (const m of mutations) {
        const data = {
          revision: BigInt(m.newRevision),
          record: m.record,
          tombstone: m.record === null,
          updatedSeq: BigInt(seq),
          updatedAt: now,
        };
        await tx.vaultItem.upsert({
          where: { vaultId_itemId: { vaultId: vault.id, itemId: m.itemId } },
          create: { vaultId: vault.id, itemId: m.itemId, createdAt: now, ...data },
          update: data,
        });
      }
      await tx.vaultCommit.create({
        data: {
          vaultId: vault.id,
          seq: BigInt(seq),
          commitId: body.commitId,
          requestHash,
          deviceId,
          manifest: fromBase64url(body.manifest),
          mutationCount: mutations.length,
          createdAt: now,
        },
      });
      await tx.vault.update({
        where: { id: vault.id },
        data: { currentSeq: BigInt(seq), updatedAt: now },
      });
      return { seq };
    });
  }

  /**
   * Latest state of every item changed after `since`, and every manifest in the covered range,
   * read in one snapshot. A page always ends on a commit boundary, so the client can stage pages
   * and verify the chain once it reaches `currentSeq` (sync-protocol §5.1).
   */
  async changes(accountId: string, since: number, limit: number): Promise<SyncChangesResponse> {
    return this.prisma.$transaction(
      async (tx) => {
        const vault = await this.vaultFor(accountId, tx);
        const currentSeq = Number(vault.currentSeq);
        if (since >= currentSeq)
          return {
            vaultId: vault.id,
            currentSeq,
            pageEndSeq: currentSeq,
            items: [],
            manifests: [],
          };

        let pageEnd = Math.min(currentSeq, since + SYNC_MANIFESTS_PER_PAGE_MAX);
        const rows = await tx.vaultItem.findMany({
          where: { vaultId: vault.id, updatedSeq: { gt: BigInt(since), lte: BigInt(pageEnd) } },
          orderBy: [{ updatedSeq: 'asc' }, { itemId: 'asc' }],
          take: limit + 1,
        });
        if (rows.length > limit) {
          // Cut before the first commit that does not fit. A commit has at most 100 mutations
          // and the page holds at least 100 items, so the page is never empty.
          const firstExcluded = Number(rows[limit]?.updatedSeq);
          pageEnd = firstExcluded - 1;
        }
        const items = rows
          .filter((row) => Number(row.updatedSeq) <= pageEnd)
          .map((row) => ({
            itemId: row.itemId,
            revision: Number(row.revision),
            updatedSeq: Number(row.updatedSeq),
            record: row.record === null ? null : toBase64url(row.record),
          }));
        const commits = await tx.vaultCommit.findMany({
          where: { vaultId: vault.id, seq: { gt: BigInt(since), lte: BigInt(pageEnd) } },
          orderBy: { seq: 'asc' },
          select: { seq: true, manifest: true },
        });
        return {
          vaultId: vault.id,
          currentSeq,
          pageEndSeq: pageEnd,
          items,
          manifests: commits.map((c) => ({
            seq: Number(c.seq),
            manifest: toBase64url(c.manifest),
          })),
          ...(pageEnd < currentSeq ? { nextCursor: pageEnd } : {}),
        };
      },
      { isolationLevel: Prisma.TransactionIsolationLevel.RepeatableRead },
    );
  }
}
