import { uuidToBytes } from '@ruvee/crypto';
import { commitResponseSchema, syncChangesResponseSchema } from '@ruvee/contracts';
import type { Harness } from './api-harness.js';
import { buildCommit, sealItem, type SyntheticAccount } from './synthetic-client.js';

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
const unb64 = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));

/** A client that commits real envelopes and tracks what it believes the vault holds. */
export class VaultWriter {
  readonly items = new Map<string, { revision: number; record: Uint8Array | null }>();
  seq = 0;
  private prevHash: Uint8Array = new Uint8Array(32);

  constructor(
    private readonly h: Harness,
    private readonly account: SyntheticAccount,
    private readonly cookie: string,
  ) {}

  /** Adds one item (or the genesis commit, with no body) in one commit. */
  async add(body?: object): Promise<string | undefined> {
    const itemId = body ? this.account.crypto.generateUuid() : undefined;
    const record = itemId && body ? sealItem(this.account, itemId, 1, body) : undefined;
    const next = new Map(this.items);
    if (itemId && record) next.set(itemId, { revision: 1, record });
    const built = buildCommit(this.account, {
      seq: this.seq + 1,
      prevManifestHash: this.prevHash,
      items: [...next].map(([id, s]) => ({ itemId: id, ...s })),
    });
    const res = await this.h.post(
      '/api/v1/sync/commits',
      {
        vaultId: this.account.vaultId,
        commitId: built.commitId,
        baseSeq: this.seq,
        mutations:
          itemId && record
            ? [{ itemId, baseRevision: 0, newRevision: 1, record: b64(record) }]
            : [],
        manifest: b64(built.manifest),
      },
      this.cookie,
    );
    if (res.status !== 200) throw new Error(`commit failed: ${String(res.status)} ${res.text}`);
    this.seq = commitResponseSchema.parse(res.body).seq;
    this.prevHash = built.manifestHash;
    if (itemId && record) this.items.set(itemId, { revision: 1, record });
    return itemId;
  }
}

/**
 * Pulls everything from seq 0 and verifies it as a client does (sync-protocol §5): contiguous
 * seqs, each manifest opens and chains to the previous one, and the newest manifest's digest
 * equals the digest of the received items.
 */
export async function pullAndVerify(h: Harness, account: SyntheticAccount, cookie: string) {
  const pages = [];
  let cursor = 0;
  for (;;) {
    const res = await h.get(`/api/v1/sync/changes?since=${String(cursor)}`, cookie);
    if (res.status !== 200) throw new Error(`pull failed: ${String(res.status)}`);
    const page = syncChangesResponseSchema.parse(res.body);
    pages.push(page);
    if (page.nextCursor === undefined) break;
    cursor = page.nextCursor;
  }
  const manifests = pages.flatMap((p) => p.manifests);
  let previous: Uint8Array = new Uint8Array(32);
  let last;
  for (const [i, m] of manifests.entries()) {
    if (m.seq !== i + 1) throw new Error(`sequence gap at ${String(m.seq)}`);
    const envelope = unb64(m.manifest);
    const opened = account.crypto.openManifest({
      vaultKey: account.vaultKey,
      vaultKeyId: account.vaultKeyId,
      vaultId: uuidToBytes(account.vaultId),
      seq: m.seq,
      envelope,
    });
    if (b64(opened.prevManifestHash) !== b64(previous)) throw new Error('broken chain');
    previous = account.crypto.manifestHash(envelope);
    last = opened;
  }
  const latest = new Map<string, { revision: number; record: string | null }>();
  for (const item of pages.flatMap((p) => p.items)) latest.set(item.itemId, item);
  const digest = account.crypto.itemsDigest(
    [...latest].map(([id, i]) => ({
      itemId: uuidToBytes(id),
      revision: i.revision,
      recordHash: i.record === null ? null : account.crypto.recordHash(unb64(i.record)),
    })),
  );
  return {
    seq: manifests.length,
    latest,
    digestMatches: last !== undefined && b64(digest) === b64(last.itemsDigest),
  };
}
