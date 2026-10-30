/**
 * The device store (sync-protocol §12): IndexedDB in the web app's origin. It holds only what a
 * device needs to unlock and verify offline, and never plaintext (INV-16):
 * - `device`: ids, `SK` (raw: the web platform has no OS key store, R-06), the password wrap of
 *   `AK`, KDF salt and profile, and the encrypted keyset
 * - `records`: item records exactly as received or committed
 * - `meta`: the newest verified manifest envelope
 * - `local`: `LOCAL_RECORD` envelopes (checkpoint, pending queue, conflict drafts, import state)
 * - `imports`: item records of an import, already encrypted under this vault's keys, waiting to
 *   be uploaded (backup-restore.md §4.4a)
 *
 * One engine writes at a time (follow-up review F-2). An engine writes whole lists from its
 * memory, so a second engine on the same database would overwrite what the first wrote since it
 * loaded. The engine that loads state last claims the store (`claim`); from then on every write
 * of an engine that loaded earlier is refused with `StoreTakenError`, in the same transaction, and
 * that engine locks instead of overwriting.
 */

const DB_NAME = 'ruvee';
const DB_VERSION = 2;
export const STORES = ['device', 'records', 'meta', 'local', 'imports'] as const;
type StoreName = (typeof STORES)[number];

export interface DeviceRecord {
  readonly v: 1;
  readonly accountId: string;
  readonly deviceId: string;
  readonly username: string;
  readonly status: 'active' | 'pending';
  /** Present once the device is enrolled. */
  readonly enrolled?: EnrolledKeys;
}

export interface EnrolledKeys {
  readonly secretKey: Uint8Array;
  readonly kdfProfile: number;
  readonly saltPw: Uint8Array;
  readonly akId: Uint8Array;
  readonly akEpoch: number;
  readonly wrappedAkPassword: Uint8Array;
  readonly keysetVersion: number;
  readonly keyset: Uint8Array;
  readonly vaultId: string;
  readonly vkId: Uint8Array;
}

export interface StoredRecord {
  readonly itemId: string;
  readonly revision: number;
  /** Null for a tombstone. */
  readonly record: Uint8Array | null;
}

/** One imported item, encrypted for this vault at revision 1 under a fresh item id. */
export interface QueuedImport {
  readonly itemId: string;
  readonly order: number;
  readonly record: Uint8Array;
}

export interface StoredManifest {
  readonly seq: number;
  readonly envelope: Uint8Array;
}

const WRITER = 'writer';

/** Another engine claimed this device store after this one loaded its state (F-2). */
export class StoreTakenError extends Error {
  constructor() {
    super('Another engine claimed the device store.');
    this.name = 'StoreTakenError';
  }
}

function promised<T>(req: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    req.onsuccess = () => {
      resolve(req.result);
    };
    req.onerror = () => {
      reject(req.error ?? new Error('IndexedDB request failed'));
    };
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => {
      resolve();
    };
    tx.onabort = tx.onerror = () => {
      reject(tx.error ?? new Error('IndexedDB transaction failed'));
    };
  });
}

export class DeviceStore {
  /** This connection's claim, once it claimed the store or first wrote to it. */
  private writer: string | undefined;

  private constructor(private readonly db: IDBDatabase) {}

  static async open(factory: IDBFactory = indexedDB): Promise<DeviceStore> {
    const req = factory.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = req.result;
      if (event.oldVersion < 1) {
        db.createObjectStore('device');
        db.createObjectStore('records', { keyPath: 'itemId' });
        db.createObjectStore('meta');
        db.createObjectStore('local');
      }
      if (event.oldVersion < 2) db.createObjectStore('imports', { keyPath: 'order' });
    };
    return new DeviceStore(await promised(req));
  }

  close(): void {
    this.db.close();
  }

  private store(name: StoreName, mode: IDBTransactionMode = 'readonly') {
    return this.db.transaction(name, mode).objectStore(name);
  }

  /**
   * Makes this connection the only writer from now on. Called when an engine loads the stored
   * state into memory: any engine that loaded earlier can no longer write.
   */
  async claim(): Promise<void> {
    const id = crypto.randomUUID();
    const tx = this.db.transaction('meta', 'readwrite');
    tx.objectStore('meta').put(id, WRITER);
    await done(tx);
    this.writer = id;
  }

  /**
   * One read-write transaction that first checks the claim. A connection that never claimed
   * claims on its first write (a new device: nothing loaded that could be stale); one whose claim
   * was taken over is refused, and nothing in the transaction is written.
   */
  private async write(names: readonly StoreName[], fill: (tx: IDBTransaction) => void) {
    const tx = this.db.transaction([...new Set<StoreName>([...names, 'meta'])], 'readwrite');
    const finished = done(tx);
    // Set inside the request callback, which the compiler cannot follow.
    const outcome = { taken: false };
    const check = tx.objectStore('meta').get(WRITER);
    check.onsuccess = () => {
      const current = check.result as string | undefined;
      if (this.writer !== undefined && current !== undefined && current !== this.writer) {
        outcome.taken = true;
        tx.abort();
        return;
      }
      this.writer ??= crypto.randomUUID();
      if (current !== this.writer) tx.objectStore('meta').put(this.writer, WRITER);
      fill(tx);
    };
    try {
      await finished;
    } catch (error) {
      if (outcome.taken) throw new StoreTakenError();
      throw error;
    }
  }

  /**
   * A new copy on every read (IndexedDB clones it): the caller owns its buffers and may zero them,
   * the `SK` included, without changing what is stored (follow-up review F-19). Writes store a
   * copy too, so a buffer passed to `putDevice` or `apply` may be zeroed once the write resolves.
   * Another implementation of this interface must keep both rules.
   */
  async device(): Promise<DeviceRecord | undefined> {
    return (await promised(this.store('device').get('self'))) as DeviceRecord | undefined;
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    await this.write(['device'], (tx) => {
      tx.objectStore('device').put(device, 'self');
    });
  }

  async records(): Promise<StoredRecord[]> {
    return (await promised(this.store('records').getAll())) as StoredRecord[];
  }

  /** The first `limit` queued import items, in queue order. */
  async imports(limit: number): Promise<QueuedImport[]> {
    return (await promised(this.store('imports').getAll(null, limit))) as QueuedImport[];
  }

  async importsCount(): Promise<number> {
    return promised(this.store('imports').count());
  }

  async manifest(): Promise<StoredManifest | undefined> {
    return (await promised(this.store('meta').get('manifest'))) as StoredManifest | undefined;
  }

  async local(name: string): Promise<Uint8Array | undefined> {
    return (await promised(this.store('local').get(name))) as Uint8Array | undefined;
  }

  /**
   * Applies a verified sync result, a commit or a device update in one transaction, so a crash
   * never leaves records, manifest and checkpoint out of step.
   */
  async apply(change: {
    device?: DeviceRecord;
    records?: readonly StoredRecord[];
    manifest?: StoredManifest;
    local?: Readonly<Record<string, Uint8Array | null>>;
    imports?: { readonly put?: readonly QueuedImport[]; readonly remove?: readonly number[] };
  }): Promise<void> {
    await this.write(STORES, (tx) => {
      if (change.device) tx.objectStore('device').put(change.device, 'self');
      for (const record of change.records ?? []) tx.objectStore('records').put(record);
      if (change.manifest) tx.objectStore('meta').put(change.manifest, 'manifest');
      for (const row of change.imports?.put ?? []) tx.objectStore('imports').put(row);
      for (const order of change.imports?.remove ?? []) tx.objectStore('imports').delete(order);
      for (const [name, envelope] of Object.entries(change.local ?? {})) {
        if (envelope === null) tx.objectStore('local').delete(name);
        else tx.objectStore('local').put(envelope, name);
      }
    });
  }

  /**
   * Removes everything this device holds: used when the server says the device was revoked, and
   * by start-over. Never refused: it destroys rather than overwrites, and the caller keeps (or
   * takes) the claim, so it can set the device up again.
   */
  async wipe(): Promise<void> {
    const tx = this.db.transaction(STORES, 'readwrite');
    for (const name of STORES) tx.objectStore(name).clear();
    this.writer ??= crypto.randomUUID();
    tx.objectStore('meta').put(this.writer, WRITER);
    await done(tx);
  }
}
