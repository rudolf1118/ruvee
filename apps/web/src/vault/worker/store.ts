/**
 * The device store (sync-protocol §12): IndexedDB in the web app's origin. It holds only what a
 * device needs to unlock and verify offline, and never plaintext (INV-16):
 * - `device`: ids, `SK` (raw: the web platform has no OS key store, R-06), the password wrap of
 *   `AK`, KDF salt and profile, and the encrypted keyset
 * - `records`: item records exactly as received or committed
 * - `meta`: the newest verified manifest envelope
 * - `local`: `LOCAL_RECORD` envelopes (checkpoint, pending queue, conflict drafts)
 */

const DB_NAME = 'ruvee';
const DB_VERSION = 1;
export const STORES = ['device', 'records', 'meta', 'local'] as const;
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

export interface StoredManifest {
  readonly seq: number;
  readonly envelope: Uint8Array;
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
  private constructor(private readonly db: IDBDatabase) {}

  static async open(factory: IDBFactory = indexedDB): Promise<DeviceStore> {
    const req = factory.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      db.createObjectStore('device');
      db.createObjectStore('records', { keyPath: 'itemId' });
      db.createObjectStore('meta');
      db.createObjectStore('local');
    };
    return new DeviceStore(await promised(req));
  }

  close(): void {
    this.db.close();
  }

  private store(name: StoreName, mode: IDBTransactionMode = 'readonly') {
    return this.db.transaction(name, mode).objectStore(name);
  }

  async device(): Promise<DeviceRecord | undefined> {
    return (await promised(this.store('device').get('self'))) as DeviceRecord | undefined;
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    const tx = this.db.transaction('device', 'readwrite');
    tx.objectStore('device').put(device, 'self');
    await done(tx);
  }

  async records(): Promise<StoredRecord[]> {
    return (await promised(this.store('records').getAll())) as StoredRecord[];
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
  }): Promise<void> {
    const tx = this.db.transaction(STORES, 'readwrite');
    if (change.device) tx.objectStore('device').put(change.device, 'self');
    for (const record of change.records ?? []) tx.objectStore('records').put(record);
    if (change.manifest) tx.objectStore('meta').put(change.manifest, 'manifest');
    for (const [name, envelope] of Object.entries(change.local ?? {})) {
      if (envelope === null) tx.objectStore('local').delete(name);
      else tx.objectStore('local').put(envelope, name);
    }
    await done(tx);
  }

  /** Removes everything this device holds: used when the server says the device was revoked. */
  async wipe(): Promise<void> {
    const tx = this.db.transaction(STORES, 'readwrite');
    for (const name of STORES) tx.objectStore(name).clear();
    await done(tx);
  }
}
