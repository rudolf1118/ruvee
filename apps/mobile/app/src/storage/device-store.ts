import { open, type DB } from '@op-engineering/op-sqlite';
import type {
  DeviceRecord,
  DeviceStore,
  EnrolledKeys,
  QueuedImport,
  StoredManifest,
  StoredRecord,
} from '@ruvee/vault';
import { secureStore } from '../platform/secure-store';

/**
 * The mobile device store (sync-protocol §12, "iOS, Android"): the same public surface as the
 * web's IndexedDB `DeviceStore` (packages/vault/src/store.ts), over SQLite in the app sandbox.
 *
 * It holds what the web store holds, and like it never plaintext (INV-16): item records and
 * manifests exactly as received or committed, `LOCAL_RECORD` envelopes, ids, the password wrap
 * of `AK` and the encrypted keyset. One difference: `SK` is not in the database. It goes to the
 * Keystore-backed secure store under a name the database row points at
 * (device-enrollment.md §5), and is merged back into the record on read.
 *
 * The database file is in the app's private storage, which the manifest excludes from backup and
 * device transfer. It is not encrypted again as a whole: everything confidential in it is already
 * an authenticated envelope (docs/mobile/storage-policy.md).
 *
 * Writing a new `SK`: the key is stored under a fresh name first, then the row that names it is
 * committed, then the old name is removed. A crash in between leaves the previous row and key
 * intact; an orphaned key is removed the next time the store opens.
 */

const DB_NAME = 'ruvee-device.sqlite';
const STORES = ['device', 'records', 'meta', 'local', 'imports'] as const;
const SK_PREFIX = 'sk.';

type Stored = Omit<DeviceRecord, 'enrolled'> & {
  readonly enrolled?: Omit<EnrolledKeys, 'secretKey'> & { readonly secretKeyName: string };
};

// ---- Encoding: JSON with byte arrays tagged as base64 ----

function toB64(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromB64(text: string): Uint8Array {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

function encode(value: unknown): string {
  return JSON.stringify(value, (_key, v: unknown) =>
    v instanceof Uint8Array ? { $b: toB64(v) } : v,
  );
}

function decode<T>(text: string): T {
  return JSON.parse(text, (_key, v: unknown) =>
    v !== null && typeof v === 'object' && '$b' in v && typeof v.$b === 'string'
      ? fromB64(v.$b)
      : v,
  ) as T;
}

function bytesOf(value: unknown): Uint8Array {
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value))
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength).slice();
  throw new Error('device store: expected a blob');
}

function textOf(value: unknown): string {
  if (typeof value !== 'string') throw new Error('device store: expected text');
  return value;
}

const importKey = (order: number) => order.toString().padStart(16, '0');

export class MobileDeviceStore {
  private constructor(private readonly db: DB) {}

  static async open(): Promise<MobileDeviceStore> {
    const db = open({ name: DB_NAME });
    await db.execute('PRAGMA journal_mode = WAL');
    await db.execute('PRAGMA secure_delete = ON');
    await db.execute(
      'CREATE TABLE IF NOT EXISTS kv (store TEXT NOT NULL, key TEXT NOT NULL, text TEXT, blob BLOB, PRIMARY KEY (store, key)) WITHOUT ROWID',
    );
    const store = new MobileDeviceStore(db);
    await store.removeOrphanKeys();
    return store;
  }

  /** The engine's interface type is the web class; this object has the same public surface. */
  asDeviceStore(): DeviceStore {
    return this as unknown as DeviceStore;
  }

  close(): void {
    this.db.close();
  }

  // ---- Settings that are not part of the vault (the server address) ----

  async setting(key: string): Promise<string | undefined> {
    const { rows } = await this.db.execute(
      "SELECT text FROM kv WHERE store = 'settings' AND key = ?",
      [key],
    );
    return rows[0] ? textOf(rows[0].text) : undefined;
  }

  async putSetting(key: string, value: string | null): Promise<void> {
    if (value === null)
      await this.db.execute("DELETE FROM kv WHERE store = 'settings' AND key = ?", [key]);
    else
      await this.db.execute(
        "INSERT OR REPLACE INTO kv (store, key, text) VALUES ('settings', ?, ?)",
        [key, value],
      );
  }

  // ---- DeviceStore ----

  private async storedDevice(): Promise<Stored | undefined> {
    const { rows } = await this.db.execute(
      "SELECT text FROM kv WHERE store = 'device' AND key = 'self'",
    );
    return rows[0] ? decode<Stored>(textOf(rows[0].text)) : undefined;
  }

  async device(): Promise<DeviceRecord | undefined> {
    const stored = await this.storedDevice();
    if (!stored?.enrolled) return stored as DeviceRecord | undefined;
    const { secretKeyName, ...enrolled } = stored.enrolled;
    const secretKey = await secureStore.getBytes(secretKeyName);
    // The row names a key the Keystore no longer has (the app's keys were cleared): the device
    // cannot unlock; treat it as not enrolled rather than inventing one.
    if (!secretKey) {
      const { enrolled: _missing, ...unenrolled } = stored;
      return unenrolled;
    }
    return { ...stored, enrolled: { ...enrolled, secretKey } };
  }

  async putDevice(device: DeviceRecord): Promise<void> {
    await this.apply({ device });
  }

  async records(): Promise<StoredRecord[]> {
    const { rows } = await this.db.execute("SELECT text, blob FROM kv WHERE store = 'records'");
    return rows.map((row) => {
      const meta = JSON.parse(textOf(row.text)) as { itemId: string; revision: number };
      return {
        ...meta,
        record: row.blob === null || row.blob === undefined ? null : bytesOf(row.blob),
      };
    });
  }

  async imports(limit: number): Promise<QueuedImport[]> {
    const { rows } = await this.db.execute(
      "SELECT text, blob FROM kv WHERE store = 'imports' ORDER BY key LIMIT ?",
      [limit],
    );
    return rows.map((row) => ({
      ...(JSON.parse(textOf(row.text)) as { itemId: string; order: number }),
      record: bytesOf(row.blob),
    }));
  }

  async importsCount(): Promise<number> {
    const { rows } = await this.db.execute("SELECT COUNT(*) AS n FROM kv WHERE store = 'imports'");
    return Number(rows[0]?.n ?? 0);
  }

  async manifest(): Promise<StoredManifest | undefined> {
    const { rows } = await this.db.execute(
      "SELECT text, blob FROM kv WHERE store = 'meta' AND key = 'manifest'",
    );
    const row = rows[0];
    return row ? { seq: Number(textOf(row.text)), envelope: bytesOf(row.blob) } : undefined;
  }

  async local(name: string): Promise<Uint8Array | undefined> {
    const { rows } = await this.db.execute(
      "SELECT blob FROM kv WHERE store = 'local' AND key = ?",
      [name],
    );
    return rows[0] ? bytesOf(rows[0].blob) : undefined;
  }

  /** As on the web: one transaction, so records, manifest and checkpoint never diverge. */
  async apply(change: {
    device?: DeviceRecord;
    records?: readonly StoredRecord[];
    manifest?: StoredManifest;
    local?: Readonly<Record<string, Uint8Array | null>>;
    imports?: { readonly put?: readonly QueuedImport[]; readonly remove?: readonly number[] };
  }): Promise<void> {
    let deviceText: string | undefined;
    let previousKey: string | undefined;
    let newKey: string | undefined;
    if (change.device) {
      previousKey = (await this.storedDevice())?.enrolled?.secretKeyName;
      const { enrolled, ...rest } = change.device;
      let stored: Stored = rest;
      if (enrolled) {
        const { secretKey, ...keys } = enrolled;
        newKey = await this.storeSecretKey(secretKey, previousKey);
        stored = { ...rest, enrolled: { ...keys, secretKeyName: newKey } };
      }
      deviceText = encode(stored);
    }
    await this.db.transaction(async (tx) => {
      if (deviceText !== undefined)
        await tx.execute(
          "INSERT OR REPLACE INTO kv (store, key, text) VALUES ('device', 'self', ?)",
          [deviceText],
        );
      for (const r of change.records ?? [])
        await tx.execute(
          "INSERT OR REPLACE INTO kv (store, key, text, blob) VALUES ('records', ?, ?, ?)",
          [
            r.itemId,
            JSON.stringify({ itemId: r.itemId, revision: r.revision }),
            r.record === null ? null : r.record.slice(),
          ],
        );
      if (change.manifest)
        await tx.execute(
          "INSERT OR REPLACE INTO kv (store, key, text, blob) VALUES ('meta', 'manifest', ?, ?)",
          [String(change.manifest.seq), change.manifest.envelope.slice()],
        );
      for (const row of change.imports?.put ?? [])
        await tx.execute(
          "INSERT OR REPLACE INTO kv (store, key, text, blob) VALUES ('imports', ?, ?, ?)",
          [
            importKey(row.order),
            JSON.stringify({ itemId: row.itemId, order: row.order }),
            row.record.slice(),
          ],
        );
      for (const order of change.imports?.remove ?? [])
        await tx.execute("DELETE FROM kv WHERE store = 'imports' AND key = ?", [importKey(order)]);
      for (const [name, envelope] of Object.entries(change.local ?? {})) {
        if (envelope === null)
          await tx.execute("DELETE FROM kv WHERE store = 'local' AND key = ?", [name]);
        else
          await tx.execute("INSERT OR REPLACE INTO kv (store, key, blob) VALUES ('local', ?, ?)", [
            name,
            envelope.slice(),
          ]);
      }
    });
    if (previousKey !== undefined && previousKey !== newKey && change.device)
      await secureStore.remove(previousKey).catch(() => undefined);
  }

  /** Removes everything this device holds: used when the server says the device was revoked. */
  async wipe(): Promise<void> {
    await this.db.transaction(async (tx) => {
      for (const name of STORES) await tx.execute('DELETE FROM kv WHERE store = ?', [name]);
    });
    // secure_delete zeroes the freed pages; the write-ahead log still holds earlier versions of
    // them until a checkpoint, so fold it in and truncate it now.
    await this.db.execute('PRAGMA wal_checkpoint(TRUNCATE)');
    for (const name of await secureStore.names())
      if (name.startsWith(SK_PREFIX)) await secureStore.remove(name);
  }

  // ---- SK in the secure store ----

  /** Keeps the current name when the key is unchanged, so an unchanged `SK` is not rewritten. */
  private async storeSecretKey(
    secretKey: Uint8Array,
    current: string | undefined,
  ): Promise<string> {
    if (current !== undefined) {
      const existing = await secureStore.getBytes(current);
      const same =
        existing !== undefined &&
        existing.length === secretKey.length &&
        existing.every((b, i) => b === secretKey[i]);
      existing?.fill(0);
      if (same) return current;
    }
    const name = `${SK_PREFIX}${Date.now().toString(36)}.${Math.random().toString(36).slice(2, 10)}`;
    await secureStore.setBytes(name, secretKey);
    return name;
  }

  private async removeOrphanKeys(): Promise<void> {
    const referenced = (await this.storedDevice())?.enrolled?.secretKeyName;
    for (const name of await secureStore.names())
      if (name.startsWith(SK_PREFIX) && name !== referenced) await secureStore.remove(name);
  }
}
