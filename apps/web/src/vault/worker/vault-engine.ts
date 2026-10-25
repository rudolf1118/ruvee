import {
  DEFAULT_KDF_PROFILE,
  normalizePassword,
  uuidFromBytes,
  uuidToBytes,
  type RuveeCrypto,
} from '@ruvee/crypto';
import {
  commitRequestSchema,
  normalizeUsername,
  type CommitRequest,
  type SyncChangesResponse,
} from '@ruvee/contracts';
import { z } from 'zod';
import { decodeItemBody, encodeItemBody, ITEM_SCHEMA_VERSION, type ItemBody } from '../item-schema';
import { checkMasterPassword } from '../password-policy';
import type {
  ConflictView,
  DevicePhase,
  ItemDetail,
  ItemDraft,
  ItemSummary,
  RecoveryKitView,
  SyncStatus,
  UnlockedVault,
  VaultErrorCode,
  VaultEvent,
} from '../protocol';
import { ApiError, NetworkError, type Api } from './api';
import { fromB64, fromUtf8, toB64, utf8 } from './bytes';
import type { DeviceRecord, DeviceStore, EnrolledKeys } from './store';
import {
  buildCommit,
  rebase,
  verifyPages,
  ZERO_HASH,
  type Checkpoint,
  type Conflict,
  type PendingMutation,
  type SyncedItem,
  type VaultKeys,
} from './sync-logic';

export class VaultError extends Error {
  constructor(
    readonly code: VaultErrorCode,
    readonly retryAfterSeconds?: number,
  ) {
    super(code);
    this.name = 'VaultError';
  }
}

/** The OPAQUE client calls the engine needs, with the D-02 configuration fixed by the caller. */
export interface OpaqueClient {
  startRegistration(password: string): {
    clientRegistrationState: string;
    registrationRequest: string;
  };
  finishRegistration(state: string, response: string, password: string): string;
  startLogin(password: string): { clientLoginState: string; startLoginRequest: string };
  /** Undefined for a wrong password, a substituted server or a tampered response. */
  finishLogin(state: string, response: string, password: string): string | undefined;
}

export interface EngineDeps {
  readonly crypto: RuveeCrypto;
  readonly api: Api;
  readonly store: DeviceStore;
  readonly opaque: OpaqueClient;
  readonly origin: string;
  readonly now: () => number;
  readonly emit: (event: VaultEvent) => void;
}

const MAX_MUTATIONS_PER_COMMIT = 100;
const MAX_PUSH_ROUNDS = 5;

// ---- Local records (LOCAL_RECORD envelopes under K_local) ----

const checkpointSchema = z.strictObject({
  vaultId: z.string(),
  seq: z.int().min(0),
  manifestHash: z.string(),
  keysetVersion: z.int().min(0),
});
const mutationSchema = z.strictObject({
  itemId: z.string(),
  baseRevision: z.int().min(0),
  record: z.string().nullable(),
});
const pendingSchema = z.strictObject({
  mutations: z.array(mutationSchema),
  inflight: z
    .strictObject({
      body: commitRequestSchema,
      manifestHash: z.string(),
      mutations: z.array(mutationSchema),
    })
    .nullable(),
  /** Hashes of records this device sent but has not seen confirmed, to recognise its own work. */
  sent: z.array(
    z.strictObject({ itemId: z.string(), revision: z.int(), recordHash: z.string().nullable() }),
  ),
});
const conflictsSchema = z.array(
  z.strictObject({
    itemId: z.string(),
    kind: z.enum(['edited_on_both', 'deleted_elsewhere', 'edited_after_delete']),
    localRecord: z.string().nullable(),
    localRevision: z.int().min(1),
    remoteRevision: z.int().min(0),
    detectedAtMs: z.int(),
  }),
);

interface Inflight {
  readonly body: CommitRequest;
  readonly manifestHash: Uint8Array;
  readonly mutations: readonly PendingMutation[];
}

interface SentRecord {
  readonly itemId: string;
  readonly revision: number;
  readonly recordHash: string | null;
}

interface Session {
  device: DeviceRecord & { readonly enrolled: EnrolledKeys };
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly deviceIdBytes: Uint8Array;
  readonly vault: VaultKeys;
  synced: Map<string, SyncedItem>;
  checkpoint: Checkpoint;
  pending: PendingMutation[];
  inflight: Inflight | null;
  sent: SentRecord[];
  conflicts: Map<string, Conflict>;
  bodies: Map<string, { revision: number; body: ItemBody | null }>;
  lastSyncedAtMs: number | null;
  lastChange: SyncStatus['lastChange'];
  state: SyncStatus['state'];
  integrity: string | undefined;
}

interface PendingSetup {
  readonly username: string;
  readonly password: string;
  readonly bootstrapToken: string;
  readonly registrationRecord: string;
  readonly accountId: string;
  readonly deviceId: string;
  readonly vaultId: string;
  readonly secretKey: Uint8Array;
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  readonly passwordSalt: Uint8Array;
  readonly recoveryKeyId: Uint8Array;
  readonly wrappedAkPassword: Uint8Array;
  readonly wrappedAkRecovery: Uint8Array;
  readonly recoveryVerifier: Uint8Array;
  readonly keyset: Uint8Array;
  verified: boolean;
}

/** Re-reads the state after a call that may have changed it (TypeScript keeps the old narrowing). */
function readOnly(session: { state: SyncStatus['state'] }): boolean {
  return session.state === 'integrity_error';
}

function same(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((v, i) => v === b[i]);
}

/** Maps transport failures onto the codes the UI understands. */
function vaultErrorFrom(error: unknown): VaultError {
  if (error instanceof VaultError) return error;
  if (error instanceof NetworkError) return new VaultError('offline');
  if (error instanceof ApiError) {
    switch (error.code) {
      case 'login_failed':
        return new VaultError('login_failed');
      case 'rate_limited':
        return new VaultError('rate_limited', error.retryAfterSeconds);
      case 'bootstrap_failed':
        return new VaultError('bootstrap_failed');
      case 'unauthenticated':
      case 'session_expired':
        return new VaultError('session_expired');
      case 'device_revoked':
        return new VaultError('device_revoked');
      case 'device_not_enrolled':
        return new VaultError('device_not_enrolled');
      default:
        return new VaultError('internal');
    }
  }
  return new VaultError('internal');
}

export class VaultEngine {
  private session: Session | undefined;
  private setup: PendingSetup | undefined;
  /** Serializes every state change, so a save never interleaves with a sync. */
  private queue: Promise<unknown> = Promise.resolve();

  constructor(private readonly deps: EngineDeps) {}

  /** Resolves when every queued operation, background syncs included, has finished. */
  async idle(): Promise<void> {
    let seen: Promise<unknown> | undefined;
    while (seen !== this.queue) {
      seen = this.queue;
      await seen;
    }
  }

  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const run = this.queue.then(task, task);
    this.queue = run.catch(() => undefined);
    return run;
  }

  // ---- Device phase ----

  async phase(): Promise<DevicePhase> {
    const device = await this.deps.store.device();
    if (!device) return { phase: 'new' };
    return device.status === 'active' && device.enrolled
      ? { phase: 'enrolled', username: device.username, deviceId: device.deviceId }
      : { phase: 'pending', username: device.username, deviceId: device.deviceId };
  }

  // ---- Account setup (authentication.md §3, device-enrollment.md §2, account-recovery.md §2) ----

  async setupBegin(params: {
    bootstrapToken: string;
    username: string;
    password: string;
  }): Promise<RecoveryKitView> {
    const { crypto, api, opaque } = this.deps;
    if (await this.deps.store.device()) throw new VaultError('registration_closed');
    const username = normalizeUsername(params.username);
    if (!username) throw new VaultError('invalid_username');
    if (!checkMasterPassword(params.password).ok) throw new VaultError('invalid_password');
    const password = normalizePassword(params.password);
    const token = params.bootstrapToken.trim();
    if (!/^[A-Za-z0-9_-]{43}$/.test(token)) throw new VaultError('bootstrap_failed');

    const registration = opaque.startRegistration(password);
    let response: string;
    try {
      ({ registrationResponse: response } = await api.registerStart({
        bootstrapToken: token,
        username,
        registrationRequest: registration.registrationRequest,
      }));
    } catch (error) {
      if (error instanceof ApiError && error.code === 'not_found')
        throw new VaultError('registration_closed');
      throw vaultErrorFrom(error);
    }
    const registrationRecord = opaque.finishRegistration(
      registration.clientRegistrationState,
      response,
      password,
    );

    // Every key comes from the CSPRNG on this device (device-enrollment.md §2 step 1).
    const accountId = crypto.generateUuid();
    const accountIdBytes = uuidToBytes(accountId);
    const deviceId = crypto.generateUuid();
    const vaultId = crypto.generateUuid();
    const secretKey = crypto.generateKey();
    const accountKey = crypto.generateKey();
    const accountKeyId = crypto.generateKeyId();
    const vaultKey = crypto.generateKey();
    const vaultKeyId = crypto.generateKeyId();
    const passwordSalt = crypto.generatePasswordSalt();
    const { recoveryKey, recoveryKeyId } = crypto.generateRecoveryKey();
    const recovery = crypto.deriveRecoveryKeys(recoveryKey);
    const auk = crypto.deriveAccountUnlockKey({
      password,
      passwordSalt,
      profile: DEFAULT_KDF_PROFILE,
      secretKey,
      accountId: accountIdBytes,
    });
    const wrappedAkPassword = crypto.wrapAccountKey({
      accountUnlockKey: auk,
      accountKey,
      accountId: accountIdBytes,
      accountKeyId,
      accountKeyEpoch: 1,
      profile: DEFAULT_KDF_PROFILE,
      passwordSalt,
    });
    auk.fill(0);
    const wrappedAkRecovery = crypto.wrapAccountKeyForRecovery({
      recoveryWrapKey: recovery.recoveryWrapKey,
      recoveryKeyId,
      accountId: accountIdBytes,
      accountKeyId,
      accountKeyEpoch: 1,
      accountKey,
    });
    const recoveryVerifier = crypto.recoveryVerifier(recovery.recoveryAuthKey);
    recovery.recoveryWrapKey.fill(0);
    recovery.recoveryAuthKey.fill(0);
    const keyset = crypto.sealKeyset({
      accountKey,
      accountKeyId,
      accountId: accountIdBytes,
      keysetVersion: 1,
      keyset: { secretKey, vaults: [{ vaultId, vkId: vaultKeyId, vk: vaultKey }] },
    });
    const recoveryKeyText = crypto.formatRecoveryKey(recoveryKey);
    // RK is shown once and never stored (cryptographic-design §6).
    recoveryKey.fill(0);

    this.setup = {
      username,
      password,
      bootstrapToken: token,
      registrationRecord,
      accountId,
      deviceId,
      vaultId,
      secretKey,
      accountKey,
      accountKeyId,
      vaultKey,
      vaultKeyId,
      passwordSalt,
      recoveryKeyId,
      wrappedAkPassword,
      wrappedAkRecovery,
      recoveryVerifier,
      keyset,
      verified: false,
    };
    return {
      recoveryKey: recoveryKeyText,
      recoveryKeyIdShort: toB64(recoveryKeyId).slice(0, 8),
      username,
      serverOrigin: this.deps.origin,
      createdAtMs: this.deps.now(),
    };
  }

  /** The kit must open the new recovery wrap before setup can finish (D-06). */
  setupVerifyKit(params: { recoveryKey: string }): Promise<true> {
    const setup = this.setup;
    if (!setup) return Promise.reject(new VaultError('internal'));
    const { crypto } = this.deps;
    let rk: Uint8Array;
    try {
      rk = crypto.parseRecoveryKey(params.recoveryKey);
    } catch {
      return Promise.reject(new VaultError('invalid_recovery_key'));
    }
    const keys = crypto.deriveRecoveryKeys(rk);
    rk.fill(0);
    try {
      const ak = crypto.unwrapAccountKeyForRecovery({
        recoveryWrapKey: keys.recoveryWrapKey,
        recoveryKeyId: setup.recoveryKeyId,
        accountId: uuidToBytes(setup.accountId),
        accountKeyId: setup.accountKeyId,
        accountKeyEpoch: 1,
        envelope: setup.wrappedAkRecovery,
      });
      const matches = same(ak, setup.accountKey);
      ak.fill(0);
      if (!matches) return Promise.reject(new VaultError('kit_mismatch'));
    } catch {
      return Promise.reject(new VaultError('kit_mismatch'));
    } finally {
      keys.recoveryWrapKey.fill(0);
      keys.recoveryAuthKey.fill(0);
    }
    setup.verified = true;
    return Promise.resolve(true);
  }

  setupFinish(): Promise<UnlockedVault> {
    return this.exclusive(async () => {
      const setup = this.setup;
      if (!setup?.verified) throw new VaultError('kit_mismatch');
      try {
        await this.deps.api.registerFinish({
          bootstrapToken: setup.bootstrapToken,
          username: setup.username,
          registrationRecord: setup.registrationRecord,
          accountId: setup.accountId,
          device: { id: setup.deviceId, platform: 'web' },
          keys: {
            kdfProfile: 1,
            saltPw: toB64(setup.passwordSalt),
            akId: toB64(setup.accountKeyId),
            akEpoch: 1,
            wrappedAkPassword: toB64(setup.wrappedAkPassword),
            recoveryKeyId: toB64(setup.recoveryKeyId),
            wrappedAkRecovery: toB64(setup.wrappedAkRecovery),
            recoveryVerifier: toB64(setup.recoveryVerifier),
            keysetVersion: 1,
            keyset: toB64(setup.keyset),
          },
          vault: { id: setup.vaultId, vkId: toB64(setup.vaultKeyId) },
        });
      } catch (error) {
        if (error instanceof ApiError && error.code === 'not_found')
          throw new VaultError('registration_closed');
        throw vaultErrorFrom(error);
      }
      // Stored only after the server accepted the account (device-enrollment.md §2 step 6).
      const device: DeviceRecord & { enrolled: EnrolledKeys } = {
        v: 1,
        accountId: setup.accountId,
        deviceId: setup.deviceId,
        username: setup.username,
        status: 'active',
        enrolled: {
          secretKey: setup.secretKey,
          kdfProfile: 1,
          saltPw: setup.passwordSalt,
          akId: setup.accountKeyId,
          akEpoch: 1,
          wrappedAkPassword: setup.wrappedAkPassword,
          keysetVersion: 1,
          keyset: setup.keyset,
          vaultId: setup.vaultId,
          vkId: setup.vaultKeyId,
        },
      };
      await this.deps.store.putDevice(device);
      this.session = this.newSession(device, setup.accountKey, setup.vaultKey, {
        vaultId: setup.vaultId,
        seq: 0,
        manifestHash: ZERO_HASH,
        keysetVersion: 1,
      });
      this.setup = undefined;
      await this.persistLocal({ checkpoint: true });
      await this.syncNow();
      return this.unlockedView();
    });
  }

  // ---- Login on a new device (it becomes pending until it is paired) ----

  async login(params: { username: string; password: string }): Promise<DevicePhase> {
    const username = normalizeUsername(params.username);
    if (!username) throw new VaultError('login_failed');
    let password: string;
    try {
      password = normalizePassword(params.password);
    } catch {
      throw new VaultError('login_failed');
    }
    const existing = await this.deps.store.device();
    const result = await this.opaqueLogin(username, password, existing?.deviceId);
    if (result.device.status === 'active' && existing?.enrolled) {
      return { phase: 'enrolled', username, deviceId: existing.deviceId };
    }
    await this.deps.store.putDevice({
      v: 1,
      accountId: result.accountId,
      deviceId: result.device.id,
      username,
      status: 'pending',
    });
    return { phase: 'pending', username, deviceId: result.device.id };
  }

  private async opaqueLogin(username: string, password: string, deviceId?: string) {
    const { api, opaque } = this.deps;
    const client = opaque.startLogin(password);
    try {
      const start = await api.loginStart({
        username,
        startLoginRequest: client.startLoginRequest,
        platform: 'web',
        ...(deviceId ? { deviceId } : {}),
      });
      const finish = opaque.finishLogin(client.clientLoginState, start.loginResponse, password);
      // A wrong password and a tampered server response look the same (authentication.md §4).
      if (finish === undefined) throw new VaultError('login_failed');
      return await api.loginFinish({ loginId: start.loginId, finishLoginRequest: finish });
    } catch (error) {
      throw vaultErrorFrom(error);
    }
  }

  // ---- Unlock (offline-capable) and session restore ----

  unlock(params: { password: string }): Promise<UnlockedVault> {
    return this.exclusive(async () => {
      const device = await this.deps.store.device();
      if (!device?.enrolled || device.status !== 'active')
        throw new VaultError('device_not_enrolled');
      const enrolled = device.enrolled;
      const { crypto } = this.deps;
      let password: string;
      try {
        password = normalizePassword(params.password);
      } catch {
        throw new VaultError('wrong_password');
      }
      const accountId = uuidToBytes(device.accountId);
      const auk = crypto.deriveAccountUnlockKey({
        password,
        passwordSalt: enrolled.saltPw,
        profile: enrolled.kdfProfile,
        secretKey: enrolled.secretKey,
        accountId,
      });
      let accountKey: Uint8Array;
      try {
        accountKey = crypto.unwrapAccountKey({
          accountUnlockKey: auk,
          accountId,
          accountKeyId: enrolled.akId,
          accountKeyEpoch: enrolled.akEpoch,
          profile: enrolled.kdfProfile,
          passwordSalt: enrolled.saltPw,
          envelope: enrolled.wrappedAkPassword,
        });
      } catch {
        // During unlock, a failing password wrap means a wrong password (§7).
        throw new VaultError('wrong_password');
      } finally {
        auk.fill(0);
      }
      const keyset = crypto.openKeyset({
        accountKey,
        accountKeyId: enrolled.akId,
        accountId,
        keysetVersion: enrolled.keysetVersion,
        envelope: enrolled.keyset,
      });
      const vault = keyset.vaults[0];
      if (!same(keyset.secretKey, enrolled.secretKey) || vault.vaultId !== enrolled.vaultId)
        throw new VaultError('internal');
      const session = this.newSession(
        { ...device, enrolled },
        accountKey,
        vault.vk,
        await this.loadCheckpoint(device, accountKey, enrolled),
      );
      this.session = session;
      await this.loadLocalState();
      const sessionProblem = await this.restoreSession(device, password);
      if (sessionProblem === undefined) {
        await this.refreshKeyset(session);
        await this.syncNow();
      } else session.state = sessionProblem === 'offline' ? 'offline' : 'session_expired';
      return { ...this.unlockedView(), ...(sessionProblem ? { sessionProblem } : {}) };
    });
  }

  /**
   * Locking is local (D-23), so an unlock may find the server session gone. The password is
   * already in hand, so it logs in again for this device. A failure leaves the vault usable
   * offline and is reported.
   */
  private async restoreSession(
    device: DeviceRecord,
    password: string,
  ): Promise<UnlockedVault['sessionProblem'] | undefined> {
    try {
      const current = await this.deps.api.currentDevice();
      if (current.id === device.deviceId && current.status === 'active') return undefined;
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'offline') return 'offline';
      if (e.code === 'device_revoked') return this.revoked();
      if (e.code !== 'session_expired') return 'offline';
    }
    try {
      const result = await this.opaqueLogin(device.username, password, device.deviceId);
      return result.device.status === 'active' ? undefined : 'login_failed';
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'device_revoked') return this.revoked();
      if (e.code === 'rate_limited') return 'rate_limited';
      if (e.code === 'offline') return 'offline';
      return 'login_failed';
    }
  }

  /**
   * INV-09: the keyset version never goes backwards. A newer keyset (vault creation, `SK` or
   * full rotation, none of which this client performs yet) must open under the current `AK` and
   * carry the same `SK` and vault; anything else stops sync instead of being trusted.
   */
  private async refreshKeyset(session: Session): Promise<void> {
    let remote;
    try {
      remote = await this.deps.api.accountKeys();
    } catch {
      return;
    }
    const local = session.device.enrolled;
    if (remote.keysetVersion < local.keysetVersion) {
      this.integrity(session, 'keyset_rollback');
      return;
    }
    if (remote.keysetVersion === local.keysetVersion) return;
    try {
      const keyset = this.deps.crypto.openKeyset({
        accountKey: session.accountKey,
        accountKeyId: fromB64(remote.akId),
        accountId: uuidToBytes(session.device.accountId),
        keysetVersion: remote.keysetVersion,
        envelope: fromB64(remote.keyset),
      });
      if (!same(keyset.secretKey, local.secretKey) || keyset.vaults[0].vaultId !== local.vaultId) {
        this.integrity(session, 'keyset_changed');
        return;
      }
    } catch {
      this.integrity(session, 'keyset_invalid');
      return;
    }
    const device = {
      ...session.device,
      enrolled: { ...local, keysetVersion: remote.keysetVersion, keyset: fromB64(remote.keyset) },
    };
    await this.deps.store.putDevice(device);
    session.device = device;
  }

  /** The server revoked this device: the client wipes itself (P2-11) and the UI locks. */
  private async revoked(): Promise<never> {
    await this.deps.store.wipe();
    this.session = undefined;
    this.deps.emit({ event: 'ended', reason: 'device_revoked' });
    throw new VaultError('device_revoked');
  }

  private newSession(
    device: DeviceRecord & { enrolled: EnrolledKeys },
    accountKey: Uint8Array,
    vaultKey: Uint8Array,
    checkpoint: Checkpoint,
  ): Session {
    return {
      device,
      accountKey,
      accountKeyId: device.enrolled.akId,
      deviceIdBytes: uuidToBytes(device.deviceId),
      vault: { vaultId: device.enrolled.vaultId, vaultKey, vaultKeyId: device.enrolled.vkId },
      synced: new Map(),
      checkpoint,
      pending: [],
      inflight: null,
      sent: [],
      conflicts: new Map(),
      bodies: new Map(),
      lastSyncedAtMs: null,
      lastChange: null,
      state: 'syncing',
      integrity: undefined,
    };
  }

  private requireSession(): Session {
    if (!this.session) throw new VaultError('locked');
    return this.session;
  }

  // ---- Local records ----

  private sealLocal(session: Session, name: string, value: unknown): Uint8Array {
    return this.deps.crypto.sealLocalRecord({
      accountKey: session.accountKey,
      accountKeyId: session.accountKeyId,
      deviceId: session.deviceIdBytes,
      name,
      plaintext: utf8(JSON.stringify(value)),
    });
  }

  private openLocal(
    accountKey: Uint8Array,
    accountKeyId: Uint8Array,
    deviceId: Uint8Array,
    name: string,
    envelope: Uint8Array,
  ): unknown {
    return JSON.parse(
      fromUtf8(
        this.deps.crypto.openLocalRecord({ accountKey, accountKeyId, deviceId, name, envelope }),
      ),
    );
  }

  private async loadCheckpoint(
    device: DeviceRecord,
    accountKey: Uint8Array,
    enrolled: EnrolledKeys,
  ): Promise<Checkpoint> {
    const envelope = await this.deps.store.local('checkpoint');
    if (!envelope)
      return {
        vaultId: enrolled.vaultId,
        seq: 0,
        manifestHash: ZERO_HASH,
        keysetVersion: enrolled.keysetVersion,
      };
    const parsed = checkpointSchema.parse(
      this.openLocal(
        accountKey,
        enrolled.akId,
        uuidToBytes(device.deviceId),
        'checkpoint',
        envelope,
      ),
    );
    return { ...parsed, manifestHash: fromB64(parsed.manifestHash) };
  }

  /** Records, pending queue and conflicts from the device store; records are decrypted here. */
  private async loadLocalState(): Promise<void> {
    const session = this.requireSession();
    const { store } = this.deps;
    for (const row of await store.records())
      session.synced.set(row.itemId, { revision: row.revision, record: row.record });
    const open = (name: string, envelope: Uint8Array | undefined) =>
      envelope
        ? this.openLocal(
            session.accountKey,
            session.accountKeyId,
            session.deviceIdBytes,
            name,
            envelope,
          )
        : undefined;
    const pending = open('pending', await store.local('pending'));
    if (pending !== undefined) {
      const p = pendingSchema.parse(pending);
      const toMutation = (m: z.infer<typeof mutationSchema>): PendingMutation => ({
        itemId: m.itemId,
        baseRevision: m.baseRevision,
        record: m.record === null ? null : fromB64(m.record),
      });
      session.pending = p.mutations.map(toMutation);
      session.inflight = p.inflight
        ? {
            body: p.inflight.body,
            manifestHash: fromB64(p.inflight.manifestHash),
            mutations: p.inflight.mutations.map(toMutation),
          }
        : null;
      session.sent = p.sent;
    }
    const conflicts = open('conflicts', await store.local('conflicts'));
    if (conflicts !== undefined)
      for (const c of conflictsSchema.parse(conflicts))
        session.conflicts.set(c.itemId, {
          ...c,
          localRecord: c.localRecord === null ? null : fromB64(c.localRecord),
        });
  }

  private async persistLocal(parts: {
    checkpoint?: boolean;
    pending?: boolean;
    conflicts?: boolean;
  }) {
    const session = this.requireSession();
    const local: Record<string, Uint8Array | null> = {};
    if (parts.checkpoint)
      local.checkpoint = this.sealLocal(session, 'checkpoint', {
        ...session.checkpoint,
        manifestHash: toB64(session.checkpoint.manifestHash),
      });
    if (parts.pending)
      local.pending = this.sealLocal(session, 'pending', this.pendingJson(session));
    if (parts.conflicts)
      local.conflicts = this.sealLocal(
        session,
        'conflicts',
        [...session.conflicts.values()].map((c) => ({
          ...c,
          localRecord: c.localRecord === null ? null : toB64(c.localRecord),
        })),
      );
    await this.deps.store.apply({ local });
  }

  private pendingJson(session: Session) {
    const json = (m: PendingMutation) => ({
      itemId: m.itemId,
      baseRevision: m.baseRevision,
      record: m.record === null ? null : toB64(m.record),
    });
    return {
      mutations: session.pending.map(json),
      inflight: session.inflight
        ? {
            body: session.inflight.body,
            manifestHash: toB64(session.inflight.manifestHash),
            mutations: session.inflight.mutations.map(json),
          }
        : null,
      sent: session.sent,
    };
  }

  // ---- Items ----

  private openBody(session: Session, itemId: string, revision: number, record: Uint8Array) {
    try {
      const bytes = this.deps.crypto.openItemRecord({
        vaultKey: session.vault.vaultKey,
        vaultKeyId: session.vault.vaultKeyId,
        vaultId: uuidToBytes(session.vault.vaultId),
        itemId: uuidToBytes(itemId),
        revision,
        schemaVersion: ITEM_SCHEMA_VERSION,
        record,
      });
      const body = decodeItemBody(bytes);
      bytes.fill(0);
      return body ?? null;
    } catch {
      return null;
    }
  }

  /** The current view: synced items overlaid with this device's pending changes. */
  private effective(
    session: Session,
  ): Map<string, { revision: number; record: Uint8Array | null; pending: boolean }> {
    const out = new Map<
      string,
      { revision: number; record: Uint8Array | null; pending: boolean }
    >();
    for (const [id, item] of session.synced) out.set(id, { ...item, pending: false });
    for (const m of [...(session.inflight?.mutations ?? []), ...session.pending])
      out.set(m.itemId, { revision: m.baseRevision + 1, record: m.record, pending: true });
    return out;
  }

  private body(
    session: Session,
    itemId: string,
    revision: number,
    record: Uint8Array,
  ): ItemBody | null {
    const cached = session.bodies.get(itemId);
    if (cached?.revision === revision && cached.body !== null) return cached.body;
    const body = this.openBody(session, itemId, revision, record);
    session.bodies.set(itemId, { revision, body });
    return body;
  }

  private summaries(session: Session): ItemSummary[] {
    const out: ItemSummary[] = [];
    for (const [id, item] of this.effective(session)) {
      if (item.record === null) continue;
      const body = this.body(session, id, item.revision, item.record);
      out.push(summaryOf(id, body, item.pending, session.conflicts.get(id)?.kind ?? null));
    }
    return out;
  }

  items(): ItemSummary[] {
    return this.summaries(this.requireSession());
  }

  private current(
    session: Session,
    id: string,
  ): { revision: number; record: Uint8Array; body: ItemBody } {
    const item = this.effective(session).get(id);
    if (!item?.record) throw new VaultError('not_found');
    const body = this.body(session, id, item.revision, item.record);
    if (!body) throw new VaultError('not_found');
    return { revision: item.revision, record: item.record, body };
  }

  detail(params: { id: string }): ItemDetail {
    const session = this.requireSession();
    const { body } = this.current(session, params.id);
    const pending = this.effective(session).get(params.id)?.pending ?? false;
    return detailOf(params.id, body, pending, session.conflicts.get(params.id)?.kind ?? null);
  }

  /** The stored password, on an explicit reveal, copy or edit by the user. */
  secret(params: { id: string }): string {
    const { body } = this.current(this.requireSession(), params.id);
    return body.type === 'login' ? body.login.password : '';
  }

  save(params: { draft: ItemDraft }): Promise<ItemSummary> {
    return this.exclusive(async () => {
      const session = this.writable();
      const draft = params.draft;
      const now = this.deps.now();
      const existing = draft.id ? this.current(session, draft.id) : undefined;
      const id = draft.id ?? this.deps.crypto.generateUuid();
      const base = {
        v: 1 as const,
        title: draft.title.trim(),
        favorite: draft.favorite,
        trashedAtMs: existing?.body.trashedAtMs ?? null,
        tags: [...draft.tags],
        createdAtMs: existing?.body.createdAtMs ?? now,
        updatedAtMs: now,
      };
      const body: ItemBody =
        draft.type === 'login'
          ? {
              ...base,
              type: 'login',
              login: {
                username: draft.username,
                password: draft.password,
                urls: draft.urls.filter((u) => u.trim() !== '').map((u) => u.trim()),
                notes: draft.notes,
              },
            }
          : { ...base, type: 'note', note: { text: draft.noteText } };
      return this.write(session, id, body);
    });
  }

  private update(id: string, change: (body: ItemBody) => ItemBody): Promise<ItemSummary> {
    return this.exclusive(async () => {
      const session = this.writable();
      const { body } = this.current(session, id);
      return this.write(session, id, { ...change(body), updatedAtMs: this.deps.now() });
    });
  }

  setFavorite(params: { id: string; favorite: boolean }) {
    return this.update(params.id, (b) => ({ ...b, favorite: params.favorite }));
  }

  trash(params: { id: string }) {
    return this.update(params.id, (b) => ({ ...b, trashedAtMs: this.deps.now() }));
  }

  restore(params: { id: string }) {
    return this.update(params.id, (b) => ({ ...b, trashedAtMs: null }));
  }

  /** Permanent deletion, from Trash only: the next revision is a tombstone (sync-protocol §8). */
  purge(params: { id: string }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.writable();
      const { body } = this.current(session, params.id);
      if (body.trashedAtMs === null) throw new VaultError('invalid_item');
      const synced = session.synced.get(params.id);
      session.pending = session.pending.filter((m) => m.itemId !== params.id);
      if (synced?.record)
        session.pending.push({ itemId: params.id, baseRevision: synced.revision, record: null });
      session.bodies.delete(params.id);
      await this.persistLocal({ pending: true });
      this.emitItems();
      void this.backgroundSync();
      return true as const;
    });
  }

  private writable(): Session {
    const session = this.requireSession();
    if (session.state === 'integrity_error') throw new VaultError('read_only');
    return session;
  }

  /** Seals the body at the next revision over the synced state and queues it (sync-protocol §7). */
  private async write(session: Session, id: string, body: ItemBody): Promise<ItemSummary> {
    let encoded: Uint8Array;
    try {
      encoded = encodeItemBody(body);
    } catch {
      throw new VaultError('invalid_item');
    }
    const synced = session.synced.get(id);
    const queued =
      session.pending.find((m) => m.itemId === id) ??
      session.inflight?.mutations.find((m) => m.itemId === id);
    if (synced?.record === null) throw new VaultError('not_found');
    const baseRevision = synced?.revision ?? 0;
    const previousRecord = queued?.record ?? synced?.record ?? undefined;
    const record = this.sealBody(
      session,
      id,
      baseRevision + 1,
      encoded,
      previousRecord ?? undefined,
    );
    encoded.fill(0);
    session.pending = session.pending.filter((m) => m.itemId !== id);
    session.pending.push({ itemId: id, baseRevision, record });
    session.bodies.set(id, { revision: baseRevision + 1, body });
    await this.persistLocal({ pending: true });
    this.emitItems();
    void this.backgroundSync();
    return summaryOf(id, body, true, session.conflicts.get(id)?.kind ?? null);
  }

  private sealBody(
    session: Session,
    id: string,
    revision: number,
    encoded: Uint8Array,
    previousRecord?: Uint8Array,
  ) {
    return this.deps.crypto.sealItemRecord({
      vaultKey: session.vault.vaultKey,
      vaultKeyId: session.vault.vaultKeyId,
      vaultId: uuidToBytes(session.vault.vaultId),
      itemId: uuidToBytes(id),
      revision,
      schemaVersion: ITEM_SCHEMA_VERSION,
      body: encoded,
      ...(previousRecord ? { previousRecord } : {}),
    });
  }

  // ---- Conflicts (sync-protocol §6) ----

  conflict(params: { id: string }): ConflictView {
    const session = this.requireSession();
    const c = session.conflicts.get(params.id);
    if (!c) throw new VaultError('not_found');
    const local = c.localRecord
      ? this.openBody(session, c.itemId, c.localRevision, c.localRecord)
      : null;
    const remote = session.synced.get(c.itemId);
    const remoteBody = remote?.record
      ? this.body(session, c.itemId, remote.revision, remote.record)
      : null;
    return {
      itemId: c.itemId,
      kind: c.kind,
      local: local ? detailOf(c.itemId, local, false, c.kind) : null,
      remote: remoteBody ? detailOf(c.itemId, remoteBody, false, c.kind) : null,
      remoteAuthor: 'another_device',
    };
  }

  resolveConflict(params: { id: string; choice: 'mine' | 'theirs' | 'both' }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.writable();
      const c = session.conflicts.get(params.id);
      if (!c) throw new VaultError('not_found');
      const local = c.localRecord
        ? this.openBody(session, c.itemId, c.localRevision, c.localRecord)
        : null;
      const remote = session.synced.get(c.itemId);
      session.conflicts.delete(c.itemId);
      if (params.choice === 'mine') {
        if (local === null) {
          // "Delete it again", based on the new remote revision.
          if (remote?.record)
            session.pending.push({ itemId: c.itemId, baseRevision: remote.revision, record: null });
        } else if (remote?.record) {
          await this.write(session, c.itemId, { ...local, updatedAtMs: this.deps.now() });
        } else {
          // Deleted elsewhere: tombstoned ids are never reused, so restore as a new item.
          await this.write(session, this.deps.crypto.generateUuid(), {
            ...local,
            updatedAtMs: this.deps.now(),
          });
        }
      } else if (params.choice === 'both' && local !== null) {
        await this.write(session, this.deps.crypto.generateUuid(), {
          ...local,
          title: `${local.title} (this device)`.slice(0, 200),
          updatedAtMs: this.deps.now(),
        });
      }
      await this.persistLocal({ pending: true, conflicts: true });
      this.emitItems();
      void this.backgroundSync();
      return true as const;
    });
  }

  // ---- Sync ----

  sync(): Promise<SyncStatus> {
    return this.exclusive(() => this.syncNow());
  }

  private backgroundSync(): Promise<void> {
    return this.exclusive(() => this.syncNow()).then(
      () => undefined,
      () => undefined,
    );
  }

  private async syncNow(): Promise<SyncStatus> {
    const session = this.session;
    if (!session) throw new VaultError('locked');
    if (session.state === 'integrity_error') return this.status(session);
    session.state = 'syncing';
    this.emitStatus(session);
    try {
      await this.pull(session);
      if (!readOnly(session)) await this.push(session);
      if (!readOnly(session)) {
        session.state = session.pending.length > 0 || session.inflight ? 'pending' : 'synced';
        session.lastSyncedAtMs = this.deps.now();
      }
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'device_revoked') await this.revoked();
      if (e.code === 'session_expired') {
        session.state = 'session_expired';
        this.deps.emit({ event: 'ended', reason: 'session_expired' });
      } else {
        session.state = 'offline';
      }
    }
    this.emitStatus(session);
    return this.status(session);
  }

  private async pull(session: Session): Promise<void> {
    const pages: SyncChangesResponse[] = [];
    let since = session.checkpoint.seq;
    for (let i = 0; i < 10_000; i++) {
      const page = await this.deps.api.changes(since);
      pages.push(page);
      if (page.nextCursor === undefined) break;
      if (page.nextCursor <= since) {
        this.integrity(session, 'sequence_gap');
        return;
      }
      since = page.nextCursor;
    }
    const result = verifyPages(
      this.deps.crypto,
      session.vault,
      session.checkpoint,
      session.synced,
      pages,
      (itemId, revision, record) => this.openBody(session, itemId, revision, record) !== null,
    );
    if (!result.ok) {
      this.integrity(session, result.reason);
      return;
    }
    if (!result.newest) return;
    const records = result.changed.map((itemId) => {
      const item = result.state.get(itemId);
      return { itemId, revision: item?.revision ?? 0, record: item?.record ?? null };
    });
    session.synced = result.state;
    session.checkpoint = result.checkpoint;
    for (const id of result.changed) session.bodies.delete(id);
    session.lastChange = {
      atMs: result.newest.manifest.createdAtMs,
      byThisDevice:
        uuidFromBytes(result.newest.manifest.authorDeviceId) === session.device.deviceId,
    };
    await this.deps.store.apply({
      records,
      manifest: { seq: result.newest.seq, envelope: result.newest.envelope },
      local: {
        checkpoint: this.sealLocal(session, 'checkpoint', {
          ...session.checkpoint,
          manifestHash: toB64(session.checkpoint.manifestHash),
        }),
      },
    });
    await this.rebasePending(session);
    this.emitItems();
  }

  /**
   * After a verified pull, every pending change whose base moved is either this device's own
   * earlier upload (re-sealed on top of it) or a real conflict for the user to resolve.
   */
  private async rebasePending(session: Session): Promise<void> {
    const own = (itemId: string) => {
      const remote = session.synced.get(itemId);
      if (!remote) return false;
      const hash =
        remote.record === null ? null : toB64(this.deps.crypto.recordHash(remote.record));
      return session.sent.some(
        (s) => s.itemId === itemId && s.revision === remote.revision && s.recordHash === hash,
      );
    };
    const now = this.deps.now();
    const kept: PendingMutation[] = [];
    for (const m of session.pending) {
      const remote = session.synced.get(m.itemId);
      const remoteRevision = remote?.revision ?? 0;
      if (remoteRevision === m.baseRevision || !own(m.itemId)) {
        kept.push(m);
        continue;
      }
      // Our own change landed first: move this newer change on top of it.
      if (m.record === null) {
        if (remote?.record)
          kept.push({ itemId: m.itemId, baseRevision: remoteRevision, record: null });
        continue;
      }
      const body = this.openBody(session, m.itemId, m.baseRevision + 1, m.record);
      if (!body) continue;
      const encoded = encodeItemBody(body);
      kept.push({
        itemId: m.itemId,
        baseRevision: remoteRevision,
        record: this.sealBody(
          session,
          m.itemId,
          remoteRevision + 1,
          encoded,
          remote?.record ?? m.record,
        ),
      });
      encoded.fill(0);
    }
    const { keep, conflicts } = rebase(kept, session.synced, now);
    session.pending = keep;
    for (const c of conflicts) session.conflicts.set(c.itemId, c);
    session.sent = session.sent.filter(
      (s) => (session.synced.get(s.itemId)?.revision ?? 0) < s.revision,
    );
    await this.persistLocal({ pending: true, conflicts: conflicts.length > 0 });
  }

  private async push(session: Session): Promise<void> {
    for (let round = 0; round < MAX_PUSH_ROUNDS; round++) {
      if (!session.inflight) {
        const genesis = session.checkpoint.seq === 0;
        if (session.pending.length === 0 && !genesis) return;
        const mutations = session.pending.slice(0, MAX_MUTATIONS_PER_COMMIT);
        const built = buildCommit(
          this.deps.crypto,
          session.vault,
          session.device.deviceId,
          session.checkpoint,
          session.synced,
          mutations,
          this.deps.now(),
        );
        session.pending = session.pending.slice(mutations.length);
        session.inflight = { body: built.body, manifestHash: built.manifestHash, mutations };
        for (const m of mutations)
          session.sent.push({
            itemId: m.itemId,
            revision: m.baseRevision + 1,
            recordHash: m.record === null ? null : toB64(this.deps.crypto.recordHash(m.record)),
          });
        // Persisted before the first attempt, so a retry after a crash reuses the commit id.
        await this.persistLocal({ pending: true });
      }
      const inflight = session.inflight;
      try {
        const { seq } = await this.deps.api.commit(inflight.body);
        const state = new Map(session.synced);
        for (const m of inflight.mutations)
          state.set(m.itemId, { revision: m.baseRevision + 1, record: m.record });
        session.synced = state;
        session.checkpoint = { ...session.checkpoint, seq, manifestHash: inflight.manifestHash };
        session.inflight = null;
        session.lastChange = { atMs: this.deps.now(), byThisDevice: true };
        await this.deps.store.apply({
          records: inflight.mutations.map((m) => ({
            itemId: m.itemId,
            revision: m.baseRevision + 1,
            record: m.record,
          })),
          manifest: { seq, envelope: fromB64(inflight.body.manifest) },
          local: {
            checkpoint: this.sealLocal(session, 'checkpoint', {
              ...session.checkpoint,
              manifestHash: toB64(session.checkpoint.manifestHash),
            }),
            pending: this.sealLocal(session, 'pending', this.pendingJson(session)),
          },
        });
        await this.rebasePending(session);
        this.emitItems();
      } catch (error) {
        if (
          error instanceof ApiError &&
          (error.code === 'seq_conflict' ||
            error.code === 'revision_conflict' ||
            error.code === 'idempotency_mismatch')
        ) {
          // Not applied: put the changes back (newer edits win), pull, and rebase.
          const newer = new Set(session.pending.map((m) => m.itemId));
          session.pending = [
            ...inflight.mutations.filter((m) => !newer.has(m.itemId)),
            ...session.pending,
          ];
          session.inflight = null;
          await this.persistLocal({ pending: true });
          await this.pull(session);
          if (readOnly(session)) return;
          // The returned changes were based on the state before the pull; rebase them now even
          // if this pull found nothing new (an earlier pull may have moved the base).
          await this.rebasePending(session);
          continue;
        }
        throw error;
      }
    }
  }

  private integrity(session: Session, reason: string): void {
    // Nothing is applied; the vault stays readable from the local copy (cryptographic-design §7).
    session.state = 'integrity_error';
    session.integrity = reason;
  }

  private status(session: Session): SyncStatus {
    return {
      state: session.state,
      pendingCount: session.pending.length + (session.inflight?.mutations.length ?? 0),
      lastSyncedAtMs: session.lastSyncedAtMs,
      lastChange: session.lastChange,
      ...(session.integrity ? { integrity: session.integrity } : {}),
    };
  }

  private emitStatus(session: Session): void {
    this.deps.emit({ event: 'sync', status: this.status(session) });
  }

  private emitItems(): void {
    if (this.session) this.deps.emit({ event: 'items', items: this.summaries(this.session) });
  }

  private unlockedView(): UnlockedVault {
    const session = this.requireSession();
    return {
      username: session.device.username,
      deviceId: session.device.deviceId,
      items: this.summaries(session),
      sync: this.status(session),
    };
  }

  async logout(): Promise<true> {
    try {
      await this.deps.api.logout();
    } catch {
      // Offline or already expired: the local lock still happens.
    }
    return true;
  }

  /** Best-effort zeroing before the worker is terminated (sync-protocol §Memory and lock). */
  wipeMemory(): void {
    const session = this.session;
    if (session) {
      session.accountKey.fill(0);
      session.vault.vaultKey.fill(0);
      session.bodies.clear();
    }
    this.session = undefined;
    this.setup = undefined;
  }
}

function summaryOf(
  id: string,
  body: ItemBody | null,
  pending: boolean,
  conflict: ItemSummary['conflict'],
): ItemSummary {
  if (!body)
    return {
      id,
      type: 'note',
      title: 'Unreadable item',
      subtitle: 'This item could not be decrypted. Its data is kept unchanged.',
      favorite: false,
      trashed: false,
      tags: [],
      urls: [],
      updatedAtMs: 0,
      pending,
      conflict,
    };
  return {
    id,
    type: body.type,
    title: body.title,
    subtitle:
      body.type === 'login'
        ? body.login.username
        : (body.note.text.split('\n')[0] ?? '').slice(0, 80),
    favorite: body.favorite,
    trashed: body.trashedAtMs !== null,
    tags: body.tags,
    urls: body.type === 'login' ? body.login.urls : [],
    updatedAtMs: body.updatedAtMs,
    pending,
    conflict,
  };
}

function detailOf(
  id: string,
  body: ItemBody,
  pending: boolean,
  conflict: ItemSummary['conflict'],
): ItemDetail {
  return {
    ...summaryOf(id, body, pending, conflict),
    username: body.type === 'login' ? body.login.username : '',
    hasPassword: body.type === 'login' && body.login.password !== '',
    notes: body.type === 'login' ? body.login.notes : '',
    noteText: body.type === 'note' ? body.note.text : '',
    createdAtMs: body.createdAtMs,
  };
}
