import {
  DEFAULT_KDF_PROFILE,
  normalizePassword,
  uuidFromBytes,
  uuidToBytes,
  type DeviceKeyPair,
  type ProofField,
  type ProofOperation,
  type RuveeCrypto,
} from '@ruvee/crypto';
import {
  commitRequestSchema,
  normalizeUsername,
  type CommitRequest,
  type SyncChangesResponse,
} from '@ruvee/contracts';
import { z } from 'zod';
import {
  decodeItemBody,
  encodeItemBody,
  ITEM_SCHEMA_VERSION,
  type ItemBody,
} from './item-schema.js';
import { checkMasterPassword } from './password-policy.js';
import type {
  ActivityPage,
  ConflictView,
  DeviceView,
  ExportView,
  DevicePhase,
  PairingCode,
  PairingHostStatus,
  PairingJoinStatus,
  ItemDetail,
  ItemDraft,
  ItemSummary,
  LocalExport,
  LocalStateView,
  RecoveryKitView,
  SyncStatus,
  UnlockedVault,
  VaultEvent,
} from './protocol.js';
import { ApiError, NetworkError, type Api } from './api.js';
import { fromB64, fromUtf8, toB64, utf8 } from './bytes.js';
import type { DeviceRecord, DeviceStore, EnrolledKeys, QueuedImport } from './store.js';
import { buildExport, openExport, type OpenedExport } from './export-file.js';
import { VaultError } from './vault-error.js';

export { VaultError } from './vault-error.js';
import {
  buildCommit,
  rebase,
  sameBytes,
  verifyPages,
  ZERO_HASH,
  type Anchor,
  type Checkpoint,
  type Conflict,
  type PendingMutation,
  type SyncedItem,
  type VaultKeys,
} from './sync-logic.js';

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
  /** What this client logs in and pairs as; registration and recovery are web-only. */
  readonly platform: 'web' | 'extension';
  readonly now: () => number;
  readonly emit: (event: VaultEvent) => void;
}

const MAX_MUTATIONS_PER_COMMIT = 100;
/** device-enrollment §3.1: a pairing and everything a device keeps for it live 10 minutes. */
const PAIRING_TTL_MS = 10 * 60_000;
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
  /**
   * `DSK` and `DPK` while unlocked (docs/security/device-proof.md §2): opened from the
   * `device-key` local record under `K_local`, wiped on lock. Undefined for a device enrolled
   * before D-31, which must re-enroll.
   */
  deviceKey: DeviceKeyPair | undefined;
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly deviceIdBytes: Uint8Array;
  readonly vault: VaultKeys;
  synced: Map<string, SyncedItem>;
  checkpoint: Checkpoint;
  /** Set on a device paired but not yet synced; cleared by the first verified pull. */
  anchor: Anchor | undefined;
  pending: PendingMutation[];
  inflight: Inflight | null;
  sent: SentRecord[];
  conflicts: Map<string, Conflict>;
  bodies: Map<string, { revision: number; body: ItemBody | null }>;
  lastSyncedAtMs: number | null;
  lastChange: SyncStatus['lastChange'];
  state: SyncStatus['state'];
  integrity: string | undefined;
  /** When the Recovery Kit was used, if this device has not acknowledged it (§3 step 2). */
  recoveryNotice: number | undefined;
  recoveryAcknowledgedMs: number;
  /** When the server says it was restored from a backup; wording only (protocol.ts). */
  serverRestore: number | undefined;
  /** The state a local export was made of (`localMark`), if one was made in this unlock. */
  localExportMark: string | undefined;
  /** An import into this vault (backup-restore.md §4.4a), if one was ever started here. */
  importState: ImportRecord | undefined;
  /** Queue position of each imported item handed to the pending queue, by item id. */
  importOrders: Map<string, number>;
  /** Items still in the `imports` store; refreshed whenever it changes. */
  importRemaining: number;
}

const importRecordSchema = z.strictObject({
  v: z.literal(1),
  state: z.enum(['uploading', 'complete']),
  total: z.int().min(0),
  /** The export's authenticated date and `seq`: what was restored, for the user. */
  sourceAsOfMs: z.int().min(0),
  sourceSeq: z.int().min(1),
  startedAtMs: z.int().min(0),
  completedAtMs: z.int().min(0).nullable(),
});
type ImportRecord = z.infer<typeof importRecordSchema>;

/** One upload batch from the import queue: at most a commit's mutations, and small enough that
 * the pending queue stays far below the 1 MiB local-record limit. */
const IMPORT_BATCH_ITEMS = MAX_MUTATIONS_PER_COMMIT;
const IMPORT_BATCH_BYTES = 256 * 1024;

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
      case 'not_found':
        return new VaultError('not_found');
      case 'row_version_conflict':
        return new VaultError('changed_elsewhere');
      case 'maintenance':
        return new VaultError('server_maintenance');
      case 'reopening':
        return new VaultError('server_reopening');
      case 'reopen_failed':
        return new VaultError('reopen_failed');
      // device-proof.md §5, §9: this device cannot prove its key to the server; it re-enrolls.
      case 'device_proof_required':
      case 'device_proof_failed':
        return new VaultError('device_key_missing');
      case 'device_key_mismatch':
        return new VaultError('integrity');
      default:
        return new VaultError('internal');
    }
  }
  return new VaultError('internal');
}

interface HostPairing {
  readonly secret: Uint8Array;
  readonly expiresAtMs: number;
  request?: {
    readonly deviceId: string;
    readonly epk: Uint8Array;
    /** B's `DPK`, verified inside `req_mac`; A signs its approval over it. */
    readonly devicePublicKey: Uint8Array;
    readonly platform: string;
    readonly requestedAtMs: number;
  };
}

interface PendingRecovery {
  readonly username: string;
  readonly accountId: string;
  readonly deviceId: string;
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  readonly accountKeyEpoch: number;
  readonly secretKey: Uint8Array;
  readonly vaultId: string;
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  readonly keysetVersion: number;
  readonly keyset: Uint8Array;
  readonly rowVersion: number;
  /** Set for a reopening (backup-restore.md §3.13): which path, and so which endpoints. */
  readonly reopen?: 'password' | 'recovery';
  /**
   * This browser already holds this account's vault under the same `AK` (the forgotten-password
   * case): its records, unsynced edits, conflicts and rollback floors are kept (review R6, R20).
   */
  readonly keepLocal: boolean;
  complete?: {
    readonly registrationRecord: string;
    readonly saltPw: Uint8Array;
    readonly wrappedAkPassword: Uint8Array;
    readonly recoveryKeyId: Uint8Array;
    readonly wrappedAkRecovery: Uint8Array;
    readonly recoveryVerifier: Uint8Array;
    verified: boolean;
  };
}

interface JoinPairing {
  readonly secret: Uint8Array;
  /** Device B's key, in memory only until B holds `AK` to seal it (device-proof.md §8). */
  readonly deviceKey: DeviceKeyPair;
  readonly pairingId: Uint8Array;
  readonly ephemeralPublicKey: Uint8Array;
  readonly ephemeralPrivateKey: Uint8Array;
  readonly expiresAtMs: number;
}

export class VaultEngine {
  private session: Session | undefined;
  private setup: PendingSetup | undefined;
  /** Device A: secrets of pairings this device started, by pairing id. */
  private readonly hosting = new Map<string, HostPairing>();
  /** Device B: the pairing it joined. */
  private joining: JoinPairing | undefined;
  /**
   * Device B keeps the password from its login for at most 10 minutes, to unwrap `AK` once the
   * reply arrives (§3.2 step 1); after that it asks again.
   */
  private pendingPassword: { readonly value: string; readonly expiresAtMs: number } | undefined;
  /** A new Recovery Kit made from Security, until it is verified and stored (§5). */
  private kitRotation:
    | {
        readonly recoveryKeyId: Uint8Array;
        readonly wrappedAkRecovery: Uint8Array;
        readonly recoveryVerifier: Uint8Array;
        verified: boolean;
      }
    | undefined;
  /** An export opened read-only (backup-restore.md §4.4): its bodies, in memory only. */
  private opened: OpenedExport | undefined;
  /** An unfinished recovery: what `RK` unlocked, then the new password and Recovery Key. */
  private recovery: PendingRecovery | undefined;
  /** Serializes every state change, so a save never interleaves with a sync. */
  private queue: Promise<unknown> = Promise.resolve();
  /** Bumped by every `wipeMemory` (a lock). */
  private generation = 0;
  /** The generation the running operation started in; undefined between operations. */
  private running: number | undefined;
  private readonly deps: EngineDeps;

  constructor(deps: EngineDeps) {
    this.deps = { ...deps, store: this.lockAware(deps.store) };
  }

  /**
   * Review R19: a lock can arrive while an operation waits on the network. Its keys are zeroed
   * at once, so whatever it would still write (records sealed under a zeroed key, a device
   * record without its keys) is refused, and so is a session it would install afterwards.
   */
  private lockAware(store: DeviceStore): DeviceStore {
    const assertCurrent = () => {
      if (this.running !== undefined && this.running !== this.generation)
        throw new VaultError('locked');
    };
    return new Proxy(store, {
      get: (target, key, receiver) => {
        const value: unknown = Reflect.get(target, key, receiver);
        if (typeof value !== 'function') return value;
        const method = value as (...args: unknown[]) => unknown;
        if (key === 'putDevice' || key === 'apply' || key === 'wipe')
          return (...args: unknown[]) => {
            assertCurrent();
            return method.apply(target, args);
          };
        return method.bind(target);
      },
    });
  }

  /** Resolves when every queued operation, background syncs included, has finished. */
  async idle(): Promise<void> {
    let seen: Promise<unknown> | undefined;
    while (seen !== this.queue) {
      seen = this.queue;
      await seen;
    }
  }

  private exclusive<T>(task: () => Promise<T>): Promise<T> {
    const guarded = async () => {
      const generation = this.generation;
      this.running = generation;
      try {
        const result = await task();
        // Locked while it ran: nothing it unlocked or derived may outlive the lock (R19).
        if (this.generation !== generation) {
          this.clearMemory();
          throw new VaultError('locked');
        }
        return result;
      } finally {
        this.running = undefined;
      }
    };
    const run = this.queue.then(guarded, guarded);
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
      const { crypto } = this.deps;
      // device-proof.md §8, first setup: this device's key and AK's proof key, both proved, bound
      // to the setup token; the server stores the public halves only.
      const deviceKey = crypto.generateDeviceKey();
      const akVerifyKey = crypto.accountProofPublicKey(setup.accountKey);
      const base = {
        operation: 'register' as const,
        accountId: uuidToBytes(setup.accountId),
        binding: crypto.setupBinding(fromB64(setup.bootstrapToken)),
        nonce: new Uint8Array(32),
        payload: crypto.proofPayload('register', [
          fromB64(setup.registrationRecord),
          deviceKey.publicKey,
          akVerifyKey,
          setup.wrappedAkPassword,
          setup.wrappedAkRecovery,
          setup.recoveryVerifier,
          setup.keyset,
          uuidToBytes(setup.vaultId),
        ]),
      };
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
          devicePublicKey: toB64(deviceKey.publicKey),
          akVerifyKey: toB64(akVerifyKey),
          proof: {
            device: toB64(
              crypto.signDeviceProof({
                ...base,
                deviceId: uuidToBytes(setup.deviceId),
                secretKey: deviceKey.secretKey,
              }),
            ),
            accountKey: toB64(
              crypto.signAccountProof({
                ...base,
                accountKey: setup.accountKey,
                accountKeyId: setup.accountKeyId,
                accountKeyEpoch: 1,
              }),
            ),
          },
        });
      } catch (error) {
        deviceKey.secretKey.fill(0);
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
      await this.storeDeviceKey(this.session, deviceKey);
      deviceKey.secretKey.fill(0);
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
    let result = await this.opaqueLogin(username, password, existing?.deviceId);
    if (result.device.status === 'active' && existing?.enrolled) {
      return { phase: 'enrolled', username, deviceId: existing.deviceId };
    }
    // An enrollment interrupted after approval (device-proof.md §8): the server's device is
    // active, but this browser never stored its key and cannot prove it. Start over as a new
    // device; the orphan row holds no privilege and is removed under Devices.
    if (result.device.status === 'active' && !existing?.enrolled)
      result = await this.opaqueLogin(username, password);
    await this.deps.store.putDevice({
      v: 1,
      accountId: result.accountId,
      deviceId: result.device.id,
      username,
      status: 'pending',
    });
    this.pendingPassword = { value: password, expiresAtMs: this.deps.now() + PAIRING_TTL_MS };
    return { phase: 'pending', username, deviceId: result.device.id };
  }

  /**
   * OPAQUE login. With `proof`, an enrolled device signs the challenge with its key and the
   * session is proven (device-proof.md §5); without it, an active device gets a pre-proof session.
   */
  private async opaqueLogin(
    username: string,
    password: string,
    deviceId?: string,
    proof?: { accountId: string; key: DeviceKeyPair },
  ) {
    const { api, opaque } = this.deps;
    const client = opaque.startLogin(password);
    try {
      const start = await api.loginStart({
        username,
        startLoginRequest: client.startLoginRequest,
        platform: this.deps.platform,
        ...(deviceId ? { deviceId } : {}),
      });
      const finish = opaque.finishLogin(client.clientLoginState, start.loginResponse, password);
      // A wrong password and a tampered server response look the same (authentication.md §4).
      if (finish === undefined) throw new VaultError('login_failed');
      return await api.loginFinish({
        loginId: start.loginId,
        finishLoginRequest: finish,
        ...(proof && deviceId
          ? {
              deviceProof: this.loginProof(
                'login',
                { accountId: proof.accountId, deviceId },
                proof.key,
                start,
                finish,
              ),
            }
          : {}),
      });
    } catch (error) {
      throw vaultErrorFrom(error);
    }
  }

  // ---- Unlock (offline-capable) and session restore ----

  /**
   * `previousPassword` is asked for only after `previous_password_required`: the password and
   * `SK` both changed elsewhere, so this device's old wrap opens only with the old password.
   */
  unlock(params: { password: string; previousPassword?: string }): Promise<UnlockedVault> {
    return this.exclusive(async () => {
      const device = await this.deps.store.device();
      if (!device?.enrolled || device.status !== 'active')
        throw new VaultError('device_not_enrolled');
      let enrolled = device.enrolled;
      const { crypto } = this.deps;
      let password: string;
      let localPassword: string;
      try {
        password = normalizePassword(params.password);
        localPassword =
          params.previousPassword === undefined
            ? password
            : normalizePassword(params.previousPassword);
      } catch {
        throw new VaultError('wrong_password');
      }
      const accountId = uuidToBytes(device.accountId);
      const auk = crypto.deriveAccountUnlockKey({
        password: localPassword,
        passwordSalt: enrolled.saltPw,
        profile: enrolled.kdfProfile,
        secretKey: enrolled.secretKey,
        accountId,
      });
      let accountKey: Uint8Array | undefined;
      let passwordUpdated = false;
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
        // The local wrap did not open: a wrong password, or a password changed on another
        // device (a password change or a recovery). Only the server can tell which.
        if (params.previousPassword !== undefined) throw new VaultError('wrong_password');
        const updated = await this.unlockWithServerWrap(device, enrolled, password);
        if (!updated) throw new VaultError('wrong_password');
        ({ accountKey, enrolled } = updated);
        passwordUpdated = true;
      } finally {
        auk.fill(0);
      }
      let session: Session;
      try {
        if (params.previousPassword !== undefined) {
          // The old wrap opened; the new password must open the server's wrap under the new SK.
          const updated = await this.adoptServerKeys(device, enrolled, password, accountKey);
          if (!updated) throw new VaultError('wrong_password');
          enrolled = updated;
          passwordUpdated = true;
        }
        const keyset = crypto.openKeyset({
          accountKey,
          accountKeyId: enrolled.akId,
          accountId,
          keysetVersion: enrolled.keysetVersion,
          envelope: enrolled.keyset,
        });
        const vault = keyset.vaults[0];
        if (!same(keyset.secretKey, enrolled.secretKey) || vault.vaultId !== enrolled.vaultId) {
          keyset.secretKey.fill(0);
          vault.vk.fill(0);
          throw new VaultError('internal');
        }
        session = this.newSession(
          { ...device, enrolled },
          accountKey,
          vault.vk,
          await this.loadCheckpoint(device, accountKey, enrolled),
        );
      } catch (error) {
        // Nothing holds AK yet: zero it before reporting the failure (INV-15, review R23).
        accountKey.fill(0);
        throw error;
      }
      this.session = session;
      await this.loadLocalState();
      session.deviceKey = await this.loadDeviceKey(session);
      const sessionProblem = await this.restoreSession(session, password);
      let secretKeyUpdated = false;
      if (sessionProblem === undefined) {
        secretKeyUpdated = await this.refreshKeyset(session, password);
        await this.syncNow();
      } else if (sessionProblem === 'maintenance' || sessionProblem === 'reopening') {
        session.state = sessionProblem;
      } else session.state = sessionProblem === 'offline' ? 'offline' : 'session_expired';
      return {
        ...this.unlockedView(),
        ...(sessionProblem ? { sessionProblem } : {}),
        ...(passwordUpdated ? { passwordUpdated } : {}),
        ...(secretKeyUpdated ? { secretKeyUpdated } : {}),
      };
    });
  }

  /**
   * D-27, extension only: a copy of `AK` for the host to keep in `chrome.storage.session` while
   * unlocked. It never goes through `dispatch`, so no UI can ask for it.
   */
  accountKeyForResume(): Uint8Array {
    return this.requireSession().accountKey.slice();
  }

  /**
   * D-27: rebuilds the unlocked state from `AK` after the extension's service worker restarted.
   * `AK` must open this device's own keyset; anything else is treated as locked. No password is
   * in hand, so a rotated `SK` is adopted only at the next unlock with the password.
   */
  resume(params: { accountKey: Uint8Array }): Promise<UnlockedVault> {
    return this.exclusive(async () => {
      const device = await this.deps.store.device();
      if (!device?.enrolled || device.status !== 'active') throw new VaultError('locked');
      const enrolled = device.enrolled;
      const accountKey = params.accountKey.slice();
      let keyset;
      try {
        keyset = this.deps.crypto.openKeyset({
          accountKey,
          accountKeyId: enrolled.akId,
          accountId: uuidToBytes(device.accountId),
          keysetVersion: enrolled.keysetVersion,
          envelope: enrolled.keyset,
        });
      } catch {
        accountKey.fill(0);
        throw new VaultError('locked');
      }
      const vault = keyset.vaults[0];
      if (!same(keyset.secretKey, enrolled.secretKey) || vault.vaultId !== enrolled.vaultId) {
        accountKey.fill(0);
        throw new VaultError('locked');
      }
      const session = this.newSession(
        { ...device, enrolled },
        accountKey,
        vault.vk,
        await this.loadCheckpoint(device, accountKey, enrolled),
      );
      this.session = session;
      await this.loadLocalState();
      session.deviceKey = await this.loadDeviceKey(session);
      await this.syncNow();
      return this.unlockedView();
    });
  }

  /**
   * authentication.md §9 step 4 ("online"): after the password changed elsewhere, the device
   * logs in with the new password, unwraps the new server wrap with its own `SK`, and replaces
   * its local wrap. A password that fails OPAQUE is a wrong password, whatever the local state.
   */
  private async unlockWithServerWrap(
    device: DeviceRecord,
    enrolled: EnrolledKeys,
    password: string,
  ): Promise<{ accountKey: Uint8Array; enrolled: EnrolledKeys } | undefined> {
    const { crypto, api } = this.deps;
    try {
      await this.opaqueLogin(device.username, password, device.deviceId);
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'device_revoked') return this.revoked();
      if (e.code === 'rate_limited') throw e;
      return undefined;
    }
    let keys;
    try {
      keys = await api.accountKeys();
    } catch {
      return undefined;
    }
    // OPAQUE accepted the password, but a newer keyset means `SK` changed too: this device
    // cannot open the server wrap until its old wrap gives it `AK` to read the new keyset.
    if (keys.keysetVersion > enrolled.keysetVersion)
      throw new VaultError('previous_password_required');
    const accountId = uuidToBytes(device.accountId);
    const saltPw = fromB64(keys.saltPw);
    const wrappedAkPassword = fromB64(keys.wrappedAkPassword);
    const auk = crypto.deriveAccountUnlockKey({
      password,
      passwordSalt: saltPw,
      profile: keys.kdfProfile,
      secretKey: enrolled.secretKey,
      accountId,
    });
    try {
      const accountKey = crypto.unwrapAccountKey({
        accountUnlockKey: auk,
        accountId,
        accountKeyId: fromB64(keys.akId),
        accountKeyEpoch: keys.akEpoch,
        profile: keys.kdfProfile,
        passwordSalt: saltPw,
        envelope: wrappedAkPassword,
      });
      const updated: EnrolledKeys = {
        ...enrolled,
        saltPw,
        wrappedAkPassword,
        kdfProfile: keys.kdfProfile,
      };
      await this.deps.store.putDevice({ ...device, enrolled: updated });
      return { accountKey, enrolled: updated };
    } catch {
      return undefined;
    } finally {
      auk.fill(0);
    }
  }

  /**
   * Locking is local (D-23), so an unlock may find the server session gone. The password is
   * already in hand, so it logs in again for this device. A failure leaves the vault usable
   * offline and is reported.
   */
  private async restoreSession(
    session: Session,
    password: string,
  ): Promise<UnlockedVault['sessionProblem'] | undefined> {
    const device = session.device;
    const key = session.deviceKey;
    const ids = { accountId: device.accountId, deviceId: device.deviceId };
    try {
      const current = await this.deps.api.currentDevice();
      if (current.id === device.deviceId && current.status === 'active') {
        if (current.sessionProven) return undefined;
        // A pre-proof session (the password changed elsewhere, step 3 of §5): prove it now.
        if (!key || !current.hasDeviceKey) return 'device_key_missing';
        try {
          await this.proveSession(ids, key);
          return undefined;
        } catch {
          // A failed proof ends that session; log in again below.
        }
      }
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'offline') return 'offline';
      if (e.code === 'server_maintenance') return 'maintenance';
      if (e.code === 'server_reopening') return 'reopening';
      if (e.code === 'device_revoked') return this.revoked();
      if (e.code !== 'session_expired') return 'offline';
    }
    try {
      const result = await this.opaqueLogin(
        device.username,
        password,
        device.deviceId,
        key ? { accountId: device.accountId, key } : undefined,
      );
      if (result.device.status === 'active' && result.device.id === device.deviceId)
        // Without a key the session stays pre-proof: usable offline, re-enroll to sync (§9).
        return result.proven ? undefined : 'device_key_missing';
      // The server took the password but does not know this device: it was restored from a
      // backup older than this device's enrollment. Nothing here is erased (§3.6a).
      return result.device.id === device.deviceId ? 'login_failed' : 'device_unknown';
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'device_revoked') return this.revoked();
      if (e.code === 'rate_limited') return 'rate_limited';
      if (e.code === 'offline') return 'offline';
      if (e.code === 'server_maintenance') return 'maintenance';
      if (e.code === 'server_reopening') return 'reopening';
      return 'login_failed';
    }
  }

  /**
   * INV-09: the keyset version never goes backwards. A newer keyset must open under the current
   * `AK` and name the same vault. If it carries a new `SK` (rotated on another device, D-24), this
   * device adopts it and re-wraps `AK` locally with the password just typed, so the old `SK` is
   * no longer stored here. Anything else stops sync instead of being trusted. Returns whether
   * `SK` was replaced.
   */
  private async refreshKeyset(session: Session, password: string): Promise<boolean> {
    let remote;
    try {
      remote = await this.deps.api.accountKeys();
    } catch {
      return false;
    }
    const local = session.device.enrolled;
    if (remote.keysetVersion < local.keysetVersion) {
      this.integrity(session, 'keyset_rollback');
      return false;
    }
    if (remote.keysetVersion === local.keysetVersion) return false;
    const { crypto } = this.deps;
    const accountId = uuidToBytes(session.device.accountId);
    let keyset;
    try {
      keyset = crypto.openKeyset({
        accountKey: session.accountKey,
        accountKeyId: fromB64(remote.akId),
        accountId,
        keysetVersion: remote.keysetVersion,
        envelope: fromB64(remote.keyset),
      });
    } catch {
      this.integrity(session, 'keyset_invalid');
      return false;
    }
    if (keyset.vaults[0].vaultId !== local.vaultId) {
      this.integrity(session, 'keyset_changed');
      return false;
    }
    let enrolled: EnrolledKeys = {
      ...local,
      keysetVersion: remote.keysetVersion,
      keyset: fromB64(remote.keyset),
    };
    const rotated = !same(keyset.secretKey, local.secretKey);
    if (rotated) {
      const saltPw = crypto.generatePasswordSalt();
      const auk = crypto.deriveAccountUnlockKey({
        password,
        passwordSalt: saltPw,
        profile: DEFAULT_KDF_PROFILE,
        secretKey: keyset.secretKey,
        accountId,
      });
      try {
        enrolled = {
          ...enrolled,
          secretKey: keyset.secretKey,
          kdfProfile: DEFAULT_KDF_PROFILE,
          saltPw,
          wrappedAkPassword: crypto.wrapAccountKey({
            accountUnlockKey: auk,
            accountKey: session.accountKey,
            accountId,
            accountKeyId: local.akId,
            accountKeyEpoch: local.akEpoch,
            profile: DEFAULT_KDF_PROFILE,
            passwordSalt: saltPw,
          }),
        };
      } finally {
        auk.fill(0);
      }
    }
    const device = { ...session.device, enrolled };
    await this.deps.store.putDevice(device);
    session.device = device;
    if (rotated) local.secretKey.fill(0);
    return rotated;
  }

  /**
   * The `previous_password_required` path: `AK` came from the old local wrap. Logs in with the
   * new password, reads the newer keyset under `AK`, and keeps the server's wrap only if the new
   * password and the new `SK` open it to the same `AK`.
   */
  private async adoptServerKeys(
    device: DeviceRecord,
    enrolled: EnrolledKeys,
    password: string,
    accountKey: Uint8Array,
  ): Promise<EnrolledKeys | undefined> {
    const { crypto, api } = this.deps;
    let keys;
    try {
      await this.opaqueLogin(device.username, password, device.deviceId);
      keys = await api.accountKeys();
    } catch (error) {
      const e = vaultErrorFrom(error);
      if (e.code === 'device_revoked') return this.revoked();
      if (e.code === 'rate_limited' || e.code === 'offline') throw e;
      return undefined;
    }
    if (keys.keysetVersion <= enrolled.keysetVersion) return undefined;
    const accountId = uuidToBytes(device.accountId);
    let auk: Uint8Array | undefined;
    try {
      const keyset = crypto.openKeyset({
        accountKey,
        accountKeyId: fromB64(keys.akId),
        accountId,
        keysetVersion: keys.keysetVersion,
        envelope: fromB64(keys.keyset),
      });
      if (keyset.vaults[0].vaultId !== enrolled.vaultId) return undefined;
      const saltPw = fromB64(keys.saltPw);
      const wrappedAkPassword = fromB64(keys.wrappedAkPassword);
      auk = crypto.deriveAccountUnlockKey({
        password,
        passwordSalt: saltPw,
        profile: keys.kdfProfile,
        secretKey: keyset.secretKey,
        accountId,
      });
      const opened = crypto.unwrapAccountKey({
        accountUnlockKey: auk,
        accountId,
        accountKeyId: fromB64(keys.akId),
        accountKeyEpoch: keys.akEpoch,
        profile: keys.kdfProfile,
        passwordSalt: saltPw,
        envelope: wrappedAkPassword,
      });
      if (!same(opened, accountKey)) return undefined;
      const updated: EnrolledKeys = {
        ...enrolled,
        secretKey: keyset.secretKey,
        kdfProfile: keys.kdfProfile,
        saltPw,
        wrappedAkPassword,
        keysetVersion: keys.keysetVersion,
        keyset: fromB64(keys.keyset),
      };
      await this.deps.store.putDevice({ ...device, enrolled: updated });
      enrolled.secretKey.fill(0);
      return updated;
    } catch {
      return undefined;
    } finally {
      auk?.fill(0);
    }
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
      deviceKey: undefined,
      accountKey,
      accountKeyId: device.enrolled.akId,
      deviceIdBytes: uuidToBytes(device.deviceId),
      vault: { vaultId: device.enrolled.vaultId, vaultKey, vaultKeyId: device.enrolled.vkId },
      synced: new Map(),
      checkpoint,
      anchor: undefined,
      pending: [],
      inflight: null,
      sent: [],
      conflicts: new Map(),
      bodies: new Map(),
      lastSyncedAtMs: null,
      lastChange: null,
      state: 'syncing',
      integrity: undefined,
      recoveryNotice: undefined,
      importState: undefined,
      importOrders: new Map(),
      importRemaining: 0,
      recoveryAcknowledgedMs: 0,
      serverRestore: undefined,
      localExportMark: undefined,
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

  // ---- Device proof of possession (docs/security/device-proof.md) ----

  /** The device key from its local record, under this session's `K_local`; undefined if none. */
  private async loadDeviceKey(session: Session): Promise<DeviceKeyPair | undefined> {
    const envelope = await this.deps.store.local('device-key');
    if (!envelope) return undefined;
    const parsed = z
      .strictObject({ v: z.literal(1), publicKey: z.string(), secretKey: z.string() })
      .parse(
        this.openLocal(
          session.accountKey,
          session.accountKeyId,
          session.deviceIdBytes,
          'device-key',
          envelope,
        ),
      );
    return { publicKey: fromB64(parsed.publicKey), secretKey: fromB64(parsed.secretKey) };
  }

  /** Seals the device key under `K_local` and keeps it for this unlocked session. */
  private async storeDeviceKey(session: Session, key: DeviceKeyPair): Promise<void> {
    await this.deps.store.apply({
      local: {
        'device-key': this.sealLocal(session, 'device-key', {
          v: 1,
          publicKey: toB64(key.publicKey),
          secretKey: toB64(key.secretKey),
        }),
      },
    });
    session.deviceKey = { publicKey: key.publicKey.slice(), secretKey: key.secretKey.slice() };
  }

  /** `deviceProof` for a login or reopening login (ops 1 and 10). */
  private loginProof(
    operation: 'login' | 'reopen_login',
    ids: { accountId: string; deviceId: string },
    key: DeviceKeyPair,
    start: { loginId: string; challenge: string },
    finishLoginRequest: string,
  ): string {
    const { crypto } = this.deps;
    return toB64(
      crypto.signDeviceProof({
        operation,
        accountId: uuidToBytes(ids.accountId),
        deviceId: uuidToBytes(ids.deviceId),
        binding: crypto.loginBinding(fromB64(start.loginId)),
        nonce: fromB64(start.challenge),
        payload: crypto.proofPayload(operation, [fromB64(finishLoginRequest)]),
        secretKey: key.secretKey,
      }),
    );
  }

  /**
   * `{ nonce, proof }` for an operation-bound request (§7): the device key over the exact
   * payload and the session's nonce, and for key replacement `AK`'s own proof as well.
   */
  private signed(
    ids: { accountId: string; deviceId: string },
    key: DeviceKeyPair,
    operation: ProofOperation,
    nonce: { nonce: string; sessionRef: string },
    fields: readonly ProofField[],
    account?: { accountKey: Uint8Array; accountKeyId: Uint8Array; accountKeyEpoch: number },
  ): { nonce: string; proof: { device: string; accountKey: string } } {
    const { crypto } = this.deps;
    const base = {
      operation,
      accountId: uuidToBytes(ids.accountId),
      binding: fromB64(nonce.sessionRef),
      nonce: fromB64(nonce.nonce),
      payload: crypto.proofPayload(operation, fields),
    };
    const device = toB64(
      crypto.signDeviceProof({
        ...base,
        deviceId: uuidToBytes(ids.deviceId),
        secretKey: key.secretKey,
      }),
    );
    const accountKey = account ? toB64(crypto.signAccountProof({ ...base, ...account })) : '';
    return { nonce: nonce.nonce, proof: { device, accountKey } };
  }

  /** As `signed`, for a request that carries only the device proof. */
  private signedDevice(
    ids: { accountId: string; deviceId: string },
    key: DeviceKeyPair,
    operation: ProofOperation,
    nonce: { nonce: string; sessionRef: string },
    fields: readonly ProofField[],
  ): { nonce: string; proof: { device: string } } {
    const { nonce: n, proof } = this.signed(ids, key, operation, nonce, fields);
    return { nonce: n, proof: { device: proof.device } };
  }

  /** The unlocked session's device key, or the re-enrollment it needs (§9). */
  private deviceKeyOf(session: Session): DeviceKeyPair {
    if (!session.deviceKey) throw new VaultError('device_key_missing');
    return session.deviceKey;
  }

  /** `AK`'s fields for an `AVSK` proof of this session. */
  private accountProofOf(session: Session) {
    return {
      accountKey: session.accountKey,
      accountKeyId: session.accountKeyId,
      accountKeyEpoch: session.device.enrolled.akEpoch,
    };
  }

  /** A pre-proof session of this device proves its key (§5 step 3, op 2). */
  private async proveSession(
    ids: { accountId: string; deviceId: string },
    key: DeviceKeyPair,
  ): Promise<void> {
    const nonce = await this.deps.api.proofNonce('session_proof');
    await this.deps.api.sessionProof(this.signedDevice(ids, key, 'session_proof', nonce, []));
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
    const anchor = open('anchor', await store.local('anchor'));
    if (anchor !== undefined) {
      const a = z.strictObject({ seq: z.int().min(0), manifestHash: z.string() }).parse(anchor);
      session.anchor = { seq: a.seq, manifestHash: fromB64(a.manifestHash) };
    }
    const notices = open('notices', await store.local('notices'));
    if (notices !== undefined)
      session.recoveryAcknowledgedMs = z
        .strictObject({ recoveryAcknowledgedMs: z.int().min(0) })
        .parse(notices).recoveryAcknowledgedMs;
    const imported = open('import', await store.local('import'));
    if (imported !== undefined) {
      session.importState = importRecordSchema.parse(imported);
      session.importRemaining = await store.importsCount();
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
    anchor?: boolean;
  }) {
    const session = this.requireSession();
    const local: Record<string, Uint8Array | null> = {};
    if (parts.anchor)
      local.anchor = session.anchor
        ? this.sealLocal(session, 'anchor', {
            seq: session.anchor.seq,
            manifestHash: toB64(session.anchor.manifestHash),
          })
        : null;
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
    // Nothing new is queued against a server in restore review (backup-restore.md §3.5).
    if (session.state === 'maintenance') throw new VaultError('server_maintenance');
    if (session.state === 'reopening') throw new VaultError('server_reopening');
    // The import is the only writer until it is complete (backup-restore.md §4.4a).
    if (session.importState?.state === 'uploading') throw new VaultError('import_in_progress');
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

  // ---- Pairing (device-enrollment.md §3, D-21) ----

  /** Device A, step 2: a fresh `S` and its code; only `pairing_id` goes to the server. */
  async pairingStart(): Promise<PairingCode> {
    this.writable();
    const { crypto, api } = this.deps;
    const secret = crypto.generatePairingSecret();
    const pairingId = toB64(crypto.pairingId(secret));
    try {
      await api.pairingCreate(pairingId);
    } catch (error) {
      secret.fill(0);
      throw vaultErrorFrom(error);
    }
    // A discards S at the deadline whatever the server says (§3.1 "Lifetime").
    const expiresAtMs = this.deps.now() + PAIRING_TTL_MS;
    this.hosting.set(pairingId, { secret, expiresAtMs });
    return { code: crypto.formatPairingCode(secret), pairingId, expiresAtMs };
  }

  private hosted(pairingId: string): HostPairing {
    const host = this.hosting.get(pairingId);
    if (!host) throw new VaultError('pairing_expired');
    if (host.expiresAtMs <= this.deps.now()) {
      this.dropHosted(pairingId);
      throw new VaultError('pairing_expired');
    }
    return host;
  }

  private dropHosted(pairingId: string): void {
    this.hosting.get(pairingId)?.secret.fill(0);
    this.hosting.delete(pairingId);
  }

  /** Device A, step 6: reads the request and verifies `req_mac` in constant time. */
  async pairingStatus(params: { pairingId: string }): Promise<PairingHostStatus> {
    const session = this.requireSession();
    let host: HostPairing;
    try {
      host = this.hosted(params.pairingId);
    } catch {
      return { state: 'expired' };
    }
    if (host.request)
      return {
        state: 'request',
        platform: host.request.platform,
        requestedAtMs: host.request.requestedAtMs,
      };
    // The request did not come from the device holding the code, or is not even well formed:
    // burn the pairing, and say why so the server records it (§3.2 step 6, review R23).
    const burn = async (): Promise<PairingHostStatus> => {
      this.dropHosted(params.pairingId);
      await this.deps.api.pairingCancel(params.pairingId, 'mac_failed').catch(() => undefined);
      return { state: 'failed' };
    };
    let state;
    try {
      state = await this.deps.api.pairingState(params.pairingId);
    } catch (error) {
      if (error instanceof ApiError && error.code === 'not_found') {
        this.dropHosted(params.pairingId);
        return { state: 'expired' };
      }
      // A reply that does not parse (a malformed key, an unknown platform) is the server's.
      if (error instanceof NetworkError && error.reason === 'unexpected_response') return burn();
      throw vaultErrorFrom(error);
    }
    if (state.state === 'open' || !state.request) return { state: 'waiting' };
    const request = state.request;
    let verified: { epk: Uint8Array; devicePublicKey: Uint8Array } | undefined;
    try {
      const epk = fromB64(request.epk);
      const devicePublicKey = fromB64(request.devicePublicKey);
      // req_mac covers B's device key too (pair-req-2): A approves exactly this key (§8).
      if (
        this.deps.crypto.verifyPairingRequest({
          secret: host.secret,
          accountId: uuidToBytes(session.device.accountId),
          pairingId: fromB64(params.pairingId),
          deviceId: uuidToBytes(request.requesterDeviceId),
          ephemeralPublicKey: epk,
          platform: request.platform,
          devicePublicKey,
          mac: fromB64(request.mac),
        })
      )
        verified = { epk, devicePublicKey };
    } catch {
      // A key of the wrong size or an unknown platform: as unverifiable as a wrong MAC.
    }
    if (!verified) return burn();
    host.request = {
      deviceId: request.requesterDeviceId,
      epk: verified.epk,
      devicePublicKey: verified.devicePublicKey,
      platform: request.platform,
      // §3.2 step 7 shows when the request arrived. The server's `requestedAt` is outside the
      // MAC, so A shows when it received the verified request itself (review R23).
      requestedAtMs: this.deps.now(),
    };
    return {
      state: 'request',
      platform: request.platform,
      requestedAtMs: host.request.requestedAtMs,
    };
  }

  /** Device A, step 8: seals `SK` and the current checkpoint to B's verified ephemeral key. */
  pairingApprove(params: { pairingId: string }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.writable();
      const host = this.hosted(params.pairingId);
      const request = host.request;
      if (!request) throw new VaultError('pairing_failed');
      const reply = this.deps.crypto.createPairingResponse({
        secret: host.secret,
        accountId: uuidToBytes(session.device.accountId),
        pairingId: fromB64(params.pairingId),
        deviceId: uuidToBytes(request.deviceId),
        ephemeralPublicKey: request.epk,
        payload: {
          accountId: session.device.accountId,
          deviceId: request.deviceId,
          secretKey: session.device.enrolled.secretKey,
          checkpoint: {
            vaultId: session.checkpoint.vaultId,
            seq: session.checkpoint.seq,
            manifestHash: session.checkpoint.manifestHash,
            keysetVersion: session.device.enrolled.keysetVersion,
          },
        },
      });
      try {
        // A's own device proof over B's id and key and the reply (op 8).
        const nonce = await this.deps.api.proofNonce('pairing_approve');
        const proof = this.signedDevice(
          { accountId: session.device.accountId, deviceId: session.device.deviceId },
          this.deviceKeyOf(session),
          'pairing_approve',
          nonce,
          [
            fromB64(params.pairingId),
            uuidToBytes(request.deviceId),
            request.devicePublicKey,
            reply.ciphertext,
            reply.mac,
            null,
          ],
        );
        await this.deps.api.pairingApprove(params.pairingId, {
          ciphertext: toB64(reply.ciphertext),
          mac: toB64(reply.mac),
          ...proof,
        });
      } catch (error) {
        if (error instanceof ApiError && error.code === 'pairing_state')
          throw new VaultError('pairing_used');
        if (error instanceof ApiError && error.code === 'not_found')
          throw new VaultError('pairing_expired');
        throw vaultErrorFrom(error);
      } finally {
        this.dropHosted(params.pairingId);
      }
      return true as const;
    });
  }

  async pairingCancel(params: { pairingId: string }): Promise<true> {
    this.dropHosted(params.pairingId);
    if (this.joining && toB64(this.joining.pairingId) === params.pairingId) this.dropJoining();
    await this.deps.api.pairingCancel(params.pairingId, 'user').catch(() => undefined);
    return true;
  }

  pairingNeedsPassword(): boolean {
    return !this.pendingPassword || this.pendingPassword.expiresAtMs <= this.deps.now();
  }

  private dropJoining(): void {
    this.joining?.secret.fill(0);
    this.joining?.ephemeralPrivateKey.fill(0);
    this.joining?.deviceKey.secretKey.fill(0);
    this.joining = undefined;
  }

  /** Device B, steps 4 and 5: checks the code offline, then sends `epk_B` and `req_mac`. */
  async pairingJoin(params: { code: string; password?: string }): Promise<true> {
    const device = await this.deps.store.device();
    if (device?.status !== 'pending') throw new VaultError('device_not_enrolled');
    if (params.password !== undefined) {
      try {
        this.pendingPassword = {
          value: normalizePassword(params.password),
          expiresAtMs: this.deps.now() + PAIRING_TTL_MS,
        };
      } catch {
        throw new VaultError('wrong_password');
      }
    }
    if (this.pairingNeedsPassword()) throw new VaultError('password_required');
    const { crypto, api } = this.deps;
    let secret: Uint8Array;
    try {
      secret = crypto.parsePairingCode(params.code);
    } catch {
      throw new VaultError('invalid_pairing_code');
    }
    // This device's key exists before it holds AK: in memory until enrollment (§8).
    const deviceKey = crypto.generateDeviceKey();
    const request = crypto.createPairingRequest({
      secret,
      accountId: uuidToBytes(device.accountId),
      deviceId: uuidToBytes(device.deviceId),
      platform: this.deps.platform,
      devicePublicKey: deviceKey.publicKey,
    });
    const pairingId = toB64(request.pairingId);
    try {
      await api.pairingRequest(pairingId, {
        epk: toB64(request.ephemeralPublicKey),
        platform: this.deps.platform,
        devicePublicKey: toB64(deviceKey.publicKey),
        mac: toB64(request.mac),
      });
    } catch (error) {
      secret.fill(0);
      request.ephemeralPrivateKey.fill(0);
      deviceKey.secretKey.fill(0);
      // A pairing with a request already: someone else may have seen the code (§3.2).
      if (error instanceof ApiError && error.code === 'pairing_state')
        throw new VaultError('pairing_used');
      if (error instanceof ApiError && error.code === 'not_found')
        throw new VaultError('pairing_expired');
      throw vaultErrorFrom(error);
    }
    this.dropJoining();
    this.joining = {
      secret,
      deviceKey,
      pairingId: request.pairingId,
      ephemeralPublicKey: request.ephemeralPublicKey,
      ephemeralPrivateKey: request.ephemeralPrivateKey,
      expiresAtMs: this.deps.now() + PAIRING_TTL_MS,
    };
    return true;
  }

  /**
   * Device B, steps 9 and 10: verifies `resp_mac`, opens the box, unlocks with the password and
   * the received `SK`, checks the keyset against them, and only then stores anything.
   */
  pairingWait(): Promise<PairingJoinStatus> {
    return this.exclusive(async () => {
      const join = this.joining;
      if (!join || join.expiresAtMs <= this.deps.now()) {
        this.dropJoining();
        throw new VaultError('pairing_expired');
      }
      const password = this.pendingPassword?.value;
      if (!password || this.pairingNeedsPassword()) throw new VaultError('password_required');
      const device = await this.deps.store.device();
      if (!device) throw new VaultError('device_not_enrolled');
      const { crypto, api } = this.deps;
      const pairingId = toB64(join.pairingId);
      const ids = { accountId: device.accountId, deviceId: device.deviceId };
      let state;
      try {
        state = await api.pairingState(pairingId);
      } catch (error) {
        if (error instanceof ApiError && error.code === 'not_found') {
          this.dropJoining();
          throw new VaultError('pairing_expired');
        }
        // Approved: this device is active now, and its session proves the key it already holds
        // before it reads anything else (device-proof.md §8).
        if (error instanceof ApiError && error.code === 'device_proof_required') {
          try {
            await this.proveSession(ids, join.deviceKey);
            state = await api.pairingState(pairingId);
          } catch (proofError) {
            throw vaultErrorFrom(proofError);
          }
        } else throw vaultErrorFrom(error);
      }
      if (state.state !== 'approved' || !state.response) return { state: 'waiting' } as const;

      const accountId = uuidToBytes(device.accountId);
      let payload;
      try {
        payload = crypto.openPairingResponse({
          secret: join.secret,
          accountId,
          pairingId: join.pairingId,
          deviceId: uuidToBytes(device.deviceId),
          ephemeralPublicKey: join.ephemeralPublicKey,
          ephemeralPrivateKey: join.ephemeralPrivateKey,
          ciphertext: fromB64(state.response.ciphertext),
          mac: fromB64(state.response.mac),
        });
      } catch {
        this.dropJoining();
        throw new VaultError('pairing_failed');
      }
      // Any failure from here on discards everything received (step 9).
      let keys;
      try {
        keys = await api.accountKeys();
      } catch (error) {
        payload.secretKey.fill(0);
        throw vaultErrorFrom(error);
      }
      const saltPw = fromB64(keys.saltPw);
      const akId = fromB64(keys.akId);
      const keysetEnvelope = fromB64(keys.keyset);
      const wrappedAkPassword = fromB64(keys.wrappedAkPassword);
      let accountKey: Uint8Array;
      const auk = crypto.deriveAccountUnlockKey({
        password,
        passwordSalt: saltPw,
        profile: keys.kdfProfile,
        secretKey: payload.secretKey,
        accountId,
      });
      try {
        accountKey = crypto.unwrapAccountKey({
          accountUnlockKey: auk,
          accountId,
          accountKeyId: akId,
          accountKeyEpoch: keys.akEpoch,
          profile: keys.kdfProfile,
          passwordSalt: saltPw,
          envelope: wrappedAkPassword,
        });
      } catch {
        payload.secretKey.fill(0);
        this.pendingPassword = undefined;
        throw new VaultError('wrong_password');
      } finally {
        auk.fill(0);
      }
      const keyset = crypto.openKeyset({
        accountKey,
        accountKeyId: akId,
        accountId,
        keysetVersion: keys.keysetVersion,
        envelope: keysetEnvelope,
      });
      const vault = keyset.vaults[0];
      if (
        keys.keysetVersion < payload.checkpoint.keysetVersion ||
        !same(keyset.secretKey, payload.secretKey) ||
        vault.vaultId !== payload.checkpoint.vaultId
      ) {
        accountKey.fill(0);
        payload.secretKey.fill(0);
        this.dropJoining();
        throw new VaultError('pairing_failed');
      }
      const enrolledDevice: DeviceRecord & { enrolled: EnrolledKeys } = {
        ...device,
        status: 'active',
        enrolled: {
          secretKey: payload.secretKey,
          kdfProfile: keys.kdfProfile,
          saltPw,
          akId,
          akEpoch: keys.akEpoch,
          wrappedAkPassword,
          keysetVersion: keys.keysetVersion,
          keyset: keysetEnvelope,
          vaultId: vault.vaultId,
          vkId: vault.vkId,
        },
      };
      await this.deps.store.putDevice(enrolledDevice);
      // The checkpoint from A lets this device detect rollback from its first sync (step 10).
      // It has no records yet, so it pulls from genesis and the chain must pass through A's
      // checkpoint (an anchor) instead of starting there.
      this.session = this.newSession(enrolledDevice, accountKey, vault.vk, {
        vaultId: payload.checkpoint.vaultId,
        seq: 0,
        manifestHash: ZERO_HASH,
        keysetVersion: keys.keysetVersion,
      });
      this.session.anchor = {
        seq: payload.checkpoint.seq,
        manifestHash: payload.checkpoint.manifestHash,
      };
      await this.persistLocal({ checkpoint: true, anchor: true });
      // Only now can this device seal its key: it holds AK.
      await this.storeDeviceKey(this.session, join.deviceKey);
      await api.pairingComplete(pairingId).catch(() => undefined);
      this.dropJoining();
      this.pendingPassword = undefined;
      await this.syncNow();
      return { state: 'enrolled', vault: this.unlockedView() } as const;
    });
  }

  // ---- Recovery with the Recovery Kit (account-recovery.md §3, D-22) ----

  /** Steps 1 to 3: checks the key offline, proves it with `RAK`, unwraps `AK` and the keyset. */
  recoveryBegin(params: {
    username: string;
    recoveryKey: string;
    reopenCode?: string;
    /** The user confirmed that this browser's vault of another account may be erased. */
    replaceLocalData?: boolean;
  }): Promise<true> {
    return this.exclusive(async () => {
      const { crypto, api } = this.deps;
      const reopening = params.reopenCode !== undefined;
      const username = normalizeUsername(params.username);
      if (!username) throw new VaultError('recovery_failed');
      let rk: Uint8Array;
      try {
        rk = crypto.parseRecoveryKey(params.recoveryKey);
      } catch {
        throw new VaultError('invalid_recovery_key');
      }
      const keys = crypto.deriveRecoveryKeys(rk);
      rk.fill(0);
      // On a device that is already set up, recovery keeps its id (the forgotten-password case).
      const local = await this.deps.store.device();
      // Reopening with the kit starts this browser from nothing, so it is only for a browser
      // with no local data: one that has data reopens with its password (§3.13), and keeps it.
      if (reopening && local) throw new VaultError('local_data_present');
      // A vault of another account on this browser is never erased without the user's say-so
      // (review R6): recovery here would replace it, unsynced edits included.
      const sameName = local?.username === username;
      if (local?.enrolled && !sameName && params.replaceLocalData !== true)
        throw new VaultError('local_data_other_account');
      const deviceId = sameName ? local.deviceId : crypto.generateUuid();
      try {
        const body = {
          username,
          recoveryAuthKey: toB64(keys.recoveryAuthKey),
          device: { id: deviceId, platform: 'web' as const },
        };
        const started = params.reopenCode
          ? await api.reopenRecoveryStart({ ...body, reopenCode: params.reopenCode })
          : await api.recoveryStart(body);
        const material = reopening
          ? await (async () => {
              const m = await api.reopenMaterial();
              if (!m.wrappedAkRecovery) throw new VaultError('integrity');
              return { ...m, wrappedAkRecovery: m.wrappedAkRecovery };
            })()
          : await api.recoveryMaterial();
        const accountId = uuidToBytes(started.accountId);
        const accountKeyId = fromB64(material.akId);
        let accountKey: Uint8Array | undefined;
        let keyset;
        try {
          accountKey = crypto.unwrapAccountKeyForRecovery({
            recoveryWrapKey: keys.recoveryWrapKey,
            recoveryKeyId: fromB64(material.recoveryKeyId),
            accountId,
            accountKeyId,
            accountKeyEpoch: material.akEpoch,
            envelope: fromB64(material.wrappedAkRecovery),
          });
          keyset = crypto.openKeyset({
            accountKey,
            accountKeyId,
            accountId,
            keysetVersion: material.keysetVersion,
            envelope: fromB64(material.keyset),
          });
        } catch {
          // RAK matched, so a wrap that does not open is an integrity failure, not a wrong key.
          accountKey?.fill(0);
          throw new VaultError('integrity');
        }
        const vault = keyset.vaults[0];
        const refuse = (code: 'local_data_other_account' | 'integrity'): never => {
          for (const key of [accountKey, keyset.secretKey, vault.vk]) key.fill(0);
          throw new VaultError(code);
        };
        // The forgotten-password case: the same account, device and vault under the same `AK`,
        // so this browser's own sealed records open and are kept.
        const keepLocal =
          !reopening &&
          sameName &&
          local.enrolled !== undefined &&
          local.accountId === started.accountId &&
          local.deviceId === started.deviceId &&
          same(local.enrolled.akId, accountKeyId) &&
          local.enrolled.vaultId === vault.vaultId;
        if (local?.enrolled && sameName && !keepLocal && params.replaceLocalData !== true)
          refuse('local_data_other_account');
        // R20: the keyset version this browser verified is a floor, as on every unlock (INV-09).
        // Checked before anything changes on the server.
        if (keepLocal && material.keysetVersion < local.enrolled.keysetVersion) refuse('integrity');
        this.recovery = {
          keepLocal,
          username,
          accountId: started.accountId,
          deviceId: started.deviceId,
          accountKey,
          accountKeyId,
          accountKeyEpoch: material.akEpoch,
          secretKey: keyset.secretKey,
          vaultId: vault.vaultId,
          vaultKey: vault.vk,
          vaultKeyId: vault.vkId,
          keysetVersion: material.keysetVersion,
          keyset: fromB64(material.keyset),
          rowVersion: material.rowVersion,
          ...(reopening ? { reopen: 'recovery' as const } : {}),
        };
      } catch (error) {
        if (error instanceof ApiError && error.code === 'recovery_failed')
          throw new VaultError('recovery_failed');
        throw vaultErrorFrom(error);
      } finally {
        keys.recoveryWrapKey.fill(0);
        keys.recoveryAuthKey.fill(0);
      }
      return true as const;
    });
  }

  /**
   * Reopening, password path (backup-restore.md §3.13), on this unlocked device: the host code
   * and OPAQUE with the snapshot-time password authenticate; the server's snapshot-time password
   * wrap then opens only with this device's own `SK`. The code and the password alone open
   * nothing. Nothing local changes here; the new password and kit follow as in recovery.
   */
  reopenBegin(params: { reopenCode: string; password: string }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      const { crypto, api, opaque } = this.deps;
      const device = session.device;
      const enrolled = device.enrolled;
      let password: string;
      try {
        password = normalizePassword(params.password);
      } catch {
        throw new VaultError('reopen_failed');
      }
      let material;
      try {
        const client = opaque.startLogin(password);
        const start = await api.reopenLoginStart({
          reopenCode: params.reopenCode,
          username: device.username,
          startLoginRequest: client.startLoginRequest,
          deviceId: device.deviceId,
        });
        const finish = opaque.finishLogin(client.clientLoginState, start.loginResponse, password);
        if (finish === undefined) throw new VaultError('reopen_failed');
        // The device active in the snapshot proves its key (device-proof.md §8, R12).
        await api.reopenLoginFinish({
          loginId: start.loginId,
          finishLoginRequest: finish,
          deviceProof: this.loginProof(
            'reopen_login',
            { accountId: device.accountId, deviceId: device.deviceId },
            this.deviceKeyOf(session),
            start,
            finish,
          ),
        });
        material = await api.reopenMaterial();
      } catch (error) {
        throw vaultErrorFrom(error);
      }
      const accountId = uuidToBytes(device.accountId);
      const p = material.password;
      if (!p) throw new VaultError('integrity');
      const auk = crypto.deriveAccountUnlockKey({
        password,
        passwordSalt: fromB64(p.saltPw),
        profile: p.kdfProfile,
        secretKey: enrolled.secretKey,
        accountId,
      });
      let accountKey: Uint8Array;
      try {
        accountKey = crypto.unwrapAccountKey({
          accountUnlockKey: auk,
          accountId,
          accountKeyId: fromB64(material.akId),
          accountKeyEpoch: material.akEpoch,
          profile: p.kdfProfile,
          passwordSalt: fromB64(p.saltPw),
          envelope: fromB64(p.wrappedAkPassword),
        });
      } catch {
        // OPAQUE accepted the password, so this device's SK is not the snapshot's: it was
        // replaced after the backup. Only the Recovery Kit path can reopen (on a new browser).
        throw new VaultError('reopen_needs_kit');
      } finally {
        auk.fill(0);
      }
      let keyset;
      try {
        keyset = crypto.openKeyset({
          accountKey,
          accountKeyId: fromB64(material.akId),
          accountId,
          keysetVersion: material.keysetVersion,
          envelope: fromB64(material.keyset),
        });
      } catch {
        accountKey.fill(0);
        throw new VaultError('integrity');
      }
      const vault = keyset.vaults[0];
      if (vault.vaultId !== enrolled.vaultId || !same(accountKey, session.accountKey)) {
        for (const key of [accountKey, keyset.secretKey, vault.vk]) key.fill(0);
        throw new VaultError('integrity');
      }
      this.recovery = {
        // The password path never replaces local data: it finishes on this device's own session.
        keepLocal: false,
        username: device.username,
        accountId: device.accountId,
        deviceId: device.deviceId,
        accountKey,
        accountKeyId: fromB64(material.akId),
        accountKeyEpoch: material.akEpoch,
        secretKey: keyset.secretKey,
        vaultId: vault.vaultId,
        vaultKey: vault.vk,
        vaultKeyId: vault.vkId,
        keysetVersion: material.keysetVersion,
        keyset: fromB64(material.keyset),
        rowVersion: material.rowVersion,
        reopen: 'password',
      };
      return true as const;
    });
  }

  /** Steps 4 and 5: the new master password, and the mandatory new Recovery Key. */
  recoverySetPassword(params: { password: string }): Promise<RecoveryKitView> {
    return this.exclusive(async () => {
      const r = this.recovery;
      if (!r) throw new VaultError('recovery_failed');
      if (!checkMasterPassword(params.password).ok) throw new VaultError('invalid_password');
      const password = normalizePassword(params.password);
      const { crypto, api, opaque } = this.deps;
      const registration = opaque.startRegistration(password);
      let response: string;
      try {
        ({ registrationResponse: response } = await (r.reopen
          ? api.reopenPasswordStart(registration.registrationRequest)
          : api.recoveryPasswordStart(registration.registrationRequest)));
      } catch (error) {
        throw vaultErrorFrom(error);
      }
      const registrationRecord = opaque.finishRegistration(
        registration.clientRegistrationState,
        response,
        password,
      );
      const accountId = uuidToBytes(r.accountId);
      const saltPw = crypto.generatePasswordSalt();
      const auk = crypto.deriveAccountUnlockKey({
        password,
        passwordSalt: saltPw,
        profile: DEFAULT_KDF_PROFILE,
        secretKey: r.secretKey,
        accountId,
      });
      const wrappedAkPassword = crypto.wrapAccountKey({
        accountUnlockKey: auk,
        accountKey: r.accountKey,
        accountId,
        accountKeyId: r.accountKeyId,
        accountKeyEpoch: r.accountKeyEpoch,
        profile: DEFAULT_KDF_PROFILE,
        passwordSalt: saltPw,
      });
      auk.fill(0);
      const { recoveryKey, recoveryKeyId } = crypto.generateRecoveryKey();
      const rotated = crypto.deriveRecoveryKeys(recoveryKey);
      const wrappedAkRecovery = crypto.wrapAccountKeyForRecovery({
        recoveryWrapKey: rotated.recoveryWrapKey,
        recoveryKeyId,
        accountId,
        accountKeyId: r.accountKeyId,
        accountKeyEpoch: r.accountKeyEpoch,
        accountKey: r.accountKey,
      });
      const recoveryVerifier = crypto.recoveryVerifier(rotated.recoveryAuthKey);
      rotated.recoveryWrapKey.fill(0);
      rotated.recoveryAuthKey.fill(0);
      const text = crypto.formatRecoveryKey(recoveryKey);
      recoveryKey.fill(0);
      r.complete = {
        registrationRecord,
        saltPw,
        wrappedAkPassword,
        recoveryKeyId,
        wrappedAkRecovery,
        recoveryVerifier,
        verified: false,
      };
      this.pendingPassword = { value: password, expiresAtMs: this.deps.now() + PAIRING_TTL_MS };
      return {
        recoveryKey: text,
        recoveryKeyIdShort: toB64(recoveryKeyId).slice(0, 8),
        username: r.username,
        serverOrigin: this.deps.origin,
        createdAtMs: this.deps.now(),
      };
    });
  }

  /** The new kit is checked like at setup (§2) before anything is sent. */
  recoveryVerifyKit(params: { recoveryKey: string }): Promise<true> {
    const r = this.recovery;
    const c = r?.complete;
    if (!r || !c) return Promise.reject(new VaultError('recovery_failed'));
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
        recoveryKeyId: c.recoveryKeyId,
        accountId: uuidToBytes(r.accountId),
        accountKeyId: r.accountKeyId,
        accountKeyEpoch: r.accountKeyEpoch,
        envelope: c.wrappedAkRecovery,
      });
      const ok = same(ak, r.accountKey);
      ak.fill(0);
      if (!ok) return Promise.reject(new VaultError('kit_mismatch'));
    } catch {
      return Promise.reject(new VaultError('kit_mismatch'));
    } finally {
      keys.recoveryWrapKey.fill(0);
      keys.recoveryAuthKey.fill(0);
    }
    c.verified = true;
    return Promise.resolve(true);
  }

  /** Step 6 and 7: the server replaces everything at once; this device starts from genesis. */
  recoveryFinish(): Promise<UnlockedVault> {
    return this.exclusive(async () => {
      const r = this.recovery;
      const c = r?.complete;
      if (!r || !c?.verified) throw new VaultError('kit_mismatch');
      const { crypto, api } = this.deps;
      const complete = r.reopen ? api.reopenComplete : api.recoveryComplete;
      // device-proof.md §8: a recovery (and the kit path of a reopening) enrolls a new device key;
      // the reopening password path keeps and proves this device's restored one. AK is proved too.
      const deviceKey =
        r.reopen === 'password'
          ? this.deviceKeyOf(this.requireSession())
          : crypto.generateDeviceKey();
      const akVerifyKey = crypto.accountProofPublicKey(r.accountKey);
      const operation = r.reopen ? 'reopen_complete' : 'recovery_complete';
      try {
        const nonce = r.reopen ? await api.reopenProofNonce() : await api.recoveryProofNonce();
        const fields = {
          registrationRecord: c.registrationRecord,
          kdfProfile: 1 as const,
          saltPw: toB64(c.saltPw),
          wrappedAkPassword: toB64(c.wrappedAkPassword),
          recoveryKeyId: toB64(c.recoveryKeyId),
          wrappedAkRecovery: toB64(c.wrappedAkRecovery),
          recoveryVerifier: toB64(c.recoveryVerifier),
          expectedRowVersion: r.rowVersion,
        };
        await complete({
          ...fields,
          devicePublicKey: toB64(deviceKey.publicKey),
          akVerifyKey: toB64(akVerifyKey),
          ...this.signed(
            { accountId: r.accountId, deviceId: r.deviceId },
            deviceKey,
            operation,
            nonce,
            [
              fromB64(c.registrationRecord),
              { u8: 1 },
              c.saltPw,
              c.wrappedAkPassword,
              c.recoveryKeyId,
              c.wrappedAkRecovery,
              c.recoveryVerifier,
              { u64: r.rowVersion },
              null,
              deviceKey.publicKey,
              akVerifyKey,
            ],
            {
              accountKey: r.accountKey,
              accountKeyId: r.accountKeyId,
              accountKeyEpoch: r.accountKeyEpoch,
            },
          ),
        });
      } catch (error) {
        if (r.reopen !== 'password') deviceKey.secretKey.fill(0);
        throw vaultErrorFrom(error);
      }
      if (r.reopen === 'password') return this.finishReopenOnThisDevice(c);
      if (r.keepLocal) return this.finishRecoveryKeepingLocal(r, c, deviceKey);
      const device: DeviceRecord & { enrolled: EnrolledKeys } = {
        v: 1,
        accountId: r.accountId,
        deviceId: r.deviceId,
        username: r.username,
        status: 'active',
        enrolled: {
          secretKey: r.secretKey,
          kdfProfile: 1,
          saltPw: c.saltPw,
          akId: r.accountKeyId,
          akEpoch: r.accountKeyEpoch,
          wrappedAkPassword: c.wrappedAkPassword,
          keysetVersion: r.keysetVersion,
          keyset: r.keyset,
          vaultId: r.vaultId,
          vkId: r.vaultKeyId,
        },
      };
      // Anything this browser held before is replaced; it has no trusted checkpoint now.
      await this.deps.store.wipe();
      await this.deps.store.putDevice(device);
      this.session = this.newSession(device, r.accountKey, r.vaultKey, {
        vaultId: r.vaultId,
        seq: 0,
        manifestHash: ZERO_HASH,
        keysetVersion: r.keysetVersion,
      });
      this.recovery = undefined;
      this.pendingPassword = undefined;
      await this.storeDeviceKey(this.session, deviceKey);
      deviceKey.secretKey.fill(0);
      // This device ran the recovery, so it does not warn about it. (Assumes the device clock is
      // not minutes behind the server's, which recorded the start before this finish.)
      this.session.recoveryAcknowledgedMs = this.deps.now();
      await this.persistLocal({ checkpoint: true });
      await this.deps.store.apply({
        local: {
          notices: this.sealLocal(this.session, 'notices', {
            recoveryAcknowledgedMs: this.session.recoveryAcknowledgedMs,
          }),
        },
      });
      await this.syncNow();
      const view = this.unlockedView();
      return { ...view, recovered: { lastChange: view.sync.lastChange } };
    });
  }

  /**
   * Forgotten password on a browser that holds this account's vault (review R6, R20): only the
   * keys that recovery replaced change (the password wrap and salt, and the server's current
   * keyset, never older than this browser's). The synced records, unsynced edits, conflicts,
   * import state, verified checkpoint and anchor are this browser's own, sealed under the same
   * `AK`, and are kept. The first sync continues from that checkpoint, so a server behind it is
   * still refused, and kept edits are rebased or become conflicts as after any pull.
   */
  private async finishRecoveryKeepingLocal(
    r: PendingRecovery,
    c: NonNullable<PendingRecovery['complete']>,
    deviceKey: DeviceKeyPair,
  ): Promise<UnlockedVault> {
    const local = await this.deps.store.device();
    if (!local?.enrolled || local.deviceId !== r.deviceId || local.accountId !== r.accountId)
      throw new VaultError('internal');
    const device: DeviceRecord & { enrolled: EnrolledKeys } = {
      ...local,
      status: 'active',
      enrolled: {
        ...local.enrolled,
        secretKey: r.secretKey,
        kdfProfile: 1,
        saltPw: c.saltPw,
        akId: r.accountKeyId,
        akEpoch: r.accountKeyEpoch,
        wrappedAkPassword: c.wrappedAkPassword,
        keysetVersion: r.keysetVersion,
        keyset: r.keyset,
      },
    };
    const checkpoint = await this.loadCheckpoint(device, r.accountKey, device.enrolled);
    await this.deps.store.putDevice(device);
    this.session = this.newSession(device, r.accountKey, r.vaultKey, {
      ...checkpoint,
      keysetVersion: Math.max(checkpoint.keysetVersion, r.keysetVersion),
    });
    await this.loadLocalState();
    const session = this.session;
    // The recovered device's new key replaces any it had (device-proof.md §8, §9).
    await this.storeDeviceKey(session, deviceKey);
    deviceKey.secretKey.fill(0);
    this.recovery = undefined;
    this.pendingPassword = undefined;
    session.recoveryAcknowledgedMs = this.deps.now();
    await this.deps.store.apply({
      local: {
        notices: this.sealLocal(session, 'notices', {
          recoveryAcknowledgedMs: session.recoveryAcknowledgedMs,
        }),
      },
    });
    // What this browser kept, before the first sync uploads or rebases any of it.
    const keptLocal = {
      pending: session.pending.length + (session.inflight?.mutations.length ?? 0),
      conflicts: session.conflicts.size,
    };
    await this.syncNow();
    const view = this.unlockedView();
    return { ...view, recovered: { lastChange: view.sync.lastChange, keptLocal } };
  }

  /**
   * After a password-path reopening: only this device's own password wrap is replaced. Its items,
   * pending edits and checkpoint stay exactly as they were (backup-restore.md §3.13), and the next
   * sync decides, as always, whether the server is behind it.
   */
  private async finishReopenOnThisDevice(
    c: NonNullable<PendingRecovery['complete']>,
  ): Promise<UnlockedVault> {
    const session = this.requireSession();
    const enrolled: EnrolledKeys = {
      ...session.device.enrolled,
      kdfProfile: 1,
      saltPw: c.saltPw,
      wrappedAkPassword: c.wrappedAkPassword,
    };
    const device = { ...session.device, enrolled };
    await this.deps.store.putDevice(device);
    session.device = device;
    this.recovery = undefined;
    this.pendingPassword = undefined;
    session.state = 'syncing';
    await this.syncNow();
    return { ...this.unlockedView(), reopened: true };
  }

  acknowledgeRecoveryNotice(): Promise<true> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      if (session.recoveryNotice !== undefined) {
        session.recoveryAcknowledgedMs = session.recoveryNotice;
        session.recoveryNotice = undefined;
        await this.deps.store.apply({
          local: {
            notices: this.sealLocal(session, 'notices', {
              recoveryAcknowledgedMs: session.recoveryAcknowledgedMs,
            }),
          },
        });
      }
      this.emitStatus(session);
      return true as const;
    });
  }

  // ---- Devices, sessions and password change (device-enrollment §6, authentication.md §9) ----

  /** Every device of the account with its sessions, newest activity first. */
  async devices(): Promise<DeviceView[]> {
    const session = this.requireSession();
    const { api } = this.deps;
    let devices, sessions;
    try {
      [{ devices }, { sessions }] = await Promise.all([api.devices(), api.sessions()]);
    } catch (error) {
      return this.onlineFailure(error);
    }
    const ms = (t: string | null) => (t === null ? null : Date.parse(t));
    return devices
      .map((d) => ({
        id: d.id,
        platform: d.platform,
        status: d.status,
        enrolledVia: d.enrolledVia,
        current: d.id === session.device.deviceId,
        createdAtMs: Date.parse(d.createdAt),
        enrolledAtMs: ms(d.enrolledAt),
        lastSeenAtMs: ms(d.lastSeenAt),
        revokedAtMs: ms(d.revokedAt),
        sessions: sessions
          .filter((s) => s.deviceId === d.id)
          .map((s) => ({
            id: s.id,
            current: s.current,
            createdAtMs: Date.parse(s.createdAt),
            lastUsedAtMs: Date.parse(s.lastUsedAt),
          })),
      }))
      .sort(
        (a, b) =>
          Number(b.current) - Number(a.current) || (b.lastSeenAtMs ?? 0) - (a.lastSeenAtMs ?? 0),
      );
  }

  /** P2-15: the account's security events, newest first. */
  async activity(params: { cursor?: string }): Promise<ActivityPage> {
    const session = this.requireSession();
    let page;
    try {
      page = await this.deps.api.activity(params.cursor);
    } catch (error) {
      return this.onlineFailure(error);
    }
    return {
      events: page.events.map((e) => ({
        id: e.id,
        type: e.type,
        atMs: Date.parse(e.createdAt),
        device:
          e.deviceId === null
            ? null
            : e.deviceId === session.device.deviceId
              ? 'this_device'
              : 'other',
        ip: e.ip,
        userAgent: e.userAgent,
        details: e.details,
      })),
      nextCursor: page.nextCursor,
    };
  }

  async endSession(params: { sessionId: string }): Promise<true> {
    this.requireSession();
    try {
      await this.deps.api.endSession(params.sessionId);
    } catch (error) {
      return this.onlineFailure(error);
    }
    return true;
  }

  /**
   * Step-up (INV-14) right before a sensitive call: OPAQUE again for this session's account. A
   * wrong password is reported as such; the session itself stays as it was.
   */
  private async stepUp(password: string): Promise<void> {
    const { api, opaque } = this.deps;
    let normalized: string;
    try {
      normalized = normalizePassword(password);
    } catch {
      throw new VaultError('wrong_password');
    }
    const client = opaque.startLogin(normalized);
    try {
      const start = await api.reauthStart({ startLoginRequest: client.startLoginRequest });
      const finish = opaque.finishLogin(client.clientLoginState, start.loginResponse, normalized);
      if (finish === undefined) throw new VaultError('wrong_password');
      await api.reauthFinish({ loginId: start.loginId, finishLoginRequest: finish });
    } catch (error) {
      const e = vaultErrorFrom(error);
      throw e.code === 'login_failed' ? new VaultError('wrong_password') : e;
    }
  }

  /**
   * device-enrollment §6. The server revokes the device and its sessions at once. Revoking this
   * device from itself is refused: that is what logging out is for. A device revoked as lost
   * also gets `SK` rotated in the same step-up (D-24); if only that part fails, the revocation
   * stands and the result says so, so the UI can offer the rotation again.
   */
  revokeDevice(params: {
    deviceId: string;
    reason: 'retired' | 'lost';
    password: string;
  }): Promise<{ secretKeyRotated: boolean }> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      if (params.deviceId === session.device.deviceId)
        throw new VaultError('cannot_revoke_current');
      try {
        await this.stepUp(params.password);
        const nonce = await this.deps.api.proofNonce('device_revoke');
        await this.deps.api.revokeDevice(params.deviceId, {
          reason: params.reason,
          ...this.signedDevice(
            { accountId: session.device.accountId, deviceId: session.device.deviceId },
            this.deviceKeyOf(session),
            'device_revoke',
            nonce,
            [uuidToBytes(params.deviceId), { text: params.reason }],
          ),
        });
      } catch (error) {
        return this.onlineFailure(error);
      }
      if (params.reason === 'retired') return { secretKeyRotated: false };
      try {
        await this.rotateSecretKeyNow(session, params.password);
        return { secretKeyRotated: true };
      } catch (error) {
        if (vaultErrorFrom(error).code === 'device_revoked') return this.revoked();
        return { secretKeyRotated: false };
      }
    });
  }

  /**
   * authentication.md §9 and cryptographic-design §6.1: the same `AK` under a new password wrap
   * and a new OPAQUE record. The server ends every other session; this one continues, and the
   * local wrap is replaced only after the server accepted the change.
   */
  changePassword(params: { currentPassword: string; newPassword: string }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      if (!checkMasterPassword(params.newPassword).ok) throw new VaultError('invalid_password');
      const password = normalizePassword(params.newPassword);
      const { crypto, api, opaque } = this.deps;
      try {
        await this.stepUp(params.currentPassword);
        const keys = await api.accountKeys();
        const enrolled = session.device.enrolled;
        if (
          !same(fromB64(keys.akId), enrolled.akId) ||
          keys.akEpoch !== enrolled.akEpoch ||
          keys.keysetVersion < enrolled.keysetVersion
        )
          throw new VaultError('changed_elsewhere');
        const registration = opaque.startRegistration(password);
        const { registrationResponse } = await api.passwordStart(registration.registrationRequest);
        const registrationRecord = opaque.finishRegistration(
          registration.clientRegistrationState,
          registrationResponse,
          password,
        );
        const accountId = uuidToBytes(session.device.accountId);
        const saltPw = crypto.generatePasswordSalt();
        const auk = crypto.deriveAccountUnlockKey({
          password,
          passwordSalt: saltPw,
          profile: DEFAULT_KDF_PROFILE,
          secretKey: enrolled.secretKey,
          accountId,
        });
        let wrappedAkPassword: Uint8Array;
        try {
          wrappedAkPassword = crypto.wrapAccountKey({
            accountUnlockKey: auk,
            accountKey: session.accountKey,
            accountId,
            accountKeyId: enrolled.akId,
            accountKeyEpoch: enrolled.akEpoch,
            profile: DEFAULT_KDF_PROFILE,
            passwordSalt: saltPw,
          });
        } finally {
          auk.fill(0);
        }
        const nonce = await api.proofNonce('password_change');
        await api.passwordFinish({
          registrationRecord,
          kdfProfile: 1,
          saltPw: toB64(saltPw),
          wrappedAkPassword: toB64(wrappedAkPassword),
          expectedRowVersion: keys.rowVersion,
          ...this.signed(
            { accountId: session.device.accountId, deviceId: session.device.deviceId },
            this.deviceKeyOf(session),
            'password_change',
            nonce,
            [
              fromB64(registrationRecord),
              { u8: 1 },
              saltPw,
              wrappedAkPassword,
              { u64: keys.rowVersion },
            ],
            this.accountProofOf(session),
          ),
        });
        const device = {
          ...session.device,
          enrolled: { ...enrolled, kdfProfile: 1, saltPw, wrappedAkPassword },
        };
        await this.deps.store.putDevice(device);
        session.device = device;
      } catch (error) {
        return this.onlineFailure(error);
      }
      return true as const;
    });
  }

  /**
   * D-24 and cryptographic-design §6.2: a new `SK` in the next keyset version, and `AK` re-wrapped
   * under `AUK'`. The password, the OPAQUE record and the Recovery Kit stay the same. Other
   * devices adopt the new `SK` the next time they unlock online. It does not help against a
   * device that already holds `AK`; only full rotation does (Phase 4).
   */
  rotateSecretKey(params: { password: string }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      try {
        await this.stepUp(params.password);
        await this.rotateSecretKeyNow(session, params.password);
      } catch (error) {
        return this.onlineFailure(error);
      }
      return true as const;
    });
  }

  /** The rotation itself, after a step-up. */
  private async rotateSecretKeyNow(session: Session, rawPassword: string): Promise<void> {
    const { crypto, api } = this.deps;
    const password = normalizePassword(rawPassword);
    const keys = await api.accountKeys();
    const enrolled = session.device.enrolled;
    if (
      !same(fromB64(keys.akId), enrolled.akId) ||
      keys.akEpoch !== enrolled.akEpoch ||
      keys.keysetVersion !== enrolled.keysetVersion
    )
      throw new VaultError('changed_elsewhere');
    const accountId = uuidToBytes(session.device.accountId);
    const secretKey = crypto.generateKey();
    const keysetVersion = enrolled.keysetVersion + 1;
    const keyset = crypto.sealKeyset({
      accountKey: session.accountKey,
      accountKeyId: enrolled.akId,
      accountId,
      keysetVersion,
      keyset: {
        secretKey,
        vaults: [
          {
            vaultId: session.vault.vaultId,
            vkId: session.vault.vaultKeyId,
            vk: session.vault.vaultKey,
          },
        ],
      },
    });
    const saltPw = crypto.generatePasswordSalt();
    const auk = crypto.deriveAccountUnlockKey({
      password,
      passwordSalt: saltPw,
      profile: DEFAULT_KDF_PROFILE,
      secretKey,
      accountId,
    });
    let wrappedAkPassword: Uint8Array;
    try {
      wrappedAkPassword = crypto.wrapAccountKey({
        accountUnlockKey: auk,
        accountKey: session.accountKey,
        accountId,
        accountKeyId: enrolled.akId,
        accountKeyEpoch: enrolled.akEpoch,
        profile: DEFAULT_KDF_PROFILE,
        passwordSalt: saltPw,
      });
    } finally {
      auk.fill(0);
    }
    const nonce = await api.proofNonce('secret_key_rotate');
    await api.rotateSecretKey({
      keysetVersion,
      keyset: toB64(keyset),
      kdfProfile: 1,
      saltPw: toB64(saltPw),
      wrappedAkPassword: toB64(wrappedAkPassword),
      expectedRowVersion: keys.rowVersion,
      ...this.signed(
        { accountId: session.device.accountId, deviceId: session.device.deviceId },
        this.deviceKeyOf(session),
        'secret_key_rotate',
        nonce,
        [
          { u32: keysetVersion },
          keyset,
          { u8: 1 },
          saltPw,
          wrappedAkPassword,
          { u64: keys.rowVersion },
        ],
        this.accountProofOf(session),
      ),
    });
    const device = {
      ...session.device,
      enrolled: {
        ...enrolled,
        secretKey,
        kdfProfile: 1,
        saltPw,
        wrappedAkPassword,
        keysetVersion,
        keyset,
      },
    };
    await this.deps.store.putDevice(device);
    session.device = device;
    enrolled.secretKey.fill(0);
  }

  /**
   * account-recovery.md §5, step 1 and 2: a new Recovery Key wrapping the same `AK`. Nothing is
   * sent until the user typed the new key back and confirmed with the master password, so the
   * step-up window does not run out while the kit is being saved.
   */
  kitRotateBegin(): RecoveryKitView {
    const session = this.requireSession();
    const { crypto } = this.deps;
    const enrolled = session.device.enrolled;
    const { recoveryKey, recoveryKeyId } = crypto.generateRecoveryKey();
    const derived = crypto.deriveRecoveryKeys(recoveryKey);
    try {
      this.kitRotation = {
        recoveryKeyId,
        wrappedAkRecovery: crypto.wrapAccountKeyForRecovery({
          recoveryWrapKey: derived.recoveryWrapKey,
          recoveryKeyId,
          accountId: uuidToBytes(session.device.accountId),
          accountKeyId: enrolled.akId,
          accountKeyEpoch: enrolled.akEpoch,
          accountKey: session.accountKey,
        }),
        recoveryVerifier: crypto.recoveryVerifier(derived.recoveryAuthKey),
        verified: false,
      };
      return {
        recoveryKey: crypto.formatRecoveryKey(recoveryKey),
        recoveryKeyIdShort: toB64(recoveryKeyId).slice(0, 8),
        username: session.device.username,
        serverOrigin: this.deps.origin,
        createdAtMs: this.deps.now(),
      };
    } finally {
      recoveryKey.fill(0);
      derived.recoveryWrapKey.fill(0);
      derived.recoveryAuthKey.fill(0);
    }
  }

  kitRotateVerify(params: { recoveryKey: string }): true {
    const session = this.requireSession();
    const pending = this.kitRotation;
    if (!pending) throw new VaultError('kit_mismatch');
    const { crypto } = this.deps;
    let rk: Uint8Array;
    try {
      rk = crypto.parseRecoveryKey(params.recoveryKey);
    } catch {
      throw new VaultError('invalid_recovery_key');
    }
    const keys = crypto.deriveRecoveryKeys(rk);
    rk.fill(0);
    try {
      const ak = crypto.unwrapAccountKeyForRecovery({
        recoveryWrapKey: keys.recoveryWrapKey,
        recoveryKeyId: pending.recoveryKeyId,
        accountId: uuidToBytes(session.device.accountId),
        accountKeyId: session.device.enrolled.akId,
        accountKeyEpoch: session.device.enrolled.akEpoch,
        envelope: pending.wrappedAkRecovery,
      });
      const ok = same(ak, session.accountKey);
      ak.fill(0);
      if (!ok) throw new VaultError('kit_mismatch');
    } catch {
      throw new VaultError('kit_mismatch');
    } finally {
      keys.recoveryWrapKey.fill(0);
      keys.recoveryAuthKey.fill(0);
    }
    pending.verified = true;
    return true;
  }

  /** Step 3: step-up, then the server replaces the wrap and verifier at once. */
  kitRotateFinish(params: { password: string }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      const pending = this.kitRotation;
      if (!pending?.verified) throw new VaultError('kit_mismatch');
      try {
        await this.stepUp(params.password);
        const keys = await this.deps.api.accountKeys();
        if (!same(fromB64(keys.akId), session.device.enrolled.akId))
          throw new VaultError('changed_elsewhere');
        const nonce = await this.deps.api.proofNonce('recovery_key_rotate');
        await this.deps.api.rotateRecoveryKey({
          recoveryKeyId: toB64(pending.recoveryKeyId),
          wrappedAkRecovery: toB64(pending.wrappedAkRecovery),
          recoveryVerifier: toB64(pending.recoveryVerifier),
          expectedRowVersion: keys.rowVersion,
          ...this.signed(
            { accountId: session.device.accountId, deviceId: session.device.deviceId },
            this.deviceKeyOf(session),
            'recovery_key_rotate',
            nonce,
            [
              pending.recoveryKeyId,
              pending.wrappedAkRecovery,
              pending.recoveryVerifier,
              { u64: keys.rowVersion },
            ],
            this.accountProofOf(session),
          ),
        });
      } catch (error) {
        return this.onlineFailure(error);
      }
      this.kitRotation = undefined;
      return true as const;
    });
  }

  kitRotateCancel(): true {
    this.kitRotation = undefined;
    return true;
  }

  // ---- Portable encrypted export (backup-restore.md §4, D-13 option A) ----

  /**
   * Makes the export from this device's verified state, after step-up and a sync, with nothing
   * pending or in conflict, so the file is exactly the manifest it carries. The result is
   * ciphertext only; the UI hands it to the browser as a download and it is never uploaded.
   */
  exportVault(params: {
    password: string;
    recoveryKey: string;
  }): Promise<{ fileName: string; text: string }> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      // Checked first, so a typo costs no step-up.
      try {
        this.deps.crypto.parseRecoveryKey(params.recoveryKey).fill(0);
      } catch {
        throw new VaultError('invalid_recovery_key');
      }
      try {
        await this.stepUp(params.password);
      } catch (error) {
        return this.onlineFailure(error);
      }
      await this.syncNow();
      if (session.state === 'offline') throw new VaultError('offline');
      if (session.state === 'integrity_error') throw new VaultError('read_only');
      // The file must be exactly the verified state its manifest describes.
      if (
        session.state !== 'synced' ||
        session.pending.length > 0 ||
        session.inflight ||
        session.conflicts.size > 0
      )
        throw new VaultError('unsynced_changes');
      const manifest = await this.deps.store.manifest();
      if (manifest?.seq !== session.checkpoint.seq) throw new VaultError('internal');
      const enrolled = session.device.enrolled;
      const text = buildExport({
        crypto: this.deps.crypto,
        accountId: session.device.accountId,
        vaultId: session.vault.vaultId,
        accountKey: session.accountKey,
        accountKeyId: enrolled.akId,
        accountKeyEpoch: enrolled.akEpoch,
        recoveryKeyText: params.recoveryKey,
        keyset: { version: enrolled.keysetVersion, envelope: enrolled.keyset },
        manifest,
        items: session.synced,
      });
      const day = new Date(this.deps.now()).toISOString().slice(0, 10);
      return { fileName: `ruvee-export-${day}.ruvee`, text };
    });
  }

  /** Opens an export read-only, with no account and no network (§4.3, §4.4). */
  exportOpen(params: { text: string; recoveryKey: string }): ExportView {
    this.opened = undefined;
    const opened = openExport(this.deps.crypto, params.text, params.recoveryKey);
    this.opened = opened;
    return {
      asOfMs: opened.asOfMs,
      authorDeviceId: opened.authorDeviceId,
      seq: opened.seq,
      deletedCount: opened.tombstones,
      items: [...opened.items].map(([id, item]) => detailOf(id, item.body, false, null)),
    };
  }

  /** A password from the opened export, on an explicit reveal by the user. */
  exportSecret(params: { id: string }): string {
    const body = this.opened?.items.get(params.id)?.body;
    if (!body) throw new VaultError('not_found');
    return body.type === 'login' ? body.login.password : '';
  }

  exportClose(): true {
    this.opened = undefined;
    return true;
  }

  // ---- After a server restore: local export and start over (backup-restore.md §3.12) ----

  /** Identifies the local state an export was made of: any later change makes it stale. */
  private localMark(session: Session): string {
    return JSON.stringify([
      session.checkpoint.seq,
      // Each seal starts with a fresh random nonce, so its first bytes tell edits apart.
      session.pending.map((m) => [
        m.itemId,
        m.baseRevision,
        m.record ? toB64(m.record.subarray(0, 24)) : null,
      ]),
      session.inflight?.mutations.length ?? 0,
      [...session.conflicts.keys()],
    ]);
  }

  localState(): Promise<LocalStateView> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      const manifest = await this.deps.store.manifest();
      return {
        snapshot: {
          seq: session.checkpoint.seq,
          asOfMs:
            manifest?.seq === session.checkpoint.seq ? (session.lastChange?.atMs ?? null) : null,
          items: [...session.synced.values()].filter((i) => i.record !== null).length,
        },
        pending: session.pending.length + (session.inflight?.mutations.length ?? 0),
        conflicts: session.conflicts.size,
        exported: session.localExportMark === this.localMark(session),
      };
    });
  }

  /**
   * An encrypted export of the last snapshot this device verified, with no server: for a device
   * that is ahead of a restored server, in maintenance or offline. The file is the existing
   * format (§4.2), a verified manifest and its items, so it cannot hold changes nothing has
   * verified: pending edits and conflicts stay on this device, are counted in the result, and
   * must be acknowledged when there are any. The password is checked against the local wrap.
   */
  exportLocal(params: {
    password: string;
    recoveryKey: string;
    acknowledgeNotIncluded?: boolean;
  }): Promise<LocalExport> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      const { crypto } = this.deps;
      try {
        crypto.parseRecoveryKey(params.recoveryKey).fill(0);
      } catch {
        throw new VaultError('invalid_recovery_key');
      }
      const enrolled = session.device.enrolled;
      let auk: Uint8Array | undefined;
      try {
        auk = crypto.deriveAccountUnlockKey({
          password: normalizePassword(params.password),
          passwordSalt: enrolled.saltPw,
          profile: enrolled.kdfProfile,
          secretKey: enrolled.secretKey,
          accountId: uuidToBytes(session.device.accountId),
        });
        const accountKey = crypto.unwrapAccountKey({
          accountUnlockKey: auk,
          accountId: uuidToBytes(session.device.accountId),
          accountKeyId: enrolled.akId,
          accountKeyEpoch: enrolled.akEpoch,
          profile: enrolled.kdfProfile,
          passwordSalt: enrolled.saltPw,
          envelope: enrolled.wrappedAkPassword,
        });
        const matches = same(accountKey, session.accountKey);
        accountKey.fill(0);
        if (!matches) throw new VaultError('wrong_password');
      } catch {
        throw new VaultError('wrong_password');
      } finally {
        auk?.fill(0);
      }
      const notIncluded = {
        pending: session.pending.length + (session.inflight?.mutations.length ?? 0),
        conflicts: session.conflicts.size,
      };
      if ((notIncluded.pending > 0 || notIncluded.conflicts > 0) && !params.acknowledgeNotIncluded)
        throw new VaultError('unsynced_changes');
      const manifest = await this.deps.store.manifest();
      // A device with no verified snapshot (never synced since enrolling or recovering) has
      // nothing the format can hold.
      if (manifest?.seq !== session.checkpoint.seq || session.checkpoint.seq === 0)
        throw new VaultError('unsynced_changes');
      const text = buildExport({
        crypto,
        accountId: session.device.accountId,
        vaultId: session.vault.vaultId,
        accountKey: session.accountKey,
        accountKeyId: enrolled.akId,
        accountKeyEpoch: enrolled.akEpoch,
        recoveryKeyText: params.recoveryKey,
        keyset: { version: enrolled.keysetVersion, envelope: enrolled.keyset },
        manifest,
        items: session.synced,
      });
      // Read back with the same reader an importer uses: the file is checked, and its date is the
      // one its manifest authenticates.
      const { asOfMs } = openExport(crypto, text, params.recoveryKey);
      session.localExportMark = this.localMark(session);
      const day = new Date(asOfMs).toISOString().slice(0, 10);
      return {
        fileName: `ruvee-export-${day}-verified.ruvee`,
        text,
        snapshot: {
          seq: manifest.seq,
          asOfMs,
          items: [...session.synced.values()].filter((i) => i.record !== null).length,
        },
        notIncluded,
      };
    });
  }

  /**
   * Erases this device's copy so it can log in to a restored server afresh. Never automatic:
   * only on this call, with the typed confirmation, after a local export of the current state
   * or an explicit `withoutExport`, and with the pending and conflict counts the user was shown
   * (review R22: a conflict draft is as unrecoverable as a pending edit once erased).
   */
  startOver(params: {
    confirm: 'erase-this-device';
    withoutExport?: boolean;
    pendingSeen: number;
    conflictsSeen: number;
  }): Promise<true> {
    return this.exclusive(async () => {
      const session = this.requireSession();
      // Checked at run time too: parameters arrive from the UI as a message.
      if ((params.confirm as string) !== 'erase-this-device') throw new VaultError('internal');
      const pending = session.pending.length + (session.inflight?.mutations.length ?? 0);
      if (params.pendingSeen !== pending || params.conflictsSeen !== session.conflicts.size)
        throw new VaultError('unsynced_changes');
      if (!params.withoutExport && session.localExportMark !== this.localMark(session))
        throw new VaultError('export_first');
      await this.deps.store.wipe();
      this.clearMemory();
      return true as const;
    });
  }

  // ---- Import into a fresh installation (backup-restore.md §4.4a) ----

  /**
   * QUEUED: re-encrypts every item of the export opened in this worker as a new item of this
   * vault, and queues them all in one transaction with the import record. Allowed only into a
   * vault that has never held an item, with no import started before: this is not a merge. Then
   * uploads through the normal commit path until complete or interrupted.
   */
  importIntoEmptyVault(): Promise<SyncStatus> {
    return this.exclusive(async () => {
      const session = this.writable();
      const opened = this.opened;
      if (!opened) throw new VaultError('not_found');
      if (session.importState) throw new VaultError('vault_not_empty');
      await this.syncNow();
      if (session.state === 'offline') throw new VaultError('offline');
      if (session.state !== 'synced') throw new VaultError('unsynced_changes');
      if (
        session.synced.size > 0 ||
        session.pending.length > 0 ||
        session.inflight ||
        session.conflicts.size > 0
      )
        throw new VaultError('vault_not_empty');
      const { crypto } = this.deps;
      const rows: QueuedImport[] = [];
      for (const { body } of opened.items.values()) {
        // A fresh destination id; the body (content and its meaningful metadata) is unchanged.
        const itemId = crypto.generateUuid();
        const encoded = encodeItemBody(body);
        const record = this.sealBody(session, itemId, 1, encoded);
        encoded.fill(0);
        rows.push({ itemId, order: rows.length, record });
      }
      const now = this.deps.now();
      const state: ImportRecord = {
        v: 1,
        state: rows.length === 0 ? 'complete' : 'uploading',
        total: rows.length,
        sourceAsOfMs: opened.asOfMs,
        sourceSeq: opened.seq,
        startedAtMs: now,
        completedAtMs: rows.length === 0 ? now : null,
      };
      await this.deps.store.apply({
        imports: { put: rows },
        local: { import: this.sealLocal(session, 'import', state) },
      });
      session.importState = state;
      session.importRemaining = rows.length;
      // The export's plaintext is no longer needed in memory.
      this.opened = undefined;
      await this.syncNow();
      return this.status(session);
    });
  }

  /**
   * UPLOADING: moves the next batch from the queue into the pending queue when it is empty.
   * Items already in the synced state (uploaded before a crash) leave the queue instead. Never
   * while anything is pending or in flight: a queued row stays in the queue until it is synced,
   * so feeding then would queue the same item twice (review R22).
   */
  private async feedImport(session: Session): Promise<void> {
    if (session.importState?.state !== 'uploading') return;
    if (session.pending.length > 0 || session.inflight) return;
    const { store } = this.deps;
    const rows = await store.imports(IMPORT_BATCH_ITEMS);
    const done = rows.filter((r) => session.synced.has(r.itemId));
    if (done.length > 0) {
      await store.apply({ imports: { remove: done.map((r) => r.order) } });
      session.importRemaining = await store.importsCount();
    }
    const batch: QueuedImport[] = [];
    let bytes = 0;
    for (const r of rows) {
      if (session.synced.has(r.itemId)) continue;
      if (batch.length > 0 && bytes + r.record.length > IMPORT_BATCH_BYTES) break;
      batch.push(r);
      bytes += r.record.length;
    }
    if (batch.length === 0) {
      if (session.importRemaining === 0) await this.finishImport(session);
      return;
    }
    for (const r of batch) {
      session.importOrders.set(r.itemId, r.order);
      session.pending.push({ itemId: r.itemId, baseRevision: 0, record: r.record });
    }
    await this.persistLocal({ pending: true });
  }

  private takeImportOrders(session: Session, mutations: readonly PendingMutation[]): number[] {
    const orders: number[] = [];
    for (const m of mutations) {
      const order = session.importOrders.get(m.itemId);
      if (order === undefined) continue;
      orders.push(order);
      session.importOrders.delete(m.itemId);
    }
    return orders;
  }

  /** COMPLETE only with nothing queued, pending or in flight, after a verified state. */
  private async finishImport(session: Session): Promise<void> {
    const current = session.importState;
    if (current?.state !== 'uploading') return;
    if (session.pending.length > 0 || session.inflight) return;
    if ((await this.deps.store.importsCount()) !== 0) return;
    const state: ImportRecord = { ...current, state: 'complete', completedAtMs: this.deps.now() };
    await this.deps.store.apply({ local: { import: this.sealLocal(session, 'import', state) } });
    session.importState = state;
    session.importRemaining = 0;
  }

  /** A failed online call: a revoked device wipes itself (INV-15); anything else is reported. */
  private async onlineFailure(error: unknown): Promise<never> {
    const e = vaultErrorFrom(error);
    if (e.code === 'device_revoked') return this.revoked();
    throw e;
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
    if (session.state === 'integrity_error') {
      // Nothing is pulled or pushed; the account notices only choose the wording.
      await this.checkRecoveryNotice(session).catch(() => undefined);
      return this.status(session);
    }
    session.state = 'syncing';
    this.emitStatus(session);
    try {
      await this.pull(session);
      if (!readOnly(session)) await this.push(session);
      // An import uploads in many commits; keep going while each round makes progress.
      while (!readOnly(session) && session.importState?.state === 'uploading') {
        const before = session.importRemaining;
        await this.push(session);
        await this.feedImport(session);
        const stalled = session.importRemaining >= before && session.pending.length === 0;
        if (stalled) break;
      }
      await this.checkRecoveryNotice(session);
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
      } else if (e.code === 'server_maintenance') {
        session.state = 'maintenance';
      } else if (e.code === 'server_reopening') {
        session.state = 'reopening';
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
      session.anchor,
    );
    if (!result.ok) {
      this.integrity(session, result.reason);
      return;
    }
    if (!result.newest) {
      if (session.anchor?.seq === 0) {
        session.anchor = undefined;
        await this.persistLocal({ anchor: true });
      }
      return;
    }
    const records = result.changed.map((itemId) => {
      const item = result.state.get(itemId);
      return { itemId, revision: item?.revision ?? 0, record: item?.record ?? null };
    });
    // A verified pull never moves the checkpoint back (verifyPages refuses a server behind it).
    if (result.checkpoint.seq < session.checkpoint.seq) {
      this.integrity(session, 'server_behind');
      return;
    }
    // The commit in flight is in the verified chain: it was applied and only its reply was lost.
    // It is done; its changes are in the pulled state. Retrying it would bring back the
    // server's idempotent reply for its old position (review R5).
    const landed = session.inflight;
    if (landed && result.verified.some((h) => sameBytes(h, landed.manifestHash)))
      session.inflight = null;
    session.synced = result.state;
    session.checkpoint = result.checkpoint;
    for (const id of result.changed) session.bodies.delete(id);
    session.lastChange = {
      atMs: result.newest.manifest.createdAtMs,
      byThisDevice:
        uuidFromBytes(result.newest.manifest.authorDeviceId) === session.device.deviceId,
    };
    // The anchor is satisfied once a verified chain reached it; the checkpoint takes over.
    session.anchor = undefined;
    await this.deps.store.apply({
      records,
      manifest: { seq: result.newest.seq, envelope: result.newest.envelope },
      local: {
        checkpoint: this.sealLocal(session, 'checkpoint', {
          ...session.checkpoint,
          manifestHash: toB64(session.checkpoint.manifestHash),
        }),
        anchor: null,
        ...(landed && !session.inflight
          ? { pending: this.sealLocal(session, 'pending', this.pendingJson(session)) }
          : {}),
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
        if (session.pending.length === 0) await this.feedImport(session);
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
        // Only a reply for a commit built on this checkpoint, at exactly the next seq, moves it.
        // Anything else is a replayed or delayed reply (an earlier commit's idempotent answer):
        // applying it would lower the checkpoint below what this device verified (review R5).
        if (
          inflight.body.baseSeq !== session.checkpoint.seq ||
          seq !== session.checkpoint.seq + 1
        ) {
          this.integrity(session, 'stale_commit_reply');
          return;
        }
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
          // Imported items leave the queue in the same transaction that records them as synced.
          imports: { remove: this.takeImportOrders(session, inflight.mutations) },
        });
        session.importRemaining = await this.deps.store.importsCount();
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

  /** Every device shows that the Recovery Kit was used, from the moment recovery starts. */
  private async checkRecoveryNotice(session: Session): Promise<void> {
    const account = await this.deps.api.account();
    const at = account.lastRecoveryAt === null ? 0 : Date.parse(account.lastRecoveryAt);
    if (at > session.recoveryAcknowledgedMs) session.recoveryNotice = at;
    session.serverRestore =
      account.lastRestore === null ? undefined : Date.parse(account.lastRestore.restoredAt);
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
      ...(session.recoveryNotice !== undefined ? { recoveryUsedAtMs: session.recoveryNotice } : {}),
      ...(session.serverRestore !== undefined ? { serverRestoredAtMs: session.serverRestore } : {}),
      ...(session.importState
        ? {
            import: {
              state: session.importState.state,
              total: session.importState.total,
              uploaded: session.importState.total - this.importOutstanding(session),
              sourceAsOfMs: session.importState.sourceAsOfMs,
            },
          }
        : {}),
    };
  }

  /** Imported items not yet confirmed: still queued, or handed to a commit not yet applied. */
  private importOutstanding(session: Session): number {
    if (session.importState?.state !== 'uploading') return 0;
    return session.importRemaining;
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
  /** An unfinished setup's keys (INV-15, review R23). */
  private dropSetup(): void {
    const s = this.setup;
    this.setup = undefined;
    if (!s) return;
    for (const key of [s.secretKey, s.accountKey, s.vaultKey]) key.fill(0);
  }

  /** What an unfinished recovery or reopening unlocked (INV-15, review R23). */
  private dropRecovery(): void {
    const r = this.recovery;
    this.recovery = undefined;
    if (!r) return;
    // The password path shares AK with the unlocked session, which wipeMemory clears anyway.
    for (const key of [r.accountKey, r.secretKey, r.vaultKey]) key.fill(0);
  }

  /**
   * INV-15: the lock. Zeroes what this engine holds now, even while an operation runs; that
   * operation can then neither write nor leave a session behind (review R19).
   */
  wipeMemory(): void {
    this.generation++;
    this.clearMemory();
  }

  private clearMemory(): void {
    const session = this.session;
    if (session) {
      session.accountKey.fill(0);
      session.vault.vaultKey.fill(0);
      // A locked device cannot sign (device-proof.md §2).
      session.deviceKey?.secretKey.fill(0);
      session.deviceKey = undefined;
      session.bodies.clear();
    }
    this.session = undefined;
    this.dropSetup();
    this.dropRecovery();
    this.kitRotation = undefined;
    for (const id of [...this.hosting.keys()]) this.dropHosted(id);
    this.dropJoining();
    this.pendingPassword = undefined;
    this.opened = undefined;
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
