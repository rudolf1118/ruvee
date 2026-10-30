// Test-only helpers for the vault engine: an in-memory server with the sync semantics of
// apps/api (sync-protocol §4.2 and §5.1) and a stand-in OPAQUE client. The real API and real
// OPAQUE are covered by apps/api integration tests and the browser tests.

import type {
  AccountKeysResponse,
  CommitRequest,
  PairingStateResponse,
  RegisterFinishRequest,
  SyncChangesResponse,
} from '@ruvee/contracts';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { initRuveeCrypto, uuidToBytes, type ProofField, type ProofOperation } from '@ruvee/crypto';
import { ApiError, NetworkError, type Api } from './api.js';
import { fromB64 } from './bytes.js';
import type { OpaqueClient } from './vault-engine.js';

interface ServerItem {
  revision: number;
  record: string | null;
  updatedSeq: number;
}

export interface FakeServerState {
  account: RegisterFinishRequest | undefined;
  items: Map<string, ServerItem>;
  manifests: { seq: number; manifest: string }[];
  commits: Map<string, { hash: string; seq: number }>;
  devices: Map<string, 'pending' | 'active' | 'revoked'>;
  rowVersion: number;
  passwordTag: string | undefined;
  lastRecoveryAt: string | null;
  devicePublicKeys: Map<string, string>;
  akVerifyKey: string | undefined;
}

/** The fake verifies device proofs with the same code as the API (docs/security/device-proof.md). */
const cryptoReady = initRuveeCrypto();
const raw = (text: string) => new Uint8Array(Buffer.from(text, 'base64url'));
const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');
/** A base64url envelope with its last byte flipped. */
const flipLast = (text: string) => {
  const bytes = Buffer.from(text, 'base64url');
  bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 1;
  return bytes.toString('base64url');
};

export class FakeServer {
  account: RegisterFinishRequest | undefined;
  items = new Map<string, ServerItem>();
  manifests: { seq: number; manifest: string }[] = [];
  commits = new Map<string, { hash: string; seq: number }>();
  offline = false;
  /** Commits the server still accepts before it becomes unreachable; undefined is unlimited. */
  commitBudget: number | undefined;
  /** The next commit is applied, but its response never reaches the client. */
  loseNextCommitResponse = false;
  /** Recovery material carries a keyset envelope with one flipped byte (a corrupt server). */
  corruptKeyset = false;
  /** Rewrites the pairing request the initiator reads (a malicious server). */
  tamperPairingRequest: ((r: Record<string, string>) => Record<string, string>) | undefined;
  /** Every pairing cancel, with its reason. */
  pairingCancels: { pairingId: string; reason: string }[] = [];
  sessionValid = true;
  /** Every request body the server received, for capture checks. */
  received: string[] = [];
  lastRecoveryAt: string | null = null;
  lastRestore: { restoredAt: string; restoreId: string } | null = null;
  /** While set, every request fails as a server in restore review does (503 maintenance). */
  maintenance = false;
  /**
   * While set, the server waits to be reopened with this code (backup-restore.md §3.13): every
   * route but the reopening ones fails with 503 reopening.
   */
  reopenCode: string | undefined;
  private reopenConsumed = false;
  recoverySessions = new Set<string>();
  rowVersion = 1;
  /** Stands in for the OPAQUE record: which password the server would accept. */
  passwordTag: string | undefined;
  /** Bumped when every session ends (recovery); a client's session from an older one is dead. */
  generation = 0;

  verifier(recoveryAuthKey: string): string {
    return createHash('sha256')
      .update(Buffer.from(recoveryAuthKey, 'base64url'))
      .digest('base64url');
  }
  devices = new Map<string, 'pending' | 'active' | 'revoked'>();
  /** `DPK` per device and the account's `AVPK`, as the API stores them. */
  devicePublicKeys = new Map<string, string>();
  akVerifyKey: string | undefined;
  /** Open proof nonces: value → operation and session (device-proof.md §6). */
  private nonces = new Map<string, { operation: ProofOperation; sessionId: string }>();
  revokeReasons: string[] = [];
  pairings = new Map<
    string,
    {
      initiator: string;
      requester?: string;
      epk?: string;
      devicePublicKey?: string;
      mac?: string;
      ciphertext?: string;
      responseMac?: string;
      state: 'open' | 'requested' | 'approved';
    }
  >();

  /** A consistent copy of everything the server stores, like a database backup. */
  snapshot(): FakeServerState {
    return structuredClone({
      account: this.account,
      items: this.items,
      manifests: this.manifests,
      commits: this.commits,
      devices: this.devices,
      rowVersion: this.rowVersion,
      passwordTag: this.passwordTag,
      lastRecoveryAt: this.lastRecoveryAt,
      devicePublicKeys: this.devicePublicKeys,
      akVerifyKey: this.akVerifyKey,
    });
  }

  /** Puts a snapshot back, as restoring that backup would. Sessions are clients' cookie jars here. */
  restore(state: FakeServerState): void {
    const copy = structuredClone(state);
    this.account = copy.account;
    this.items = copy.items;
    this.manifests = copy.manifests;
    this.commits = copy.commits;
    this.devices = copy.devices;
    this.rowVersion = copy.rowVersion;
    this.passwordTag = copy.passwordTag;
    this.lastRecoveryAt = copy.lastRecoveryAt;
    this.devicePublicKeys = copy.devicePublicKeys;
    this.akVerifyKey = copy.akVerifyKey;
  }

  /**
   * A restore under the revised D-28 policy, as the server reopens after the review: the snapshot
   * is back, every session from before is dead, and the account reports the restore.
   */
  restoreReviewed(state: FakeServerState, restoreId: string): void {
    this.restore(state);
    this.generation += 1;
    this.recoverySessions.clear();
    this.pairings.clear();
    this.nonces.clear();
    this.lastRestore = { restoredAt: new Date().toISOString(), restoreId };
  }

  /** A reviewed restore that waits to be reopened with `code`. */
  restoreReopening(state: FakeServerState, restoreId: string, code: string): void {
    this.restoreReviewed(state, restoreId);
    this.reopenCode = code;
    this.reopenConsumed = false;
  }

  get currentSeq(): number {
    return this.manifests.length;
  }

  private fail(
    status: number,
    code: ConstructorParameters<typeof ApiError>[1],
    details?: unknown,
  ): never {
    throw new ApiError(status, code, details, undefined);
  }

  private check(body?: unknown, reopenRoute = false) {
    if (this.offline) throw new NetworkError('offline');
    if (this.maintenance) this.fail(503, 'maintenance');
    if (this.reopenCode !== undefined && !reopenRoute) this.fail(503, 'reopening');
    if (body !== undefined) this.received.push(JSON.stringify(body));
  }

  /** One client's view: it remembers which device its session belongs to, like a cookie. */
  api(): Api {
    let sessionDevice: string | undefined;
    let sessionGeneration = this.generation;
    let loginDevice: string | undefined;
    let loginTag: string | undefined;
    let reauthTag: string | undefined;
    let reopenLogin = false;
    let reopenVia: 'password' | 'recovery' | undefined;
    // Proof state of this client's session (device-proof.md §5).
    let sessionId = randomUUID();
    let proven = false;
    let challenge = '';
    const newSession = (device: string, isProven: boolean) => {
      sessionDevice = device;
      sessionGeneration = this.generation;
      sessionId = randomUUID();
      proven = isProven;
    };
    const accountId = () => this.account?.accountId ?? '';
    const deviceValid = async (
      operation: ProofOperation,
      deviceId: string,
      binding: Uint8Array,
      nonce: Uint8Array,
      fields: readonly ProofField[],
      signature: string,
      publicKey: string | undefined,
    ) => {
      if (!publicKey) return false;
      const c = await cryptoReady;
      try {
        return c.verifyDeviceProof({
          operation,
          accountId: uuidToBytes(accountId()),
          deviceId: uuidToBytes(deviceId),
          binding,
          nonce,
          payload: c.proofPayload(operation, fields),
          publicKey: raw(publicKey),
          signature: raw(signature),
        });
      } catch {
        return false;
      }
    };
    const accountValid = async (
      operation: ProofOperation,
      binding: Uint8Array,
      nonce: Uint8Array,
      fields: readonly ProofField[],
      signature: string,
      publicKey: string | undefined,
    ) => {
      const keys = this.account?.keys;
      if (!publicKey || !keys) return false;
      const c = await cryptoReady;
      try {
        return c.verifyAccountProof({
          operation,
          accountId: uuidToBytes(accountId()),
          accountKeyId: raw(keys.akId),
          accountKeyEpoch: keys.akEpoch,
          binding,
          nonce,
          payload: c.proofPayload(operation, fields),
          publicKey: raw(publicKey),
          signature: raw(signature),
        });
      } catch {
        return false;
      }
    };
    const sessionRef = async () => (await cryptoReady).sessionRef(uuidToBytes(sessionId));
    /** An operation-bound proof of this session's device (and, for key changes, of AK). */
    const proveOperation = async (
      operation: ProofOperation,
      body: { nonce: string; proof: { device: string; accountKey?: string } },
      fields: readonly ProofField[],
      options: { deviceKey?: string; akVerifyKey?: string } = {},
    ) => {
      const device = sessionDevice ?? '';
      const binding = await sessionRef();
      const nonce = raw(body.nonce);
      const ok =
        (await deviceValid(
          operation,
          device,
          binding,
          nonce,
          fields,
          body.proof.device,
          options.deviceKey ?? this.devicePublicKeys.get(device),
        )) &&
        (body.proof.accountKey === undefined ||
          (await accountValid(
            operation,
            binding,
            nonce,
            fields,
            body.proof.accountKey,
            options.akVerifyKey ?? this.akVerifyKey,
          )));
      const open = this.nonces.get(body.nonce);
      this.nonces.delete(body.nonce);
      if (!ok || open?.operation !== operation || open.sessionId !== sessionId)
        this.fail(401, 'device_proof_failed');
    };
    const proveCompletion = async (
      operation: 'recovery_complete' | 'reopen_complete',
      body: Parameters<Api['recoveryComplete']>[0],
    ) => {
      // As the API: an account without AVPK never takes the presented one (device-proof.md §9).
      if (!this.akVerifyKey) this.fail(409, 'migration_required');
      if (this.akVerifyKey !== body.akVerifyKey) this.fail(409, 'device_key_mismatch');
      await proveOperation(
        operation,
        body,
        [
          raw(body.registrationRecord),
          { u8: body.kdfProfile },
          raw(body.saltPw),
          raw(body.wrappedAkPassword),
          raw(body.recoveryKeyId),
          raw(body.wrappedAkRecovery),
          raw(body.recoveryVerifier),
          { u64: body.expectedRowVersion },
          body.label === undefined ? null : raw(body.label),
          raw(body.devicePublicKey),
          raw(body.akVerifyKey),
        ],
        { deviceKey: body.devicePublicKey, akVerifyKey: this.akVerifyKey },
      );
    };
    const issueNonce = async (operation: ProofOperation) => {
      for (const [value, n] of this.nonces)
        if (n.sessionId === sessionId && n.operation === operation) this.nonces.delete(value);
      const nonce = b64(randomBytes(32));
      this.nonces.set(nonce, { operation, sessionId });
      return {
        nonce,
        sessionRef: b64(await sessionRef()),
        expiresAt: new Date(Date.now() + 120_000).toISOString(),
      };
    };
    const consumeCode = (code: string) => {
      if (this.reopenCode === undefined || code !== this.reopenCode || this.reopenConsumed)
        this.fail(401, 'reopen_failed');
      this.reopenConsumed = true;
    };
    const requireSession = () => {
      if (!this.sessionValid || !sessionDevice || sessionGeneration !== this.generation)
        this.fail(401, 'session_expired');
      if (this.devices.get(sessionDevice) === 'revoked') this.fail(401, 'device_revoked');
      return sessionDevice;
    };
    /** An active device's session acts as it only after proving its key (§5). */
    const requireProvenIfActive = () => {
      const id = requireSession();
      if (this.devices.get(id) === 'active' && !proven) this.fail(403, 'device_proof_required');
      return id;
    };
    /** The pre-proof allowlist: active, proof not required (`account/keys`). */
    const requireActiveBeforeProof = () => {
      const id = requireSession();
      if (this.devices.get(id) !== 'active') this.fail(403, 'device_not_enrolled');
      return id;
    };
    const requireActive = () => {
      const id = requireActiveBeforeProof();
      if (!proven) this.fail(403, 'device_proof_required');
      return id;
    };
    return {
      registerStart: (body) => {
        this.check(body);
        if (this.account) this.fail(404, 'not_found');
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      registerFinish: async (body) => {
        this.check(body);
        if (this.account) this.fail(404, 'not_found');
        this.account = body;
        const c = await cryptoReady;
        const fields: ProofField[] = [
          raw(body.registrationRecord),
          raw(body.devicePublicKey),
          raw(body.akVerifyKey),
          raw(body.keys.wrappedAkPassword),
          raw(body.keys.wrappedAkRecovery),
          raw(body.keys.recoveryVerifier),
          raw(body.keys.keyset),
          uuidToBytes(body.vault.id),
        ];
        const binding = c.setupBinding(raw(body.bootstrapToken));
        const zeros = new Uint8Array(32);
        const ok =
          (await deviceValid(
            'register',
            body.device.id,
            binding,
            zeros,
            fields,
            body.proof.device,
            body.devicePublicKey,
          )) &&
          (await accountValid(
            'register',
            binding,
            zeros,
            fields,
            body.proof.accountKey,
            body.akVerifyKey,
          ));
        if (!ok) {
          this.account = undefined;
          this.fail(401, 'device_proof_failed');
        }
        this.passwordTag = body.registrationRecord.slice(0, 43);
        this.devices.set(body.device.id, 'active');
        this.devicePublicKeys.set(body.device.id, body.devicePublicKey);
        this.akVerifyKey = body.akVerifyKey;
        newSession(body.device.id, true);
        return {
          accountId: body.accountId,
          device: { id: body.device.id, status: 'active' as const },
          proven: true,
        };
      },
      loginStart: (body) => {
        this.check(body);
        loginDevice = body.deviceId;
        loginTag = body.startLoginRequest.slice(0, 43);
        challenge = b64(randomBytes(32));
        return Promise.resolve({
          loginId: 'L'.repeat(22),
          loginResponse: 'R'.repeat(427),
          challenge,
        });
      },
      loginFinish: async (body) => {
        this.check(body);
        const account = this.account;
        if (!account || loginTag !== this.passwordTag) this.fail(401, 'login_failed');
        this.sessionValid = true;
        let id = loginDevice;
        if (!id || !this.devices.has(id)) {
          // Never reused, like the server's own ids, also across a restore.
          id = randomUUID();
          this.devices.set(id, 'pending');
        }
        const status = this.devices.get(id) ?? 'pending';
        let isProven = false;
        if (status === 'active' && body.deviceProof !== undefined) {
          const c = await cryptoReady;
          isProven = await deviceValid(
            'login',
            id,
            c.loginBinding(raw(body.loginId)),
            raw(challenge),
            [raw(body.finishLoginRequest)],
            body.deviceProof,
            this.devicePublicKeys.get(id),
          );
          if (!isProven) this.fail(401, 'device_proof_failed');
        }
        newSession(id, isProven);
        return { accountId: account.accountId, device: { id, status }, proven: isProven };
      },
      proofNonce: (operation) => {
        this.check({ operation });
        requireSession();
        if (!proven && operation !== 'session_proof') this.fail(403, 'device_proof_required');
        return issueNonce(operation);
      },
      sessionProof: async (body) => {
        this.check(body);
        requireActiveBeforeProof();
        if (proven) this.fail(403, 'forbidden');
        try {
          await proveOperation('session_proof', body, []);
        } catch (error) {
          this.sessionValid = false;
          throw error;
        }
        proven = true;
      },
      recoveryProofNonce: () => {
        this.check({});
        if (!sessionDevice || !this.recoverySessions.has(sessionDevice))
          this.fail(401, 'unauthenticated');
        return issueNonce('recovery_complete');
      },
      reopenProofNonce: () => {
        this.check({}, true);
        if (!reopenVia) this.fail(401, 'unauthenticated');
        return issueNonce('reopen_complete');
      },
      logout: () => {
        this.check({});
        this.sessionValid = false;
        return Promise.resolve(undefined);
      },
      currentDevice: () => {
        this.check();
        const id = requireSession();
        return Promise.resolve({
          sessionProven: proven,
          hasDeviceKey: this.devicePublicKeys.has(id),
          accountHasVerifyKey: this.akVerifyKey !== undefined,
          id,
          platform: 'web',
          status: this.devices.get(id) ?? 'pending',
          enrolledVia: 'bootstrap',
          label: null,
          createdAt: new Date(0).toISOString(),
          enrolledAt: new Date(0).toISOString(),
          lastSeenAt: null,
          revokedAt: null,
        });
      },
      accountKeys: () => {
        this.check();
        requireActiveBeforeProof();
        const keys = this.account?.keys;
        if (!keys) this.fail(404, 'not_found');
        const response: AccountKeysResponse = {
          kdfProfile: 1,
          saltPw: keys.saltPw,
          akId: keys.akId,
          akEpoch: keys.akEpoch,
          wrappedAkPassword: keys.wrappedAkPassword,
          keysetVersion: keys.keysetVersion,
          keyset: keys.keyset,
          rowVersion: this.rowVersion,
        };
        return Promise.resolve(response);
      },
      vaultState: () => {
        this.check();
        return Promise.resolve({
          vaultId: this.account?.vault.id ?? '',
          vkId: this.account?.vault.vkId ?? '',
          currentSeq: this.currentSeq,
        });
      },
      changes: (since) => {
        this.check();
        requireActive();
        const response: SyncChangesResponse = {
          vaultId: this.account?.vault.id ?? '',
          currentSeq: this.currentSeq,
          pageEndSeq: this.currentSeq,
          items: [...this.items]
            .filter(([, i]) => i.updatedSeq > since)
            .map(([itemId, i]) => ({ itemId, ...i })),
          manifests: this.manifests.filter((m) => m.seq > since),
        };
        return Promise.resolve(response);
      },
      commit: (body) => {
        this.check(body);
        requireActive();
        if (this.commitBudget !== undefined) {
          if (this.commitBudget <= 0) throw new NetworkError('offline');
          this.commitBudget--;
        }
        const result = this.applyCommit(body);
        if (this.loseNextCommitResponse) {
          this.loseNextCommitResponse = false;
          throw new NetworkError('offline');
        }
        return Promise.resolve(result);
      },
      account: () => {
        this.check();
        requireProvenIfActive();
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
        const at = new Date(0).toISOString();
        return Promise.resolve({
          accountId: account.accountId,
          username: account.username,
          createdAt: at,
          passwordChangedAt: at,
          lastRecoveryAt: this.lastRecoveryAt,
          lastRestore: this.lastRestore,
        });
      },
      recoveryStart: (body) => {
        this.check(body);
        const account = this.account;
        if (account?.username !== body.username) this.fail(401, 'recovery_failed');
        // The fake compares RAK through the verifier the client registered.
        if (this.verifier(body.recoveryAuthKey) !== account.keys.recoveryVerifier)
          this.fail(401, 'recovery_failed');
        if (!this.akVerifyKey) this.fail(409, 'migration_required');
        if (!this.devices.has(body.device.id)) this.devices.set(body.device.id, 'pending');
        this.recoverySessions.add(body.device.id);
        newSession(body.device.id, false);
        this.lastRecoveryAt = new Date().toISOString();
        return Promise.resolve({
          accountId: account.accountId,
          deviceId: body.device.id,
          expiresAt: new Date(Date.now() + 900_000).toISOString(),
        });
      },
      recoveryMaterial: () => {
        this.check();
        const account = this.account;
        if (!account || !sessionDevice || !this.recoverySessions.has(sessionDevice))
          this.fail(401, 'unauthenticated');
        const keys = account.keys;
        return Promise.resolve({
          accountId: account.accountId,
          recoveryKeyId: keys.recoveryKeyId,
          wrappedAkRecovery: keys.wrappedAkRecovery,
          akId: keys.akId,
          akEpoch: keys.akEpoch,
          keysetVersion: keys.keysetVersion,
          keyset: this.corruptKeyset ? flipLast(keys.keyset) : keys.keyset,
          rowVersion: this.rowVersion,
        });
      },
      recoveryPasswordStart: () => {
        this.check({});
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      reopenLoginStart: (body) => {
        this.check(body, true);
        if (this.reopenCode === undefined || body.reopenCode !== this.reopenCode)
          this.fail(401, 'reopen_failed');
        loginDevice = body.deviceId;
        loginTag = body.startLoginRequest.slice(0, 43);
        reopenLogin = body.reopenCode === this.reopenCode;
        challenge = b64(randomBytes(32));
        return Promise.resolve({
          loginId: 'L'.repeat(22),
          loginResponse: 'R'.repeat(427),
          challenge,
        });
      },
      reopenLoginFinish: async (body) => {
        this.check(body, true);
        const account = this.account;
        const device = loginDevice;
        if (!account || !reopenLogin || loginTag !== this.passwordTag || !device)
          this.fail(401, 'reopen_failed');
        if (this.devices.get(device) !== 'active') this.fail(401, 'reopen_failed');
        // The device active in the snapshot proves its restored key (device-proof.md §8).
        const c = await cryptoReady;
        const ok =
          body.deviceProof !== undefined &&
          (await deviceValid(
            'reopen_login',
            device,
            c.loginBinding(raw(body.loginId)),
            raw(challenge),
            [raw(body.finishLoginRequest)],
            body.deviceProof,
            this.devicePublicKeys.get(device),
          ));
        if (!ok) this.fail(401, 'reopen_failed');
        consumeCode(this.reopenCode ?? '');
        reopenVia = 'password';
        newSession(device, false);
        return {
          accountId: account.accountId,
          deviceId: device,
          via: 'password' as const,
          expiresAt: new Date(Date.now() + 1_800_000).toISOString(),
        };
      },
      reopenRecoveryStart: (body) => {
        this.check(body, true);
        const account = this.account;
        if (account?.username !== body.username) this.fail(401, 'reopen_failed');
        if (this.verifier(body.recoveryAuthKey) !== account.keys.recoveryVerifier)
          this.fail(401, 'reopen_failed');
        if (!this.akVerifyKey) this.fail(409, 'migration_required');
        consumeCode(body.reopenCode);
        if (!this.devices.has(body.device.id)) this.devices.set(body.device.id, 'pending');
        reopenVia = 'recovery';
        newSession(body.device.id, false);
        return Promise.resolve({
          accountId: account.accountId,
          deviceId: body.device.id,
          via: 'recovery',
          expiresAt: new Date(Date.now() + 1_800_000).toISOString(),
        });
      },
      reopenMaterial: () => {
        this.check(undefined, true);
        const account = this.account;
        if (!account || !reopenVia || this.reopenCode === undefined)
          this.fail(401, 'unauthenticated');
        const keys = account.keys;
        return Promise.resolve({
          accountId: account.accountId,
          via: reopenVia,
          akId: keys.akId,
          akEpoch: keys.akEpoch,
          keysetVersion: keys.keysetVersion,
          keyset: keys.keyset,
          recoveryKeyId: keys.recoveryKeyId,
          rowVersion: this.rowVersion,
          ...(reopenVia === 'password'
            ? {
                password: {
                  kdfProfile: 1 as const,
                  saltPw: keys.saltPw,
                  wrappedAkPassword: keys.wrappedAkPassword,
                },
              }
            : { wrappedAkRecovery: keys.wrappedAkRecovery }),
        });
      },
      reopenPasswordStart: () => {
        this.check({}, true);
        if (!reopenVia) this.fail(401, 'unauthenticated');
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      reopenComplete: async (body) => {
        this.check(body, true);
        const account = this.account;
        const device = sessionDevice;
        if (!account || !device || !reopenVia || this.reopenCode === undefined)
          this.fail(401, 'unauthenticated');
        if (body.expectedRowVersion !== this.rowVersion) this.fail(409, 'row_version_conflict');
        if (body.recoveryKeyId === account.keys.recoveryKeyId) this.fail(400, 'invalid_request');
        if (reopenVia === 'password' && this.devicePublicKeys.get(device) !== body.devicePublicKey)
          this.fail(401, 'device_proof_failed');
        await proveCompletion('reopen_complete', body);
        this.account = {
          ...account,
          keys: {
            ...account.keys,
            saltPw: body.saltPw,
            wrappedAkPassword: body.wrappedAkPassword,
            recoveryKeyId: body.recoveryKeyId,
            wrappedAkRecovery: body.wrappedAkRecovery,
            recoveryVerifier: body.recoveryVerifier,
          },
        };
        this.rowVersion++;
        this.passwordTag = body.registrationRecord.slice(0, 43);
        this.devices.set(device, 'active');
        this.devicePublicKeys.set(device, body.devicePublicKey);
        this.reopenCode = undefined;
        reopenVia = undefined;
        this.generation++;
        newSession(device, true);
        return {
          accountId: account.accountId,
          device: { id: device, status: 'active' as const },
          proven: true,
        };
      },
      recoveryComplete: async (body) => {
        this.check(body);
        const account = this.account;
        const device = sessionDevice;
        if (!account || !device || !this.recoverySessions.has(device))
          this.fail(401, 'unauthenticated');
        if (body.expectedRowVersion !== this.rowVersion) this.fail(409, 'row_version_conflict');
        if (body.recoveryKeyId === account.keys.recoveryKeyId) this.fail(400, 'invalid_request');
        await proveCompletion('recovery_complete', body);
        this.account = {
          ...account,
          keys: {
            ...account.keys,
            saltPw: body.saltPw,
            wrappedAkPassword: body.wrappedAkPassword,
            recoveryKeyId: body.recoveryKeyId,
            wrappedAkRecovery: body.wrappedAkRecovery,
            recoveryVerifier: body.recoveryVerifier,
          },
        };
        this.rowVersion++;
        this.passwordTag = body.registrationRecord.slice(0, 43);
        this.recoverySessions.clear();
        this.devices.set(device, 'active');
        this.devicePublicKeys.set(device, body.devicePublicKey);
        // Every other session ends: one generation counter shared by all clients. The new one is
        // valid, as the real server's is.
        this.generation++;
        this.sessionValid = true;
        newSession(device, true);
        return {
          accountId: account.accountId,
          device: { id: device, status: 'active' as const },
          proven: true,
        };
      },
      pairingCreate: (pairingId) => {
        this.check({ pairingId });
        const initiator = requireActive();
        this.pairings.set(pairingId, { initiator, state: 'open' });
        return Promise.resolve({ expiresAt: new Date(Date.now() + 600_000).toISOString() });
      },
      pairingState: (pairingId) => {
        this.check();
        const id = requireProvenIfActive();
        const p = this.pairings.get(pairingId);
        if (!p || (p.initiator !== id && p.requester !== id)) this.fail(404, 'not_found');
        const base: PairingStateResponse = {
          pairingId,
          state: p.state,
          role: p.initiator === id ? 'initiator' : 'requester',
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
        };
        if (base.role === 'initiator' && p.requester && p.epk && p.devicePublicKey && p.mac) {
          const request = {
            requesterDeviceId: p.requester,
            platform: 'web',
            epk: p.epk,
            devicePublicKey: p.devicePublicKey,
            mac: p.mac,
            requestedAt: new Date().toISOString(),
          };
          return Promise.resolve({
            ...base,
            request: (this.tamperPairingRequest?.(request) ?? request) as unknown as NonNullable<
              PairingStateResponse['request']
            >,
          });
        }
        if (base.role === 'requester' && p.ciphertext && p.responseMac)
          return Promise.resolve({
            ...base,
            response: { ciphertext: p.ciphertext, mac: p.responseMac },
          });
        return Promise.resolve(base);
      },
      pairingRequest: (pairingId, body) => {
        this.check(body);
        const id = requireSession();
        const p = this.pairings.get(pairingId);
        if (!p) this.fail(404, 'not_found');
        if (p.state !== 'open') this.fail(409, 'pairing_state');
        Object.assign(p, {
          requester: id,
          epk: body.epk,
          devicePublicKey: body.devicePublicKey,
          mac: body.mac,
          state: 'requested',
        });
        return Promise.resolve(undefined);
      },
      pairingApprove: async (pairingId, body) => {
        this.check(body);
        requireActive();
        const p = this.pairings.get(pairingId);
        if (!p?.requester || !p.devicePublicKey) this.fail(404, 'not_found');
        await proveOperation('pairing_approve', body, [
          raw(pairingId),
          uuidToBytes(p.requester),
          raw(p.devicePublicKey),
          raw(body.ciphertext),
          raw(body.mac),
          body.label === undefined ? null : raw(body.label),
        ]);
        Object.assign(p, { ciphertext: body.ciphertext, responseMac: body.mac, state: 'approved' });
        this.devices.set(p.requester, 'active');
        this.devicePublicKeys.set(p.requester, p.devicePublicKey);
      },
      pairingComplete: (pairingId) => {
        this.check({});
        requireActive();
        this.pairings.delete(pairingId);
        return Promise.resolve(undefined);
      },
      pairingCancel: (pairingId, reason) => {
        this.check({});
        this.pairingCancels.push({ pairingId, reason });
        this.pairings.delete(pairingId);
        return Promise.resolve(undefined);
      },
      reauthStart: (body) => {
        this.check(body);
        requireActive();
        reauthTag = body.startLoginRequest.slice(0, 43);
        return Promise.resolve({
          loginId: 'S'.repeat(22),
          loginResponse: 'R'.repeat(427),
          challenge: b64(randomBytes(32)),
        });
      },
      reauthFinish: (body) => {
        this.check(body);
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(401, 'login_failed');
        return Promise.resolve({ authAt: new Date().toISOString() });
      },
      devices: () => {
        this.check();
        requireActive();
        const at = new Date(0).toISOString();
        return Promise.resolve({
          devices: [...this.devices].map(([id, status]) => ({
            id,
            platform: 'web' as const,
            status,
            enrolledVia: null,
            label: null,
            createdAt: at,
            enrolledAt: null,
            lastSeenAt: at,
            revokedAt: status === 'revoked' ? at : null,
          })),
        });
      },
      sessions: () => {
        this.check();
        const id = requireActive();
        const at = new Date(0).toISOString();
        return Promise.resolve({
          sessions: [
            {
              id: '00000000-0000-4000-8000-00000000aaaa',
              deviceId: id,
              kind: 'cookie' as const,
              current: true,
              createdAt: at,
              lastUsedAt: at,
              idleExpiresAt: at,
              absoluteExpiresAt: at,
            },
          ],
        });
      },
      endSession: () => {
        this.check({});
        requireActive();
        return Promise.resolve(undefined);
      },
      revokeDevice: async (deviceId, body) => {
        this.check(body);
        const id = requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        if (deviceId === id) this.fail(403, 'forbidden');
        await proveOperation('device_revoke', body, [uuidToBytes(deviceId), { text: body.reason }]);
        if (!this.devices.has(deviceId)) this.fail(404, 'not_found');
        this.devices.set(deviceId, 'revoked');
        this.revokeReasons.push(body.reason);
      },
      passwordStart: () => {
        this.check({});
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      passwordFinish: async (body) => {
        this.check(body);
        requireActive();
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
        await proveOperation('password_change_v2', body, [
          raw(body.registrationRecord),
          { u8: body.kdfProfile },
          raw(body.saltPw),
          raw(body.wrappedAkPassword),
          { u64: body.expectedRowVersion },
          { u32: body.keysetVersion },
        ]);
        if (
          body.expectedRowVersion !== this.rowVersion ||
          body.keysetVersion !== account.keys.keysetVersion
        )
          this.fail(409, 'row_version_conflict');
        this.account = {
          ...account,
          keys: { ...account.keys, saltPw: body.saltPw, wrappedAkPassword: body.wrappedAkPassword },
        };
        this.rowVersion++;
        this.passwordTag = body.registrationRecord.slice(0, 43);
        // Every other session ends; this client's stays.
        this.generation++;
        sessionGeneration = this.generation;
      },
      activity: () => {
        this.check();
        const id = requireActive();
        return Promise.resolve({
          events: [
            {
              id: '00000000-0000-4000-8000-0000000000e1',
              type: 'device_revoked' as const,
              deviceId: id,
              ip: '127.0.0.1',
              userAgent: null,
              details: { reason: 'lost' },
              createdAt: new Date(0).toISOString(),
            },
          ],
          nextCursor: null,
        });
      },
      rotateRecoveryKey: async (body) => {
        this.check(body);
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
        await proveOperation('recovery_key_rotate', body, [
          raw(body.recoveryKeyId),
          raw(body.wrappedAkRecovery),
          raw(body.recoveryVerifier),
          { u64: body.expectedRowVersion },
        ]);
        if (body.expectedRowVersion !== this.rowVersion) this.fail(409, 'row_version_conflict');
        if (body.recoveryKeyId === account.keys.recoveryKeyId) this.fail(400, 'invalid_request');
        this.account = {
          ...account,
          keys: {
            ...account.keys,
            recoveryKeyId: body.recoveryKeyId,
            wrappedAkRecovery: body.wrappedAkRecovery,
            recoveryVerifier: body.recoveryVerifier,
          },
        };
        this.rowVersion++;
      },
      rotateSecretKey: async (body) => {
        this.check(body);
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
        await proveOperation('secret_key_rotate', body, [
          { u32: body.keysetVersion },
          raw(body.keyset),
          { u8: body.kdfProfile },
          raw(body.saltPw),
          raw(body.wrappedAkPassword),
          { u64: body.expectedRowVersion },
        ]);
        if (body.expectedRowVersion !== this.rowVersion) this.fail(409, 'row_version_conflict');
        if (body.keysetVersion !== account.keys.keysetVersion + 1)
          this.fail(400, 'invalid_request');
        this.account = {
          ...account,
          keys: {
            ...account.keys,
            keysetVersion: body.keysetVersion,
            keyset: body.keyset,
            saltPw: body.saltPw,
            wrappedAkPassword: body.wrappedAkPassword,
          },
        };
        this.rowVersion++;
      },
    };
  }

  applyCommit(body: CommitRequest): { seq: number } {
    const hash = JSON.stringify(body);
    const previous = this.commits.get(body.commitId);
    if (previous) {
      if (previous.hash !== hash) this.fail(409, 'idempotency_mismatch');
      return { seq: previous.seq };
    }
    if (body.baseSeq !== this.currentSeq)
      this.fail(409, 'seq_conflict', { currentSeq: this.currentSeq });
    const conflicts = body.mutations.filter((m) => {
      const current = this.items.get(m.itemId);
      return m.baseRevision === 0
        ? current !== undefined
        : current === undefined || current.record === null || current.revision !== m.baseRevision;
    });
    if (conflicts.length > 0) this.fail(409, 'revision_conflict', { conflicts: [] });
    const seq = this.currentSeq + 1;
    for (const m of body.mutations)
      this.items.set(m.itemId, { revision: m.newRevision, record: m.record, updatedSeq: seq });
    this.manifests.push({ seq, manifest: body.manifest });
    this.commits.set(body.commitId, { hash, seq });
    return { seq };
  }

  /** Replaces a stored record with an older one (a malicious server, for rollback tests). */
  replaceRecord(itemId: string, record: string | null, revision: number) {
    const item = this.items.get(itemId);
    if (item) this.items.set(itemId, { ...item, record, revision });
  }

  manifestBytes(seq: number): Uint8Array {
    const m = this.manifests.find((x) => x.seq === seq);
    if (!m) throw new Error('no manifest');
    return fromB64(m.manifest);
  }
}

/**
 * Stand-in OPAQUE client: the fake server does not run OPAQUE. Registration and login carry a
 * hash of the password, so the fake server can refuse a password it was not registered with.
 */
const tag = (password: string) => createHash('sha256').update(password).digest('base64url');

export const fakeOpaque: OpaqueClient = {
  startRegistration: () => ({ clientRegistrationState: 's', registrationRequest: 'A'.repeat(43) }),
  finishRegistration: (_state, _response, password) => tag(password).padEnd(256, 'A'),
  startLogin: (password) => ({
    clientLoginState: 's',
    startLoginRequest: tag(password).padEnd(128, 'A'),
  }),
  finishLogin: () => 'A'.repeat(86),
};
