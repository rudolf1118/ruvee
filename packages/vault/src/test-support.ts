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
import { createHash } from 'node:crypto';
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
}

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
  sessionValid = true;
  /** Every request body the server received, for capture checks. */
  received: string[] = [];
  lastRecoveryAt: string | null = null;
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
  revokeReasons: string[] = [];
  pairings = new Map<
    string,
    {
      initiator: string;
      requester?: string;
      epk?: string;
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

  private check(body?: unknown) {
    if (this.offline) throw new NetworkError('offline');
    if (body !== undefined) this.received.push(JSON.stringify(body));
  }

  /** One client's view: it remembers which device its session belongs to, like a cookie. */
  api(): Api {
    let sessionDevice: string | undefined;
    let sessionGeneration = this.generation;
    let loginDevice: string | undefined;
    let loginTag: string | undefined;
    let reauthTag: string | undefined;
    const requireSession = () => {
      if (!this.sessionValid || !sessionDevice || sessionGeneration !== this.generation)
        this.fail(401, 'session_expired');
      if (this.devices.get(sessionDevice) === 'revoked') this.fail(401, 'device_revoked');
      return sessionDevice;
    };
    const requireActive = () => {
      const id = requireSession();
      if (this.devices.get(id) !== 'active') this.fail(403, 'device_not_enrolled');
      return id;
    };
    return {
      registerStart: (body) => {
        this.check(body);
        if (this.account) this.fail(404, 'not_found');
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      registerFinish: (body) => {
        this.check(body);
        if (this.account) this.fail(404, 'not_found');
        this.account = body;
        this.passwordTag = body.registrationRecord.slice(0, 43);
        this.devices.set(body.device.id, 'active');
        sessionDevice = body.device.id;
        sessionGeneration = this.generation;
        return Promise.resolve({
          accountId: body.accountId,
          device: { id: body.device.id, status: 'active' },
        });
      },
      loginStart: (body) => {
        this.check(body);
        loginDevice = body.deviceId;
        loginTag = body.startLoginRequest.slice(0, 43);
        return Promise.resolve({ loginId: 'L'.repeat(22), loginResponse: 'R'.repeat(427) });
      },
      loginFinish: (body) => {
        this.check(body);
        const account = this.account;
        if (!account || loginTag !== this.passwordTag) this.fail(401, 'login_failed');
        this.sessionValid = true;
        let id = loginDevice;
        if (!id || !this.devices.has(id)) {
          id = `${'0'.repeat(8)}-0000-4000-8000-${String(this.devices.size).padStart(12, '0')}`;
          this.devices.set(id, 'pending');
        }
        sessionDevice = id;
        sessionGeneration = this.generation;
        const status = this.devices.get(id) ?? 'pending';
        return Promise.resolve({ accountId: account.accountId, device: { id, status } });
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
        requireActive();
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
        requireSession();
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
        const at = new Date(0).toISOString();
        return Promise.resolve({
          accountId: account.accountId,
          username: account.username,
          createdAt: at,
          passwordChangedAt: at,
          lastRecoveryAt: this.lastRecoveryAt,
        });
      },
      recoveryStart: (body) => {
        this.check(body);
        const account = this.account;
        if (account?.username !== body.username) this.fail(401, 'recovery_failed');
        // The fake compares RAK through the verifier the client registered.
        if (this.verifier(body.recoveryAuthKey) !== account.keys.recoveryVerifier)
          this.fail(401, 'recovery_failed');
        if (!this.devices.has(body.device.id)) this.devices.set(body.device.id, 'pending');
        this.recoverySessions.add(body.device.id);
        sessionDevice = body.device.id;
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
          keyset: keys.keyset,
          rowVersion: this.rowVersion,
        });
      },
      recoveryPasswordStart: () => {
        this.check({});
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      recoveryComplete: (body) => {
        this.check(body);
        const account = this.account;
        const device = sessionDevice;
        if (!account || !device || !this.recoverySessions.has(device))
          this.fail(401, 'unauthenticated');
        if (body.expectedRowVersion !== this.rowVersion) this.fail(409, 'row_version_conflict');
        if (body.recoveryKeyId === account.keys.recoveryKeyId) this.fail(400, 'invalid_request');
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
        // Every other session ends: one generation counter shared by all clients.
        this.generation++;
        sessionGeneration = this.generation;
        return Promise.resolve({
          accountId: account.accountId,
          device: { id: device, status: 'active' },
        });
      },
      pairingCreate: (pairingId) => {
        this.check({ pairingId });
        const initiator = requireActive();
        this.pairings.set(pairingId, { initiator, state: 'open' });
        return Promise.resolve({ expiresAt: new Date(Date.now() + 600_000).toISOString() });
      },
      pairingState: (pairingId) => {
        this.check();
        const id = requireSession();
        const p = this.pairings.get(pairingId);
        if (!p || (p.initiator !== id && p.requester !== id)) this.fail(404, 'not_found');
        const base: PairingStateResponse = {
          pairingId,
          state: p.state,
          role: p.initiator === id ? 'initiator' : 'requester',
          expiresAt: new Date(Date.now() + 600_000).toISOString(),
        };
        if (base.role === 'initiator' && p.requester && p.epk && p.mac)
          return Promise.resolve({
            ...base,
            request: {
              requesterDeviceId: p.requester,
              platform: 'web',
              epk: p.epk,
              mac: p.mac,
              requestedAt: new Date().toISOString(),
            },
          });
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
        Object.assign(p, { requester: id, epk: body.epk, mac: body.mac, state: 'requested' });
        return Promise.resolve(undefined);
      },
      pairingApprove: (pairingId, body) => {
        this.check(body);
        requireActive();
        const p = this.pairings.get(pairingId);
        if (!p?.requester) this.fail(404, 'not_found');
        Object.assign(p, { ciphertext: body.ciphertext, responseMac: body.mac, state: 'approved' });
        this.devices.set(p.requester, 'active');
        return Promise.resolve(undefined);
      },
      pairingComplete: (pairingId) => {
        this.check({});
        requireActive();
        this.pairings.delete(pairingId);
        return Promise.resolve(undefined);
      },
      pairingCancel: (pairingId) => {
        this.check({});
        this.pairings.delete(pairingId);
        return Promise.resolve(undefined);
      },
      reauthStart: (body) => {
        this.check(body);
        requireSession();
        reauthTag = body.startLoginRequest.slice(0, 43);
        return Promise.resolve({ loginId: 'S'.repeat(22), loginResponse: 'R'.repeat(427) });
      },
      reauthFinish: (body) => {
        this.check(body);
        requireSession();
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
      revokeDevice: (deviceId, body) => {
        this.check(body);
        const id = requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        if (deviceId === id) this.fail(403, 'forbidden');
        if (!this.devices.has(deviceId)) this.fail(404, 'not_found');
        this.devices.set(deviceId, 'revoked');
        this.revokeReasons.push(body.reason);
        return Promise.resolve(undefined);
      },
      passwordStart: () => {
        this.check({});
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        return Promise.resolve({ registrationResponse: 'A'.repeat(86) });
      },
      passwordFinish: (body) => {
        this.check(body);
        requireActive();
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
        if (body.expectedRowVersion !== this.rowVersion) this.fail(409, 'row_version_conflict');
        this.account = {
          ...account,
          keys: { ...account.keys, saltPw: body.saltPw, wrappedAkPassword: body.wrappedAkPassword },
        };
        this.rowVersion++;
        this.passwordTag = body.registrationRecord.slice(0, 43);
        // Every other session ends; this client's stays.
        this.generation++;
        sessionGeneration = this.generation;
        return Promise.resolve(undefined);
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
      rotateRecoveryKey: (body) => {
        this.check(body);
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
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
        return Promise.resolve(undefined);
      },
      rotateSecretKey: (body) => {
        this.check(body);
        requireActive();
        if (reauthTag !== this.passwordTag) this.fail(403, 'step_up_required');
        const account = this.account;
        if (!account) this.fail(404, 'not_found');
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
        return Promise.resolve(undefined);
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
