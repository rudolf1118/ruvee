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
import { ApiError, NetworkError, type Api } from './api';
import { fromB64 } from './bytes';
import type { OpaqueClient } from './vault-engine';

interface ServerItem {
  revision: number;
  record: string | null;
  updatedSeq: number;
}

export class FakeServer {
  account: RegisterFinishRequest | undefined;
  items = new Map<string, ServerItem>();
  manifests: { seq: number; manifest: string }[] = [];
  commits = new Map<string, { hash: string; seq: number }>();
  offline = false;
  sessionValid = true;
  /** Every request body the server received, for capture checks. */
  received: string[] = [];
  devices = new Map<string, 'pending' | 'active'>();
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
    let loginDevice: string | undefined;
    const requireSession = () => {
      if (!this.sessionValid || !sessionDevice) this.fail(401, 'session_expired');
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
        this.devices.set(body.device.id, 'active');
        sessionDevice = body.device.id;
        return Promise.resolve({
          accountId: body.accountId,
          device: { id: body.device.id, status: 'active' },
        });
      },
      loginStart: (body) => {
        this.check(body);
        loginDevice = body.deviceId;
        return Promise.resolve({ loginId: 'L'.repeat(22), loginResponse: 'R'.repeat(427) });
      },
      loginFinish: (body) => {
        this.check(body);
        const account = this.account;
        if (!account) this.fail(401, 'login_failed');
        this.sessionValid = true;
        let id = loginDevice;
        if (!id || !this.devices.has(id)) {
          id = `${'0'.repeat(8)}-0000-4000-8000-${String(this.devices.size).padStart(12, '0')}`;
          this.devices.set(id, 'pending');
        }
        sessionDevice = id;
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
          rowVersion: 1,
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
        if (!this.sessionValid) this.fail(401, 'session_expired');
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
        if (!this.sessionValid) this.fail(401, 'session_expired');
        return Promise.resolve(this.applyCommit(body));
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

/** Stand-in OPAQUE client: the fake server does not run OPAQUE. Only the engine flow is tested. */
export const fakeOpaque: OpaqueClient = {
  startRegistration: () => ({ clientRegistrationState: 's', registrationRequest: 'A'.repeat(43) }),
  finishRegistration: () => 'A'.repeat(256),
  startLogin: () => ({ clientLoginState: 's', startLoginRequest: 'A'.repeat(128) }),
  finishLogin: () => 'A'.repeat(86),
};
