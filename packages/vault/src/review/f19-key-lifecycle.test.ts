// @vitest-environment node
import { initRuveeCrypto, type RuveeCrypto } from '@ruvee/crypto';
import { IDBFactory } from 'fake-indexeddb';
import { NetworkError, type Api } from '../api.js';
import type { ItemDraft } from '../protocol.js';
import { DeviceStore } from '../store.js';
import { FakeServer, fakeOpaque } from '../test-support.js';
import { VaultEngine, VaultError } from '../vault-engine.js';

/**
 * Follow-up review F-19: which key buffers the engine still holds after each unlock, recovery,
 * pairing, rotation, error, cancellation and lock path. Every secret key the crypto layer returns
 * (and every `SK` the device store hands out) is captured; a test then names the ones that still
 * hold a non-zero byte, by label only, never by value. A buffer is zero only if the engine
 * overwrote it: strings, runtime copies and memory inside the WASM library are out of reach of
 * this test and of the engine. Synthetic data only.
 */

const PASSWORD = 'synthetic engine passphrase 4c1e';
const NEW = 'synthetic rotated passphrase 0d4f';
let crypto: RuveeCrypto;
beforeAll(async () => {
  crypto = await initRuveeCrypto();
});

/** The outputs of each crypto call that are secret keys, by label. */
const SECRET_OUTPUTS: Partial<Record<keyof RuveeCrypto, (out: unknown) => [string, Uint8Array][]>> =
  {
    generateKey: (k) => [['generateKey', k as Uint8Array]],
    deriveAccountUnlockKey: (k) => [['AUK', k as Uint8Array]],
    unwrapAccountKey: (k) => [['AK (password wrap)', k as Uint8Array]],
    unwrapAccountKeyForRecovery: (k) => [['AK (recovery wrap)', k as Uint8Array]],
    openKeyset: (k) => {
      const keyset = k as { secretKey: Uint8Array; vaults: readonly { vk: Uint8Array }[] };
      return [
        ['keyset SK', keyset.secretKey],
        ...keyset.vaults.map((v): [string, Uint8Array] => ['keyset VK', v.vk]),
      ];
    },
    openPairingResponse: (p) => [['paired SK', (p as { secretKey: Uint8Array }).secretKey]],
    generateDeviceKey: (k) => [['device key', (k as { secretKey: Uint8Array }).secretKey]],
    createPairingRequest: (r) => [
      ['pairing ephemeral key', (r as { ephemeralPrivateKey: Uint8Array }).ephemeralPrivateKey],
    ],
    parsePairingCode: (s) => [['pairing secret', s as Uint8Array]],
    generateRecoveryKey: (k) => [['RK', (k as { recoveryKey: Uint8Array }).recoveryKey]],
    parseRecoveryKey: (k) => [['RK', k as Uint8Array]],
    deriveRecoveryKeys: (k) => {
      const keys = k as { recoveryWrapKey: Uint8Array; recoveryAuthKey: Uint8Array };
      return [
        ['RWK', keys.recoveryWrapKey],
        ['RAK', keys.recoveryAuthKey],
      ];
    },
  };

class Captured {
  private readonly buffers: { label: string; bytes: Uint8Array }[] = [];
  add(label: string, bytes: Uint8Array): void {
    this.buffers.push({ label, bytes });
  }
  /** A position, for `live(since)`. */
  mark(): number {
    return this.buffers.length;
  }
  /** Labels of the captured buffers that still hold a non-zero byte, sorted. Never the bytes. */
  live(since = 0): string[] {
    return this.buffers
      .slice(since)
      .filter((b) => b.bytes.some((x) => x !== 0))
      .map((b) => b.label)
      .sort();
  }
}

type StoreMethod = 'putDevice' | 'apply' | 'wipe';

interface Options {
  factory?: IDBFactory;
  api?: Api;
  /** Runs before the named API call; it may throw, or lock the engine. */
  before?: Partial<Record<keyof Api, () => void>>;
}

async function device(server: FakeServer, options: Options = {}) {
  const captured = new Captured();
  const tracked: Record<string, unknown> = { ...crypto };
  for (const [name, pick] of Object.entries(SECRET_OUTPUTS)) {
    const fn = Reflect.get(crypto, name) as (...a: unknown[]) => unknown;
    tracked[name] = (...args: unknown[]) => {
      const out = Reflect.apply(fn, crypto, args);
      for (const [label, bytes] of pick(out)) captured.add(label, bytes);
      return out;
    };
  }
  const factory = options.factory ?? new IDBFactory();
  const real = await DeviceStore.open(factory);
  const failing = new Set<StoreMethod>();
  const store = new Proxy(real, {
    get(target, key) {
      const value = Reflect.get(target, key, target) as unknown;
      if (typeof value !== 'function') return value;
      const method = value as (...a: unknown[]) => Promise<unknown>;
      return async (...args: unknown[]) => {
        if (failing.delete(key as StoreMethod)) throw new Error('synthetic store failure');
        const out = await method.apply(target, args);
        // Every `SK` the store hands out is a copy the engine owns.
        if (key === 'device') {
          const record = out as { enrolled?: { secretKey: Uint8Array } } | undefined;
          if (record?.enrolled) captured.add('stored SK', record.enrolled.secretKey);
        }
        return out;
      };
    },
  });
  const base = options.api ?? server.api();
  const before = options.before ?? {};
  const api = new Proxy(base, {
    get(target, key) {
      const value = Reflect.get(target, key, target) as unknown;
      if (typeof value !== 'function') return value;
      const method = value as (...a: unknown[]) => unknown;
      return (...args: unknown[]) => {
        before[key as keyof Api]?.();
        return method.apply(target, args);
      };
    },
  });
  const engine = new VaultEngine({
    crypto: tracked as unknown as RuveeCrypto,
    api,
    store,
    opaque: fakeOpaque,
    origin: 'http://127.0.0.1:3101',
    platform: 'web',
    now: () => Date.now(),
    emit: () => undefined,
  });
  return {
    engine,
    captured,
    factory,
    api: base,
    store: real,
    before,
    /** The next call of this store method fails. */
    failNext(method: StoreMethod) {
      failing.add(method);
    },
  };
}
type Device = Awaited<ReturnType<typeof device>>;

const note = (title: string): ItemDraft => ({
  type: 'note',
  title,
  username: '',
  password: '',
  urls: [],
  notes: '',
  noteText: 'synthetic',
  tags: [],
  favorite: false,
});

const code = async (p: Promise<unknown>) => {
  try {
    await p;
    return 'ok';
  } catch (error) {
    return error instanceof VaultError ? error.code : 'not a vault error';
  }
};

async function account(server = new FakeServer()) {
  const a = await device(server);
  const kit = await a.engine.setupBegin({
    bootstrapToken: 'T'.repeat(43),
    username: 'Synthetic-User',
    password: PASSWORD,
  });
  await a.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
  await a.engine.setupFinish();
  return { server, a, kit: kit.recoveryKey };
}

/** A second device B, paired by A, synced and locked. */
async function paired(server: FakeServer, a: Device) {
  const b = await device(server);
  await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
  const started = await a.engine.pairingStart();
  await b.engine.pairingJoin({ code: started.code });
  await a.engine.pairingStatus({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await a.engine.pairingApprove({ pairingId: started.pairingId });
  await b.engine.pairingWait();
  await b.engine.sync();
  b.engine.wipeMemory();
  return b;
}

/** A new engine on an existing browser's data and cookies. */
const reopen = (server: FakeServer, d: Device, options: Omit<Options, 'factory' | 'api'> = {}) =>
  device(server, { factory: d.factory, api: d.api, ...options });

/** Proves the engine's in-memory keys still work: an item saved now opens on a later unlock. */
async function keysStillWork(server: FakeServer, d: Device, password: string) {
  await d.engine.save({ draft: note('Saved after the operation') });
  await d.engine.idle();
  d.engine.wipeMemory();
  const later = await reopen(server, d);
  const view = await later.engine.unlock({ password });
  expect(view.items.map((i) => i.title)).toContain('Saved after the operation');
  later.engine.wipeMemory();
}

describe('F-19: key lifetimes in the client engine', () => {
  describe('unlock, lock and logout', () => {
    it('a wrong password leaves no key behind, the stored SK included', async () => {
      const { server, a } = await account();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      expect(await code(d.engine.unlock({ password: 'synthetic wrong guess 1' }))).toBe(
        'wrong_password',
      );
      expect(d.captured.live()).toEqual([]);
    });

    it('an unlock keeps exactly the keys its session uses, and a lock zeroes them', async () => {
      const { server, a } = await account();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      await d.engine.unlock({ password: PASSWORD });
      // The keyset's own SK copy only served the comparison with the stored one.
      expect(d.captured.live()).toEqual(['AK (password wrap)', 'keyset VK', 'stored SK']);
      d.engine.wipeMemory();
      expect(d.captured.live()).toEqual([]);
      const again = await reopen(server, a);
      await again.engine.unlock({ password: PASSWORD });
      await keysStillWork(server, again, PASSWORD);
    });

    it('a lock that overtakes an unlock waiting on the network leaves nothing', async () => {
      const { server, a } = await account();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      d.before.currentDevice = () => {
        d.engine.wipeMemory();
      };
      expect(await code(d.engine.unlock({ password: PASSWORD }))).toBe('locked');
      expect(d.captured.live()).toEqual([]);
    });

    it('a logout zeroes the session keys, the stored SK included', async () => {
      const { server, a } = await account();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      await d.engine.unlock({ password: PASSWORD });
      await d.engine.logout();
      expect(d.captured.live()).toEqual([]);
    });
  });

  describe('extension restart (resume from AK, D-27)', () => {
    it('keeps the caller’s AK intact and only the keys its session uses', async () => {
      const { server, a } = await account();
      const held = a.engine.accountKeyForResume();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      await d.engine.resume({ accountKey: held });
      expect(held.some((x) => x !== 0)).toBe(true);
      expect(d.captured.live()).toEqual(['keyset VK', 'stored SK']);
      d.engine.wipeMemory();
      expect(d.captured.live()).toEqual([]);
      expect(held.some((x) => x !== 0)).toBe(true);
      held.fill(0);
    });

    it('a resume with a key that does not open the keyset leaves nothing', async () => {
      const { server, a } = await account();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      const wrong = crypto.generateKey();
      expect(await code(d.engine.resume({ accountKey: wrong }))).toBe('locked');
      expect(d.captured.live()).toEqual([]);
      wrong.fill(0);
    });
  });

  describe('adopting server key material', () => {
    it('adopting a rotated SK at unlock keeps the new SK and zeroes every other copy', async () => {
      const { server, a } = await account();
      const b = await paired(server, a);
      await a.engine.rotateSecretKey({ password: PASSWORD });
      const d = await reopen(server, b);
      expect((await d.engine.unlock({ password: PASSWORD })).secretKeyUpdated).toBe(true);
      // The old stored SK, the unlock's keyset SK copy and the newer keyset's VK copy are zero.
      expect(d.captured.live()).toEqual(['AK (password wrap)', 'keyset SK', 'keyset VK']);
      d.engine.wipeMemory();
      expect(d.captured.live()).toEqual([]);
      const later = await reopen(server, b);
      await later.engine.unlock({ password: PASSWORD });
      await keysStillWork(server, later, PASSWORD);
    });

    it('a failed write while adopting a rotated SK leaves nothing, and the next unlock adopts it', async () => {
      const { server, a } = await account();
      const b = await paired(server, a);
      await a.engine.rotateSecretKey({ password: PASSWORD });
      const d = await reopen(server, b);
      d.failNext('putDevice');
      expect(await code(d.engine.unlock({ password: PASSWORD }))).not.toBe('ok');
      expect(d.captured.live()).toEqual([]);
      const retry = await reopen(server, b);
      expect((await retry.engine.unlock({ password: PASSWORD })).secretKeyUpdated).toBe(true);
      retry.engine.wipeMemory();
    });

    it('the previous-password path keeps the adopted SK and zeroes the second AK and VK', async () => {
      const { server, a } = await account();
      const b = await paired(server, a);
      await a.engine.rotateSecretKey({ password: PASSWORD });
      await a.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW });
      const d = await reopen(server, b);
      await d.engine.unlock({ password: NEW, previousPassword: PASSWORD });
      expect(d.captured.live()).toEqual(['AK (password wrap)', 'keyset SK', 'keyset VK']);
      d.engine.wipeMemory();
      expect(d.captured.live()).toEqual([]);
      const later = await reopen(server, b);
      await later.engine.unlock({ password: NEW });
      await keysStillWork(server, later, NEW);
    });

    it('a wrong new password on the previous-password path leaves nothing', async () => {
      const { server, a } = await account();
      const b = await paired(server, a);
      await a.engine.rotateSecretKey({ password: PASSWORD });
      await a.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW });
      const d = await reopen(server, b);
      expect(
        await code(
          d.engine.unlock({ password: 'synthetic wrong guess 2', previousPassword: PASSWORD }),
        ),
      ).toBe('wrong_password');
      expect(d.captured.live()).toEqual([]);
    });

    it('a failed write on the previous-password path is reported as such and leaves nothing', async () => {
      const { server, a } = await account();
      const b = await paired(server, a);
      await a.engine.rotateSecretKey({ password: PASSWORD });
      await a.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW });
      const d = await reopen(server, b);
      d.failNext('putDevice');
      // Not "wrong password": the password was right, the device could not store the result.
      expect(await code(d.engine.unlock({ password: NEW, previousPassword: PASSWORD }))).toBe(
        'not a vault error',
      );
      expect(d.captured.live()).toEqual([]);
    });

    it('a failed write after the server wrap opened is reported as such and leaves nothing', async () => {
      const { server, a } = await account();
      const b = await paired(server, a);
      await a.engine.changePassword({ currentPassword: PASSWORD, newPassword: NEW });
      const d = await reopen(server, b);
      d.failNext('putDevice');
      expect(await code(d.engine.unlock({ password: NEW }))).toBe('not a vault error');
      expect(d.captured.live()).toEqual([]);
    });
  });

  describe('pairing (device B)', () => {
    async function joined(server: FakeServer, a: Device) {
      const b = await device(server);
      await b.engine.login({ username: 'synthetic-user', password: PASSWORD });
      const started = await a.engine.pairingStart();
      await b.engine.pairingJoin({ code: started.code });
      await a.engine.pairingStatus({ pairingId: started.pairingId });
      return { b, started };
    }

    it('a cancelled pairing leaves nothing', async () => {
      const { server, a } = await account();
      const { b, started } = await joined(server, a);
      expect(await b.engine.pairingWait()).toEqual({ state: 'waiting' });
      await b.engine.pairingCancel({ pairingId: started.pairingId });
      expect(b.captured.live()).toEqual([]);
    });

    it('a lock that overtakes an approved pairing leaves nothing', async () => {
      const { server, a } = await account();
      const { b, started } = await joined(server, a);
      await a.engine.pairingApprove({ pairingId: started.pairingId });
      b.before.accountKeys = () => {
        b.engine.wipeMemory();
      };
      expect(await code(b.engine.pairingWait())).toBe('locked');
      expect(b.captured.live()).toEqual([]);
    });

    it('a failed write at enrollment leaves nothing, and the pairing must start over', async () => {
      const { server, a } = await account();
      const { b, started } = await joined(server, a);
      await a.engine.pairingApprove({ pairingId: started.pairingId });
      b.failNext('apply');
      expect(await code(b.engine.pairingWait())).toBe('not a vault error');
      // A failure after the session was in place discards everything, the pairing too (F-12).
      expect(b.captured.live()).toEqual([]);
      expect(await code(b.engine.pairingWait())).toBe('pairing_expired');
    });

    it('a completed pairing keeps exactly the keys its session uses', async () => {
      const { server, a } = await account();
      const { b, started } = await joined(server, a);
      await a.engine.pairingApprove({ pairingId: started.pairingId });
      expect((await b.engine.pairingWait()).state).toBe('enrolled');
      // The session's device key is its own copy; the generated one is zeroed (dropJoining).
      expect(b.captured.live()).toEqual(['AK (password wrap)', 'keyset VK', 'paired SK']);
      await keysStillWork(server, b, PASSWORD);
    });
  });

  describe('recovery and reopening', () => {
    it('a second recovery start replaces the first one’s keys', async () => {
      const { server, kit } = await account();
      const d = await device(server);
      await d.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
      const first = d.captured.mark();
      await d.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
      expect(d.captured.live(first)).toEqual(['AK (recovery wrap)', 'keyset SK', 'keyset VK']);
      expect(d.captured.live()).toEqual(['AK (recovery wrap)', 'keyset SK', 'keyset VK']);
      d.engine.wipeMemory();
      expect(d.captured.live()).toEqual([]);
    });

    it('a recovery whose enrollment write fails leaves nothing', async () => {
      const { server, kit } = await account();
      const d = await device(server);
      await d.engine.recoveryBegin({ username: 'synthetic-user', recoveryKey: kit });
      const fresh = await d.engine.recoverySetPassword({ password: NEW });
      await d.engine.recoveryVerifyKit({ recoveryKey: fresh.recoveryKey });
      d.failNext('apply');
      expect(await code(d.engine.recoveryFinish())).toBe('not a vault error');
      expect(d.captured.live()).toEqual([]);
    });

    it('reopening with the password keeps the session keys and zeroes its second copies', async () => {
      const CODE = `RC1-${'C'.repeat(43)}`;
      const { server, a } = await account();
      await a.engine.sync();
      server.restoreReopening(server.snapshot(), '0f0e7d2c-6b5a-4c39-8a27-1e0d9c8b7a65', CODE);
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      expect((await d.engine.unlock({ password: PASSWORD })).sessionProblem).toBe('reopening');
      const session = d.captured.live();
      expect(session).toEqual(['AK (password wrap)', 'keyset VK', 'stored SK']);
      await d.engine.reopenBegin({ reopenCode: CODE, password: PASSWORD });
      const kit = await d.engine.recoverySetPassword({ password: NEW });
      await d.engine.recoveryVerifyKit({ recoveryKey: kit.recoveryKey });
      expect((await d.engine.recoveryFinish()).reopened).toBe(true);
      // The reopening's own AK, SK and VK copies are zero; the session's are not.
      expect(d.captured.live()).toEqual(session);
      await keysStillWork(server, d, NEW);
    });
  });

  describe('setup and Secret Key rotation', () => {
    it('a setup whose enrollment write fails leaves nothing', async () => {
      const server = new FakeServer();
      const d = await device(server);
      const kit = await d.engine.setupBegin({
        bootstrapToken: 'T'.repeat(43),
        username: 'Synthetic-User',
        password: PASSWORD,
      });
      await d.engine.setupVerifyKit({ recoveryKey: kit.recoveryKey });
      d.failNext('apply');
      expect(await code(d.engine.setupFinish())).toBe('not a vault error');
      expect(d.captured.live()).toEqual([]);
    });

    it('a refused Secret Key rotation zeroes the new SK and keeps the current keys', async () => {
      const { server, a } = await account();
      a.engine.wipeMemory();
      const d = await reopen(server, a);
      await d.engine.unlock({ password: PASSWORD });
      const before = d.captured.live();
      d.before.rotateSecretKey = () => {
        throw new NetworkError('offline');
      };
      expect(await code(d.engine.rotateSecretKey({ password: PASSWORD }))).toBe('offline');
      expect(d.captured.live()).toEqual(before);
      delete d.before.rotateSecretKey;
      await keysStillWork(server, d, PASSWORD);
    });
  });
});
