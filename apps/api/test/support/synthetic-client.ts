import {
  initRuveeCrypto,
  uuidToBytes,
  type DeviceKeyPair,
  type Manifest,
  type RuveeCrypto,
} from '@ruvee/crypto';
import * as opaque from '@serenity-kit/opaque';
import type { RegisterFinishRequest } from '@ruvee/contracts';

/**
 * A test client built from the real libraries: `@serenity-kit/opaque` for OPAQUE and
 * `@ruvee/crypto` for every envelope. Synthetic credentials only. It mirrors what the web app
 * does, so the server is tested against genuine bytes, not hand-made fixtures.
 */

export const SYNTHETIC_PASSWORD = 'synthetic-integration-passphrase-9f2c';
export const KEY_STRETCHING = 'memory-constrained' as const;

const b64 = (bytes: Uint8Array) => Buffer.from(bytes).toString('base64url');

export interface SyntheticAccount {
  readonly crypto: RuveeCrypto;
  readonly username: string;
  readonly accountId: string;
  readonly deviceId: string;
  readonly vaultId: string;
  readonly vaultKey: Uint8Array;
  readonly vaultKeyId: Uint8Array;
  readonly recoveryKeyText: string;
  readonly secretKey: Uint8Array;
  readonly accountKey: Uint8Array;
  readonly accountKeyId: Uint8Array;
  /** This device's Ed25519 key pair (docs/security/device-proof.md §2). */
  readonly deviceKey: DeviceKeyPair;
  /** `AVPK`, the public half of the AK-derived proof key. */
  readonly akVerifyKey: Uint8Array;
  readonly finish: (registrationRecord: string, bootstrapToken: string) => RegisterFinishRequest;
}

export async function syntheticAccount(username: string): Promise<SyntheticAccount> {
  const crypto = await initRuveeCrypto();
  const accountId = crypto.generateUuid();
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
  const deviceKey = crypto.generateDeviceKey();
  const akVerifyKey = crypto.accountProofPublicKey(accountKey);
  const accountIdBytes = uuidToBytes(accountId);
  const auk = crypto.deriveAccountUnlockKey({
    password: SYNTHETIC_PASSWORD,
    passwordSalt,
    profile: 1,
    secretKey,
    accountId: accountIdBytes,
  });
  const keys = {
    kdfProfile: 1 as const,
    saltPw: b64(passwordSalt),
    akId: b64(accountKeyId),
    akEpoch: 1,
    wrappedAkPassword: b64(
      crypto.wrapAccountKey({
        accountUnlockKey: auk,
        accountKey,
        accountId: accountIdBytes,
        accountKeyId,
        accountKeyEpoch: 1,
        profile: 1,
        passwordSalt,
      }),
    ),
    recoveryKeyId: b64(recoveryKeyId),
    wrappedAkRecovery: b64(
      crypto.wrapAccountKeyForRecovery({
        recoveryWrapKey: recovery.recoveryWrapKey,
        recoveryKeyId,
        accountId: accountIdBytes,
        accountKeyId,
        accountKeyEpoch: 1,
        accountKey,
      }),
    ),
    recoveryVerifier: b64(crypto.recoveryVerifier(recovery.recoveryAuthKey)),
    keysetVersion: 1,
    keyset: b64(
      crypto.sealKeyset({
        accountKey,
        accountKeyId,
        accountId: accountIdBytes,
        keysetVersion: 1,
        keyset: { secretKey, vaults: [{ vaultId, vkId: vaultKeyId, vk: vaultKey }] },
      }),
    ),
  };
  return {
    crypto,
    username,
    accountId,
    deviceId,
    vaultId,
    vaultKey,
    vaultKeyId,
    secretKey,
    accountKey,
    accountKeyId,
    deviceKey,
    akVerifyKey,
    recoveryKeyText: crypto.formatRecoveryKey(recoveryKey),
    finish: (registrationRecord, bootstrapToken) => {
      // Op 3, as the web app signs it: bound to the setup token, zeros as the nonce (§4).
      const base = {
        operation: 'register' as const,
        accountId: accountIdBytes,
        binding: crypto.setupBinding(Buffer.from(bootstrapToken, 'base64url')),
        nonce: new Uint8Array(32),
        payload: crypto.proofPayload('register', [
          Buffer.from(registrationRecord, 'base64url'),
          deviceKey.publicKey,
          akVerifyKey,
          Buffer.from(keys.wrappedAkPassword, 'base64url'),
          Buffer.from(keys.wrappedAkRecovery, 'base64url'),
          Buffer.from(keys.recoveryVerifier, 'base64url'),
          Buffer.from(keys.keyset, 'base64url'),
          uuidToBytes(vaultId),
        ]),
      };
      return {
        bootstrapToken,
        username,
        registrationRecord,
        accountId,
        device: { id: deviceId, platform: 'web' },
        keys,
        vault: { id: vaultId, vkId: b64(vaultKeyId) },
        devicePublicKey: b64(deviceKey.publicKey),
        akVerifyKey: b64(akVerifyKey),
        proof: {
          device: b64(
            crypto.signDeviceProof({
              ...base,
              deviceId: uuidToBytes(deviceId),
              secretKey: deviceKey.secretKey,
            }),
          ),
          accountKey: b64(
            crypto.signAccountProof({ ...base, accountKeyId, accountKeyEpoch: 1, accountKey }),
          ),
        },
      };
    },
  };
}

export function startRegistration(password = SYNTHETIC_PASSWORD) {
  return opaque.client.startRegistration({ password });
}

export function finishRegistration(
  state: string,
  registrationResponse: string,
  password = SYNTHETIC_PASSWORD,
): string {
  return opaque.client.finishRegistration({
    clientRegistrationState: state,
    registrationResponse,
    password,
    keyStretching: KEY_STRETCHING,
  }).registrationRecord;
}

export function startLogin(password = SYNTHETIC_PASSWORD) {
  return opaque.client.startLogin({ password });
}

export function finishLogin(state: string, loginResponse: string, password = SYNTHETIC_PASSWORD) {
  return opaque.client.finishLogin({
    clientLoginState: state,
    loginResponse,
    password,
    keyStretching: KEY_STRETCHING,
  });
}

/** A commit's record and manifest, built the way a client builds them (sync-protocol §4.1). */
export function buildCommit(
  account: SyntheticAccount,
  options: {
    seq: number;
    prevManifestHash: Uint8Array;
    items: readonly { itemId: string; revision: number; record: Uint8Array | null }[];
    commitId?: string;
  },
) {
  const { crypto } = account;
  const commitId = options.commitId ?? crypto.generateUuid();
  const entries = options.items.map((i) => ({
    itemId: uuidToBytes(i.itemId),
    revision: i.revision,
    recordHash: i.record === null ? null : crypto.recordHash(i.record),
  }));
  const manifest: Manifest = {
    vaultId: uuidToBytes(account.vaultId),
    seq: options.seq,
    prevManifestHash: options.prevManifestHash,
    itemsDigest: crypto.itemsDigest(entries),
    liveCount: entries.filter((e) => e.recordHash !== null).length,
    tombstoneCount: entries.filter((e) => e.recordHash === null).length,
    authorDeviceId: uuidToBytes(account.deviceId),
    createdAtMs: Date.now(),
    commitId: uuidToBytes(commitId),
  };
  const envelope = crypto.sealManifest({
    vaultKey: account.vaultKey,
    vaultKeyId: account.vaultKeyId,
    manifest,
  });
  return { commitId, manifest: envelope, manifestHash: crypto.manifestHash(envelope) };
}

export function sealItem(
  account: SyntheticAccount,
  itemId: string,
  revision: number,
  body: object,
  previousRecord?: Uint8Array,
): Uint8Array {
  return account.crypto.sealItemRecord({
    vaultKey: account.vaultKey,
    vaultKeyId: account.vaultKeyId,
    vaultId: uuidToBytes(account.vaultId),
    itemId: uuidToBytes(itemId),
    revision,
    schemaVersion: 1,
    body: new TextEncoder().encode(JSON.stringify(body)),
    ...(previousRecord ? { previousRecord } : {}),
  });
}
