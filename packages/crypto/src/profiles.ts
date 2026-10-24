import { RuveeCryptoError } from './errors.js';

/**
 * Argon2id profile registry (cryptographic-design §3.2). Parameters are never read from the
 * server or from library constants; an account stores only the profile id.
 */
export interface KdfProfile {
  readonly id: number;
  /** Profile 1 is provisional until D-03 and D-26 are settled on the reference devices. */
  readonly status: 'provisional';
  readonly opslimit: number;
  /** Bytes, a whole number of KiB, so libsodium cannot round it down. */
  readonly memlimit: number;
  readonly outputBytes: 32;
}

const PROFILE_1: KdfProfile = Object.freeze({
  id: 1,
  status: 'provisional',
  opslimit: 3,
  memlimit: 64 * 1024 * 1024,
  outputBytes: 32,
});

const ENABLED: ReadonlyMap<number, KdfProfile> = new Map([[1, PROFILE_1]]);

/** Specified but enabled only by a future release, after its benchmarks pass. */
const RESERVED: ReadonlySet<number> = new Set([2]);

export const DEFAULT_KDF_PROFILE = PROFILE_1.id;

/** Resolves a profile id, failing before any derivation for unknown or reserved ids (INV-05). */
export function resolveKdfProfile(id: unknown): KdfProfile {
  const profile = typeof id === 'number' ? ENABLED.get(id) : undefined;
  if (profile) return profile;
  const reason = typeof id === 'number' && RESERVED.has(id) ? 'reserved' : 'unknown';
  throw new RuveeCryptoError('unsupported_profile', { reason });
}

/** True only for the frozen registry objects, so forged parameter objects never reach Argon2id. */
export function isRegisteredProfile(value: unknown): value is KdfProfile {
  for (const profile of ENABLED.values()) if (value === profile) return true;
  return false;
}
