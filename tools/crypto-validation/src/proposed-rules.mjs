// PROPOSED rules, not approved. Test-local reference predicates for input rules written in
// docs/security/cryptographic-design.md (§2 lengths, §3.1 password input, §3.2 profiles) and
// open decisions D-03 and D-20. They exist so the harness can show which protections the caller
// would have to supply. They are not an application API and must not be imported by apps or
// packages; P2-03 implements and reviews the real ones.

import { te } from './bytes.mjs';

export class RuleRejection extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'RuleRejection';
    this.reason = reason;
  }
}

const reject = (reason) => {
  throw new RuleRejection(reason);
};

// Unpaired-surrogate scan, independent of String.prototype.isWellFormed so the two can be compared.
export function isWellFormedUtf16(s) {
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c >= 0xd800 && c <= 0xdbff) {
      const d = s.charCodeAt(i + 1);
      if (!(d >= 0xdc00 && d <= 0xdfff)) return false;
      i++;
    } else if (c >= 0xdc00 && c <= 0xdfff) return false;
  }
  return true;
}

export const PASSWORD_MAX_UTF8_BYTES = 4096;

// D-20 (Proposed): reject strings that are not well formed, then NFC, then 1 to 4,096 UTF-8 bytes.
function normalizePassword(input) {
  if (typeof input !== 'string') reject('password_not_a_string');
  if (!isWellFormedUtf16(input)) reject('password_not_well_formed');
  const value = input.normalize('NFC');
  const bytes = te.encode(value);
  if (bytes.length === 0) reject('password_empty');
  if (bytes.length > PASSWORD_MAX_UTF8_BYTES) reject('password_too_long');
  return { value, bytes };
}

function requireBytes(x, length, what) {
  if (!(x instanceof Uint8Array)) reject(`${what}_not_bytes`);
  if (length !== undefined && x.length !== length) reject(`${what}_wrong_length`);
  return x;
}

// cryptographic-design §3.2 (Proposed; profile 1 provisional per D-03). Parameters come only from
// this registry, never from raw numbers. Profile 2 is reserved and not enabled.
const PROFILES = new Map([[1, { opslimit: 3, memlimit: 64 * 1024 * 1024, outLength: 32 }]]);
const RESERVED_PROFILES = new Set([2]);

function resolveProfile(id) {
  if (!Number.isInteger(id)) reject('profile_id_not_integer');
  if (RESERVED_PROFILES.has(id)) reject('profile_not_enabled');
  const p = PROFILES.get(id);
  if (!p) reject('profile_unknown');
  return p;
}

const MAC_KEY_LENGTHS = new Set([16, 32]);
const KDF_CONTEXT = /^[\x20-\x7e]{8}$/;

// mode 'proposed' validates before any library call. The other modes exist only for negative
// controls: 'permissive' validates nothing, 'late' calls the library first and validates after.
export function createRules(mode = 'proposed') {
  const validate = mode !== 'permissive';
  const late = mode === 'late';
  const guarded = (check, call) => {
    if (late) {
      const out = call();
      check();
      return out;
    }
    if (validate) check();
    return call();
  };
  return {
    mode,
    normalizePassword: validate
      ? normalizePassword
      : (input) => ({ value: input, bytes: typeof input === 'string' ? te.encode(input) : input }),
    resolveProfile: validate ? resolveProfile : (id) => PROFILES.get(id) ?? id,

    mac(sodium, key, msg, keyLength) {
      return guarded(
        () => {
          if (!MAC_KEY_LENGTHS.has(keyLength)) reject('mac_key_length_not_allowed');
          requireBytes(key, keyLength, 'mac_key');
          requireBytes(msg, undefined, 'mac_message');
        },
        () => sodium.crypto_generichash(32, msg, key),
      );
    },

    kdf(sodium, key, context, subkeyLength = 32) {
      return guarded(
        () => {
          requireBytes(key, 32, 'kdf_key');
          if (typeof context !== 'string' || !KDF_CONTEXT.test(context))
            reject('kdf_context_not_8_ascii');
          if (subkeyLength !== 32) reject('kdf_subkey_length_not_32');
        },
        () => sodium.crypto_kdf_derive_from_key(subkeyLength, 1, context, key),
      );
    },

    pwhash(sodium, profileId, password, salt) {
      const checked = () => {
        const profile = resolveProfile(profileId);
        const { bytes } = normalizePassword(password);
        requireBytes(salt, 16, 'password_salt');
        return { profile, bytes };
      };
      const unchecked = () => ({
        profile:
          PROFILES.get(profileId) ??
          (profileId && typeof profileId === 'object' ? profileId : PROFILES.get(1)),
        bytes: typeof password === 'string' ? te.encode(password) : password,
      });
      const derive = ({ profile, bytes }) =>
        sodium.crypto_pwhash(
          32,
          bytes,
          salt,
          profile.opslimit,
          profile.memlimit,
          sodium.crypto_pwhash_ALG_ARGON2ID13,
        );
      if (!validate) return derive(unchecked());
      if (!late) return derive(checked());
      const out = derive(unchecked());
      checked();
      return out;
    },
  };
}

// Records which library functions were called, optionally replacing some with stubs.
export function recordingProxy(sodium, stubs = {}) {
  const calls = [];
  const proxy = new Proxy(sodium, {
    get(target, prop) {
      const v = target[prop];
      if (typeof prop === 'string' && /^crypto_/.test(prop) && typeof v === 'function')
        return (...args) => {
          calls.push({ fn: prop, args });
          return stubs[prop] ? stubs[prop](...args) : v.apply(target, args);
        };
      return v;
    },
  });
  return { proxy, calls };
}
