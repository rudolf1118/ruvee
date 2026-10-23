// Argon2id calibration core (P2-02). Shared by the Node worker and the browser worker.
// Measurement only: synthetic inputs, a fixed registry of configurations, and argument checks
// that run before every library call. Not an API for application code.

import { hex, synthetic } from '../bytes.mjs';

export const MiB = 1024 * 1024;

// The only memory limit the benchmark will pass to crypto_pwhash.
export const MAX_BENCH_MEMLIMIT = 256 * MiB;

// Fixed, bounded set. Every entry cites its basis in the existing specification. Ids are stable
// so results from different devices can be compared.
export const CONFIGS = Object.freeze(
  [
    {
      id: 'ref-19m-t2',
      role: 'comparison',
      opslimit: 2,
      memlimit: 19 * MiB,
      basis:
        'OWASP Password Storage Cheat Sheet server-side minimum (m = 19 MiB, t = 2, p = 1), cited in research-sources.md. Comparison only: weaker than profile 1, which may never be weakened.',
    },
    {
      id: 'p1-64m-t3',
      role: 'baseline',
      opslimit: 3,
      memlimit: 64 * MiB,
      basis:
        'Profile 1 as proposed in cryptographic-design.md §3.2 (provisional); memory and iterations of the second RFC 9106 §4 recommendation, with p = 1 because crypto_pwhash fixes parallelism.',
    },
    {
      id: 'c-64m-t4',
      role: 'candidate',
      opslimit: 4,
      memlimit: 64 * MiB,
      basis:
        'Strengthens profile 1 in time only, staying inside the 128 MiB peak-memory budget of §3.2.',
    },
    {
      id: 'c-128m-t3',
      role: 'candidate',
      opslimit: 3,
      memlimit: 128 * MiB,
      basis:
        'Strengthens profile 1 in memory up to the 128 MiB peak-memory budget of §3.2. The Argon2 memory alone equals that budget, so total peak memory necessarily exceeds it.',
    },
    {
      id: 'p2-256m-t3',
      role: 'reserved',
      opslimit: 3,
      memlimit: 256 * MiB,
      basis:
        'Profile 2 (reserved) in cryptographic-design.md §3.2. Exceeds the 128 MiB peak-memory budget by design; measured to show the cost, not proposed for V1.',
    },
  ].map((c) => Object.freeze(c)),
);

export const RUN_MODES = Object.freeze({
  standard: Object.freeze({ warmup: 3, samples: 20 }),
  quick: Object.freeze({ warmup: 1, samples: 5 }),
});

// The baseline is measured again at the end to expose thermal or power drift during a run.
export const DEFAULT_ORDER = Object.freeze([...CONFIGS.map((c) => c.id), 'p1-64m-t3']);

export const SUBKEY_CONTEXT = 'rvcalib1';
export const OUTPUT_BYTES = 32;
export const SALT_BYTES = 16;

export class BenchArgumentError extends Error {
  constructor(reason) {
    super(reason);
    this.name = 'BenchArgumentError';
  }
}

const fail = (reason) => {
  throw new BenchArgumentError(reason);
};

export function configById(id) {
  const c = CONFIGS.find((x) => x.id === id);
  if (!c) fail(`unknown_config:${String(id)}`);
  return c;
}

export function argon2Mapping(c) {
  return {
    api: 'crypto_pwhash(outlen, passwd, salt, opslimit, memlimit, crypto_pwhash_ALG_ARGON2ID13)',
    opslimit: c.opslimit,
    memlimitBytes: c.memlimit,
    argon2: { type: 'argon2id', version: '0x13', t: c.opslimit, mKiB: c.memlimit / 1024, p: 1 },
    outputBytes: OUTPUT_BYTES,
    saltBytes: SALT_BYTES,
    secret: 'none',
    associatedData: 'none',
  };
}

// libsodium floors memlimit to whole KiB and has no ceiling below the WebAssembly limit
// (LB-ARGON2-SILENT-ADJUSTMENTS), so the exact values are enforced here instead.
export function validatePwhashArgs(sodium, { config, password, salt, outLength }) {
  const c = configById(config?.id);
  if (c !== config) fail('config_not_from_registry');
  for (const [name, v] of [
    ['opslimit', c.opslimit],
    ['memlimit', c.memlimit],
  ])
    if (!Number.isSafeInteger(v) || v <= 0) fail(`${name}_not_positive_integer`);
  if (c.memlimit % 1024 !== 0) fail('memlimit_not_whole_kib');
  if (c.memlimit > MAX_BENCH_MEMLIMIT) fail('memlimit_above_benchmark_cap');
  if (outLength !== OUTPUT_BYTES) fail('output_length_not_32');
  if (!(salt instanceof Uint8Array) || salt.length !== sodium.crypto_pwhash_SALTBYTES)
    fail('salt_not_16_bytes');
  if (!(password instanceof Uint8Array) || password.length < 1 || password.length > 4096)
    fail('password_not_1_to_4096_bytes');
}

// V-15: libsodium.js 0.8.4 returns uninitialised WebAssembly memory instead of failing when
// subkey_len is outside 16..64. This check is the benchmark's own guard; it does not fix the
// library, and the production integration issue stays open.
export function validateKdfArgs({ subkeyLength, subkeyId, context, key }) {
  if (subkeyLength !== 32) fail('subkey_length_not_32');
  if (!Number.isSafeInteger(subkeyId) || subkeyId < 0 || subkeyId > 2 ** 31 - 1)
    fail('subkey_id_out_of_range');
  if (typeof context !== 'string' || !/^[\x20-\x7e]{8}$/.test(context))
    fail('context_not_8_printable_ascii');
  if (!(key instanceof Uint8Array) || key.length !== 32) fail('key_not_32_bytes');
}

export function derive(sodium, args) {
  validatePwhashArgs(sodium, args);
  const { config, password, salt, outLength } = args;
  return sodium.crypto_pwhash(
    outLength,
    password,
    salt,
    config.opslimit,
    config.memlimit,
    sodium.crypto_pwhash_ALG_ARGON2ID13,
  );
}

export function deriveSubkey(sodium, args) {
  validateKdfArgs(args);
  return sodium.crypto_kdf_derive_from_key(
    args.subkeyLength,
    args.subkeyId,
    args.context,
    args.key,
  );
}

// Confirms the mapping with the library's own description of the parameters it used.
export function verifyMapping(sodium, config, password) {
  validatePwhashArgs(sodium, {
    config,
    password,
    salt: new Uint8Array(sodium.crypto_pwhash_SALTBYTES),
    outLength: OUTPUT_BYTES,
  });
  const encoded = sodium.crypto_pwhash_str(password, config.opslimit, config.memlimit);
  const m = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(encoded);
  const observed = m ? { mKiB: Number(m[1]), t: Number(m[2]), p: Number(m[3]) } : null;
  const ok =
    observed !== null &&
    observed.mKiB === config.memlimit / 1024 &&
    observed.t === config.opslimit &&
    observed.p === 1;
  return { ok, prefix: `${encoded.split('$').slice(0, 4).join('$')}$`, observed };
}

export function stats(values) {
  const v = [...values].sort((a, b) => a - b);
  const n = v.length;
  if (n === 0) return { n: 0 };
  const mid = Math.floor(n / 2);
  const round = (x) => Math.round(x * 100) / 100;
  return {
    n,
    median: round(n % 2 ? v[mid] : (v[mid - 1] + v[mid]) / 2),
    p95: round(v[Math.ceil(0.95 * n) - 1]),
    min: round(v[0]),
    max: round(v[n - 1]),
    mean: round(v.reduce((a, b) => a + b, 0) / n),
  };
}

export function timerResolution(now) {
  let best = Infinity;
  for (let i = 0; i < 50; i++) {
    const a = now();
    let b = now();
    while (b === a) b = now();
    best = Math.min(best, b - a);
  }
  return Math.round(best * 1e6) / 1e6;
}

export const wasmLinearMemoryBytes = (sodium) => sodium.libsodium?.HEAPU8?.length ?? null;

const describeError = (e) =>
  e instanceof Error ? `${e.name}: ${e.message}` : `non-Error: ${String(e?.message ?? e)}`;

// Runs one configuration: mapping check, warm-up, timed samples, one subkey derivation.
// Stops at the first failure, because an aborted WebAssembly module may be unusable.
export async function runConfig(
  sodium,
  configId,
  { warmup, samples, now, pause = async () => {}, cancelled = () => false, onProgress = () => {} },
) {
  const config = configById(configId);
  const password = synthetic('calibration-password', 24);
  const salt = synthetic('calibration-salt', SALT_BYTES);
  const args = { config, password, salt, outLength: OUTPUT_BYTES };
  const result = {
    configId,
    role: config.role,
    mapping: argon2Mapping(config),
    status: 'ok',
    warmupMs: [],
    samplesMs: [],
    failures: [],
    wasmLinearMemoryBytesBefore: wasmLinearMemoryBytes(sodium),
  };
  let fingerprint = null;
  let phase = 'mapping';
  try {
    result.mappingCheck = verifyMapping(sodium, config, password);
    if (!result.mappingCheck.ok) throw new Error('encoded parameters differ from the registry');
    for (const [kind, count] of [
      ['warmup', warmup],
      ['sample', samples],
    ]) {
      phase = kind;
      for (let i = 0; i < count; i++) {
        if (cancelled()) {
          result.status = 'cancelled';
          return finish();
        }
        const t0 = now();
        const out = derive(sodium, args);
        const ms = now() - t0;
        if (!(out instanceof Uint8Array) || out.length !== OUTPUT_BYTES)
          throw new Error('derivation returned the wrong length');
        const fp = hex(sodium.crypto_generichash(16, out));
        if (fingerprint === null) {
          fingerprint = fp;
          const sub0 = now();
          const subkey = deriveSubkey(sodium, {
            subkeyLength: 32,
            subkeyId: 1,
            context: SUBKEY_CONTEXT,
            key: out,
          });
          result.subkeyDerivationMs = Math.round((now() - sub0) * 1000) / 1000;
          sodium.memzero(subkey);
        } else if (fp !== fingerprint) throw new Error('derivation output changed between runs');
        sodium.memzero(out);
        (kind === 'warmup' ? result.warmupMs : result.samplesMs).push(Math.round(ms * 1000) / 1000);
        onProgress({ configId, kind, index: i, ms });
        await pause();
      }
    }
  } catch (e) {
    result.status = 'failed';
    result.failures.push({ phase, error: describeError(e) });
  }
  return finish();

  function finish() {
    result.outputFingerprint = fingerprint;
    result.stats = stats(result.samplesMs);
    result.wasmLinearMemoryBytesAfter = wasmLinearMemoryBytes(sodium);
    sodium.memzero(password);
    return result;
  }
}
