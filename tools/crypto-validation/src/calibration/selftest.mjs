// Self-test of the calibration tooling (fast; runs in CI). It checks the tooling, not the
// device: argument guards, statistics, mapping verification, output correctness and the server.

import { spawnSync } from 'node:child_process';
import { rm } from 'node:fs/promises';
import sodium from 'libsodium-wrappers-sumo';
import { argon2id } from '@noble/hashes/argon2.js';
import { hex, synthetic } from '../bytes.mjs';
import { recordingProxy } from '../proposed-rules.mjs';
import { root } from '../preflight.mjs';
import {
  BenchArgumentError,
  CONFIGS,
  SUBKEY_CONTEXT,
  configById,
  derive,
  deriveSubkey,
  runConfig,
  stats,
} from './core.mjs';
import { startServer } from './serve.mjs';

await sodium.ready;
const failures = [];
let passed = 0;
const check = async (name, fn) => {
  try {
    await fn();
    passed++;
  } catch (e) {
    failures.push(`${name}: ${e?.message ?? e}`);
  }
};
const expect = (cond, msg) => {
  if (!cond) throw new Error(msg);
};

const p1 = configById('p1-64m-t3');
const goodPw = {
  config: p1,
  password: synthetic('pw', 24),
  salt: synthetic('salt', 16),
  outLength: 32,
};
const goodKdf = { subkeyLength: 32, subkeyId: 1, context: SUBKEY_CONTEXT, key: synthetic('k', 32) };

await check('pwhash guard rejects invalid arguments before any library call', () => {
  const bad = [
    { ...goodPw, config: { ...p1 } },
    { ...goodPw, config: { ...p1, memlimit: 512 * 1048576 } },
    { ...goodPw, config: undefined },
    { ...goodPw, outLength: 31 },
    { ...goodPw, outLength: 65 },
    { ...goodPw, salt: synthetic('s', 15) },
    { ...goodPw, salt: synthetic('s', 17) },
    { ...goodPw, salt: 'sixteen-byte-str' },
    { ...goodPw, password: new Uint8Array(0) },
    { ...goodPw, password: new Uint8Array(4097) },
    { ...goodPw, password: 'a string' },
  ];
  for (const [i, args] of bad.entries()) {
    const { proxy, calls } = recordingProxy(sodium);
    let error;
    try {
      derive(proxy, args);
    } catch (e) {
      error = e;
    }
    expect(error instanceof BenchArgumentError, `case ${i} not rejected by the guard`);
    expect(
      calls.filter((c) => c.fn === 'crypto_pwhash').length === 0,
      `case ${i} reached crypto_pwhash`,
    );
  }
});

await check('V-15 guard: only 32-byte subkeys reach crypto_kdf_derive_from_key', () => {
  const bad = [
    { ...goodKdf, subkeyLength: 15 },
    { ...goodKdf, subkeyLength: 16 },
    { ...goodKdf, subkeyLength: 64 },
    { ...goodKdf, subkeyLength: 65 },
    { ...goodKdf, subkeyLength: 0 },
    { ...goodKdf, subkeyLength: NaN },
    { ...goodKdf, subkeyLength: '32' },
    { ...goodKdf, subkeyId: -1 },
    { ...goodKdf, subkeyId: 2 ** 31 },
    { ...goodKdf, subkeyId: 1.5 },
    { ...goodKdf, context: 'rvcalib' },
    { ...goodKdf, context: 'rvcalib12' },
    { ...goodKdf, context: 'rvcalié' },
    { ...goodKdf, key: synthetic('k', 31) },
    { ...goodKdf, key: 'x'.repeat(32) },
  ];
  for (const [i, args] of bad.entries()) {
    const { proxy, calls } = recordingProxy(sodium);
    let error;
    try {
      deriveSubkey(proxy, args);
    } catch (e) {
      error = e;
    }
    expect(error instanceof BenchArgumentError, `case ${i} not rejected by the guard`);
    expect(calls.length === 0, `case ${i} reached the library`);
  }
  const { proxy, calls } = recordingProxy(sodium);
  expect(deriveSubkey(proxy, goodKdf).length === 32, 'valid subkey derivation failed');
  expect(calls.length === 1 && calls[0].args[0] === 32, 'valid call not passed through unchanged');
});

await check('registry is bounded and every entry is whole KiB', () => {
  for (const c of CONFIGS) {
    expect(c.memlimit % 1024 === 0 && c.memlimit <= 256 * 1048576, `${c.id} out of bounds`);
    expect(Object.isFrozen(c), `${c.id} is mutable`);
  }
});

await check('statistics', () => {
  const s = stats(Array.from({ length: 20 }, (_, i) => 20 - i));
  expect(
    s.median === 10.5 && s.p95 === 19 && s.min === 1 && s.max === 20 && s.n === 20,
    JSON.stringify(s),
  );
  const t = stats([3, 1, 2]);
  expect(t.median === 2 && t.p95 === 3, JSON.stringify(t));
  expect(stats([]).n === 0, 'empty');
});

await check('a mapping mismatch fails the configuration', async () => {
  const { proxy } = recordingProxy(sodium, {
    crypto_pwhash_str: () => '$argon2id$v=19$m=65535,t=3,p=1$c2FsdA$aGFzaA',
  });
  const r = await runConfig(proxy, 'ref-19m-t2', {
    warmup: 0,
    samples: 1,
    now: () => performance.now(),
  });
  expect(r.status === 'failed' && r.samplesMs.length === 0, 'mismatch not detected');
});

await check('a library failure is recorded, not hidden', async () => {
  const { proxy } = recordingProxy(sodium, {
    crypto_pwhash: () => {
      throw new Error('simulated out of memory');
    },
  });
  const r = await runConfig(proxy, 'ref-19m-t2', {
    warmup: 0,
    samples: 3,
    now: () => performance.now(),
  });
  expect(
    r.status === 'failed' && /simulated/.test(r.failures[0]?.error),
    JSON.stringify(r.failures),
  );
});

await check('benchmark output equals noble Argon2id (ref-19m-t2)', async () => {
  const c = configById('ref-19m-t2');
  const r = await runConfig(sodium, c.id, { warmup: 0, samples: 2, now: () => performance.now() });
  expect(r.status === 'ok' && r.samplesMs.length === 2, JSON.stringify(r.failures));
  const expected = argon2id(
    synthetic('calibration-password', 24),
    synthetic('calibration-salt', 16),
    {
      t: c.opslimit,
      m: c.memlimit / 1024,
      p: 1,
      dkLen: 32,
    },
  );
  expect(
    r.outputFingerprint === hex(sodium.crypto_generichash(16, expected)),
    'output differs from noble',
  );
});

await check('server refuses bad requests and saves valid results', async () => {
  const { server, origin } = await startServer({ host: '127.0.0.1', port: 0 });
  try {
    const post = (body, type = 'application/json') =>
      fetch(`${origin}/results`, { method: 'POST', headers: { 'Content-Type': type }, body });
    expect((await post('{}', 'text/plain')).status === 415, 'wrong content type accepted');
    expect((await post('{"kind":"other"}')).status === 400, 'wrong kind accepted');
    expect((await post('not json')).status === 400, 'invalid JSON accepted');
    expect(
      (await fetch(`${origin}/../package.json`)).status === 404,
      'path outside the page served',
    );
    const ok = await post(
      JSON.stringify({ kind: 'argon2id-calibration', deviceLabel: 'selftest' }),
    );
    expect(ok.status === 201, `valid upload refused (${ok.status})`);
    expect(/wasm-unsafe-eval/.test(ok.headers.get('content-security-policy')), 'CSP missing');
    const { saved } = await ok.json();
    await rm(new URL(`results/calibration/manual/${saved}`, root));
  } finally {
    server.close();
  }
});

await check('server refuses to listen on all interfaces', () => {
  const r = spawnSync(process.execPath, [new URL('./serve.mjs', import.meta.url).pathname], {
    env: { ...process.env, HOST: '0.0.0.0', PORT: '0' },
    encoding: 'utf8',
    timeout: 10000,
  });
  expect(r.status === 1, `exit ${r.status}`);
});

for (const f of failures) console.log(`FAIL ${f}`);
console.log(`calibration selftest: ${passed} passed, ${failures.length} failed`);
process.exit(failures.length ? 1 : 0);
