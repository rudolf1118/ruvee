import * as opaque from '@serenity-kit/opaque';
import { runChecks } from './checks.mjs';
import { profiles } from './bench-profiles.mjs';

async function loadKat(base) {
  const [wycheproof, blake2bKat] = await Promise.all([
    fetch(`${base}/kat/wycheproof-xchacha20_poly1305_test.json`).then((r) => r.json()),
    fetch(`${base}/kat/blake2b-kat.txt`).then((r) => r.text()),
  ]);
  return { wycheproof, blake2bKat };
}

async function run({ base = '', runs = 0 } = {}) {
  const logs = [];
  try {
    const kat = await loadKat(base);
    const out = await runChecks({ kat, bench: { runs, profiles }, log: (l) => logs.push(l) });
    return { ...out, logs };
  } catch (e) {
    return { fatal: e instanceof Error ? `${e.name}: ${e.message}` : String(e), logs };
  }
}

globalThis.runSpike = run;

globalThis.probeOpaqueOnly = async () => {
  try {
    await opaque.ready;
    return { ok: true, setupLength: opaque.server.createSetup().length };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? `${e.name}: ${e.message}` : String(e) };
  }
};

if (
  typeof globalThis.WorkerGlobalScope !== 'undefined' &&
  globalThis instanceof globalThis.WorkerGlobalScope &&
  typeof globalThis.ServiceWorkerGlobalScope === 'undefined'
) {
  globalThis.onmessage = async (event) => globalThis.postMessage(await run(event.data));
}
