// Browser bundle entry, used by both the page and the dedicated worker. Vector files are fetched
// from the local test server and verified by SHA-256 exactly as in Node.

import sodium from 'libsodium-wrappers-sumo';
import { runNegativeControls } from '../negative-controls.mjs';
import { createContext, runSuite } from '../suite.mjs';

const plain = (value) =>
  JSON.parse(JSON.stringify(value, (k, v) => (typeof v === 'bigint' ? v.toString() : v)));
const describe = (e) => (e instanceof Error ? `${e.name}: ${e.message}` : String(e));

async function fetchOk(path) {
  const res = await fetch(path, { cache: 'no-store' });
  if (!res.ok) throw new Error(`${path}: HTTP ${res.status}`);
  return res;
}

async function runValidation() {
  try {
    const manifest = await (await fetchOk('/vectors/sources.json')).json();
    const readBytes = async (file) =>
      new Uint8Array(await (await fetchOk(`/vectors/${file}`)).arrayBuffer());
    const suite = await runSuite({ manifest, readBytes });
    const ctx = await createContext({ manifest, readBytes });
    const controls = await runNegativeControls({ ctx, manifest, readBytes });
    return plain({ ...suite, packages: __PACKAGES__, negativeControls: controls });
  } catch (e) {
    return { fatal: describe(e) };
  }
}

// Initialises libsodium only; used to show whether the page CSP permits WebAssembly compilation.
async function probeWasm(timeoutMs = 10000) {
  const timeout = new Promise((resolve) =>
    setTimeout(() => resolve({ ok: false, error: `not ready after ${timeoutMs} ms` }), timeoutMs),
  );
  const ready = sodium.ready.then(
    () => ({ ok: true, version: sodium.sodium_version_string() }),
    (e) => ({ ok: false, error: describe(e) }),
  );
  return Promise.race([ready, timeout]);
}

globalThis.runValidation = runValidation;
globalThis.probeWasm = probeWasm;

if (
  typeof globalThis.WorkerGlobalScope !== 'undefined' &&
  globalThis instanceof globalThis.WorkerGlobalScope
) {
  const violations = [];
  globalThis.addEventListener('securitypolicyviolation', (e) =>
    violations.push(`${e.effectiveDirective}: ${e.blockedURI}`),
  );
  globalThis.onmessage = async (event) => {
    const out = event.data === 'probe' ? await probeWasm() : await runValidation();
    globalThis.postMessage({ ...out, violations });
  };
}
