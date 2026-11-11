// Assembles the four check categories and the shared context. Runs unchanged in Node, a browser
// page and a dedicated Web Worker.

import sodiumModule from 'libsodium-wrappers-sumo';
import { argon2id } from '@noble/hashes/argon2.js';
import { blake2b } from '@noble/hashes/blake2.js';
import { hchacha, xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hsalsa, xsalsa20poly1305 } from '@noble/ciphers/salsa.js';
import { x25519 } from '@noble/curves/ed25519.js';

import { crossImplementationChecks } from './checks/cross-implementation.mjs';
import { libraryBehaviorChecks } from './checks/library-behavior.mjs';
import { proposedRuleChecks } from './checks/proposed-rules.mjs';
import { publishedKatChecks } from './checks/published-kat.mjs';
import { runChecks, summarize, verifyCompleteness } from './harness.mjs';
import { createRules } from './proposed-rules.mjs';
import { loadVerifiedSources } from './sources.mjs';
import { parseVectors } from './vectors.mjs';

export const ALL_CHECKS = [
  ...publishedKatChecks,
  ...crossImplementationChecks,
  ...libraryBehaviorChecks,
  ...proposedRuleChecks,
];
export const CHECK_IDS = ALL_CHECKS.map((c) => c.id);
if (new Set(CHECK_IDS).size !== CHECK_IDS.length) throw new Error('duplicate check ids');

export const noble = Object.freeze({
  argon2id,
  blake2b,
  hchacha,
  xchacha20poly1305,
  hsalsa,
  xsalsa20poly1305,
  x25519,
});

function scope() {
  const g = globalThis;
  if (typeof g.WorkerGlobalScope !== 'undefined' && g instanceof g.WorkerGlobalScope)
    return 'dedicated-worker';
  if (typeof g.document !== 'undefined') return 'window';
  if (g.process?.versions?.node) return 'node';
  return 'unknown';
}

export async function createContext({ manifest, readBytes }) {
  const sources = await loadVerifiedSources(manifest, readBytes);
  await sodiumModule.ready;
  return {
    sodium: sodiumModule,
    noble,
    vectors: parseVectors(sources),
    rules: createRules('proposed'),
    sources,
  };
}

export function environment(sodium) {
  const g = globalThis;
  return {
    scope: scope(),
    userAgent: g.navigator?.userAgent ?? null,
    node: g.process?.versions?.node ?? null,
    v8: g.process?.versions?.v8 ?? null,
    platform: g.process ? `${g.process.platform} ${g.process.arch}` : null,
    hardwareConcurrency: g.navigator?.hardwareConcurrency ?? null,
    sodiumVersionString: sodium.sodium_version_string(),
    sodiumLibraryVersion: `${sodium.SODIUM_LIBRARY_VERSION_MAJOR}.${sodium.SODIUM_LIBRARY_VERSION_MINOR}`,
    nativeIsWellFormed: typeof String.prototype.isWellFormed === 'function',
  };
}

export async function runSuite({ manifest, readBytes, log = () => {} }) {
  const t0 = globalThis.performance.now();
  const ctx = await createContext({ manifest, readBytes });
  const results = await runChecks(ALL_CHECKS, ctx, { log });
  return {
    environment: environment(ctx.sodium),
    results,
    summary: summarize(results),
    completenessProblems: verifyCompleteness(results, CHECK_IDS),
    wallMs: Math.round(globalThis.performance.now() - t0),
  };
}
