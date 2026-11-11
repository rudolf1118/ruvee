// Check registry, runner and result verification. A check either passes or fails: there is no
// skip status, and a run is complete only if every registered check reported exactly once.

import { errorSummary } from './bytes.mjs';

export const CATEGORIES = {
  'published-kat': {
    order: 1,
    title: 'Published known-answer tests',
    meaning:
      'The output equals bytes printed in an authoritative published source. Expected values are parsed from hash-verified files.',
  },
  'cross-implementation': {
    order: 2,
    title: 'Cross-implementation checks',
    meaning:
      'libsodium.js and @noble/* (or a harness reference) produce the same bytes. Agreement is not independent proof of correctness: both can share a defect or the same misreading of a specification.',
  },
  'library-behavior': {
    order: 3,
    title: 'Library behavior and boundary checks',
    meaning:
      'What the pinned libsodium.js build actually does at its edges, including limits it documents but does not enforce. Each check states whether the library or nobody enforces the constraint.',
  },
  'proposed-rule': {
    order: 4,
    title: 'Proposed Ruvee input-validation rules',
    meaning:
      'Reference predicates for rules that are Proposed, not approved. They exist only in this harness and are not an application API.',
  },
};

export const ENFORCEMENT = {
  library: 'Enforced by the library',
  notEnforced: 'Not enforced by the library',
  harness: 'Enforced only by the harness reference predicate (proposed rule)',
};

// Heavy key-derivation cases never allocate more than this per call.
export const MAX_KDF_MEMORY_KIB = 64 * 1024;

const required = ['id', 'category', 'primitive', 'title', 'subject', 'expectedFrom', 'run'];

export function defineCheck(spec) {
  for (const f of required) if (spec[f] === undefined) throw new Error(`${spec.id}: missing ${f}`);
  if (!CATEGORIES[spec.category]) throw new Error(`${spec.id}: unknown category ${spec.category}`);
  if (spec.category === 'library-behavior' && !spec.enforcement)
    throw new Error(`${spec.id}: library-behavior checks must state enforcement`);
  if (spec.category === 'proposed-rule' && !(spec.proposal && spec.status === 'Proposed'))
    throw new Error(`${spec.id}: proposed-rule checks must cite the proposal and be Proposed`);
  if (spec.category !== 'published-kat' && spec.vectors)
    throw new Error(`${spec.id}: only published-kat checks read published vectors`);
  return Object.freeze({ ...spec });
}

export function describe(check) {
  const { run, ...rest } = check;
  return rest;
}

export async function runChecks(checks, ctx, { log = () => {} } = {}) {
  const results = [];
  for (const check of checks) {
    const t0 = globalThis.performance.now();
    let entry;
    try {
      const details = (await check.run(ctx)) ?? {};
      entry = { status: 'pass', details };
    } catch (e) {
      entry = { status: 'fail', error: errorSummary(e), details: e?.data };
    }
    entry = {
      id: check.id,
      category: check.category,
      ms: Math.round(globalThis.performance.now() - t0),
      ...entry,
    };
    results.push(entry);
    log(
      `${entry.status === 'pass' ? 'PASS' : 'FAIL'} ${check.id} (${entry.ms} ms)${entry.error ? ` ${entry.error}` : ''}`,
    );
  }
  return results;
}

// Fails closed: a missing, duplicated, unknown or non-binary result makes the run invalid.
export function verifyCompleteness(results, expectedIds) {
  const problems = [];
  const seen = new Map();
  for (const r of results ?? []) seen.set(r.id, (seen.get(r.id) ?? 0) + 1);
  for (const id of expectedIds) {
    if (!seen.has(id)) problems.push(`missing result: ${id}`);
    else if (seen.get(id) > 1) problems.push(`duplicate result: ${id}`);
  }
  for (const id of seen.keys())
    if (!expectedIds.includes(id)) problems.push(`unexpected result: ${id}`);
  for (const r of results ?? [])
    if (r.status !== 'pass' && r.status !== 'fail')
      problems.push(`invalid status "${r.status}" for ${r.id}`);
  return problems;
}

export function summarize(results) {
  const byCategory = {};
  for (const r of results) {
    const c = (byCategory[r.category] ??= { pass: 0, fail: 0 });
    c[r.status === 'pass' ? 'pass' : 'fail']++;
  }
  return {
    total: results.length,
    passed: results.filter((r) => r.status === 'pass').length,
    failed: results.filter((r) => r.status !== 'pass').map((r) => r.id),
    byCategory,
  };
}
