// Node runner: version preflight, all four check categories, then the negative controls.
// Exit code 1 on any failure, missing result or ineffective negative control.

import { mkdir, writeFile } from 'node:fs/promises';
import { CATEGORIES } from './harness.mjs';
import { runNegativeControls } from './negative-controls.mjs';
import { pinnedVersions, readJson, readVector, root, toJson } from './preflight.mjs';
import { ALL_CHECKS, createContext, environment, runSuite } from './suite.mjs';

async function main() {
  const versions = await pinnedVersions();
  if (versions.problems.length) {
    console.error('Version preflight failed:\n  ' + versions.problems.join('\n  '));
    process.exit(1);
  }
  const manifest = await readJson('vectors/sources.json');
  const log = (l) => console.log(`  ${l}`);

  console.log('Checks');
  const suite = await runSuite({ manifest, readBytes: readVector, log });

  console.log('\nNegative controls (each must make its target check fail)');
  const ctx = await createContext({ manifest, readBytes: readVector });
  const t0 = performance.now();
  const controls = await runNegativeControls({ ctx, manifest, readBytes: readVector });
  const ineffective = controls.filter((c) => !c.passed);
  for (const c of ineffective) console.log(`  FAIL ${c.id}: ${c.fault}`);
  console.log(
    `  ${controls.length - ineffective.length}/${controls.length} controls made their target fail (${Math.round(performance.now() - t0)} ms)`,
  );

  const report = {
    generatedAt: new Date().toISOString(),
    runtime: 'node',
    environment: { ...environment(ctx.sodium), packages: versions.installed },
    summary: suite.summary,
    completenessProblems: suite.completenessProblems,
    checks: ALL_CHECKS.map(({ run, ...meta }) => ({
      ...meta,
      ...suite.results.find((r) => r.id === meta.id),
    })),
    negativeControls: {
      total: controls.length,
      ineffective: ineffective.map((c) => c.id),
      controls,
    },
  };
  await mkdir(new URL('results/', root), { recursive: true });
  await writeFile(new URL('results/node.json', root), toJson(report));

  console.log(`\nSummary (Node ${process.versions.node})`);
  for (const [cat, meta] of Object.entries(CATEGORIES).sort((a, b) => a[1].order - b[1].order)) {
    const c = suite.summary.byCategory[cat] ?? { pass: 0, fail: 0 };
    console.log(`  ${meta.order}. ${meta.title}: ${c.pass} passed, ${c.fail} failed`);
  }
  for (const p of suite.completenessProblems) console.log(`  INCOMPLETE ${p}`);
  const ok =
    suite.summary.failed.length === 0 &&
    suite.completenessProblems.length === 0 &&
    ineffective.length === 0;
  console.log(
    ok ? '  RESULT: all checks passed and every negative control was detected' : '  RESULT: FAILED',
  );
  process.exit(ok ? 0 : 1);
}

main().catch((e) => {
  console.error(`FATAL ${e?.name ?? 'Error'}: ${e?.message ?? e}`);
  process.exit(1);
});
