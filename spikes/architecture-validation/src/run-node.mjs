import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { cpus, totalmem, release, arch } from 'node:os';
import { runChecks } from './checks.mjs';
import { profiles } from './bench-profiles.mjs';

const runs = Number(process.env.BENCH_RUNS ?? 5);
const kat = {
  wycheproof: JSON.parse(
    readFileSync(
      new URL('../kat/wycheproof-xchacha20_poly1305_test.json', import.meta.url),
      'utf8',
    ),
  ),
  blake2bKat: readFileSync(new URL('../kat/blake2b-kat.txt', import.meta.url), 'utf8'),
};

const out = await runChecks({ kat, bench: { runs, profiles }, log: (l) => console.log(l) });
out.host = {
  cpu: cpus()[0]?.model,
  cores: cpus().length,
  totalMemGiB: Math.round(totalmem() / 2 ** 30),
  os: `${process.platform} ${release()} ${arch()}`,
};
out.env.rssMiBAfter = Math.round(process.memoryUsage().rss / 2 ** 20);
mkdirSync(new URL('../results/', import.meta.url), { recursive: true });
writeFileSync(
  new URL('../results/node.json', import.meta.url),
  JSON.stringify(out, null, 2) + '\n',
);
const failed = out.results.filter((r) => r.status === 'fail');
console.log(`\n${out.results.length} checks, ${failed.length} failed`);
process.exitCode = failed.length ? 1 : 0;
