import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import nextConfig from '../../next.config';

const repo = join(__dirname, '../../../..');

async function buildIdWith(value: string | undefined): Promise<string | null> {
  const before = process.env.RUVEE_BUILD_ID;
  if (value === undefined) delete process.env.RUVEE_BUILD_ID;
  else process.env.RUVEE_BUILD_ID = value;
  try {
    if (!nextConfig.generateBuildId) throw new Error('no generateBuildId');
    return await nextConfig.generateBuildId();
  } finally {
    if (before === undefined) delete process.env.RUVEE_BUILD_ID;
    else process.env.RUVEE_BUILD_ID = before;
  }
}

// A reproducible export (deployment rehearsal): Next.js's default build id is random, so two
// builds of one commit differed in 14 files and in the CSP of out-caddy/.
describe('the export build id', () => {
  it('is the checked-out commit', async () => {
    const head = execFileSync('git', ['rev-parse', 'HEAD'], { cwd: repo, encoding: 'utf8' });
    expect(await buildIdWith(undefined)).toBe(head.trim());
  });

  it('takes RUVEE_BUILD_ID when it is a full commit id', async () => {
    expect(await buildIdWith('0123456789abcdef0123456789abcdef01234567')).toBe(
      '0123456789abcdef0123456789abcdef01234567',
    );
  });

  it.each(['', 'ruvee', '87497e4', '../0123456789abcdef0123456789abcdef01234567'])(
    'refuses RUVEE_BUILD_ID %j',
    async (value) => {
      await expect(buildIdWith(value)).rejects.toThrow('RUVEE_BUILD_ID');
    },
  );

  it('keeps out-caddy/ in the build cache with out/, so a cache hit restores both', () => {
    const turbo = JSON.parse(readFileSync(join(repo, 'turbo.json'), 'utf8')) as {
      tasks: { build: { outputs: string[]; env?: string[] } };
    };
    expect(turbo.tasks.build.outputs).toEqual(expect.arrayContaining(['out/**', 'out-caddy/**']));
    expect(turbo.tasks.build.env).toContain('RUVEE_BUILD_ID');
  });
});
