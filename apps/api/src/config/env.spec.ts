import { InvalidEnvironmentError, validateEnv } from './env.js';

const validUrl = 'postgresql://ruvee:local-only@127.0.0.1:5432/ruvee';
const required = {
  DATABASE_URL: validUrl,
  OPAQUE_SERVER_SETUP_FILE: '/run/secrets/opaque-server-setup',
  PUBLIC_ORIGIN: 'http://127.0.0.1:3100',
};

function problemsFor(raw: Record<string, unknown>): string[] {
  try {
    validateEnv(raw);
  } catch (error) {
    if (error instanceof InvalidEnvironmentError) return error.problems;
    throw error;
  }
  throw new Error('Expected validation to fail');
}

describe('validateEnv', () => {
  it('applies safe defaults when only the required variables are set', () => {
    expect(validateEnv(required)).toEqual({
      ...required,
      NODE_ENV: 'development',
      API_HOST: '127.0.0.1',
      API_PORT: 4000,
      LOG_LEVEL: 'info',
      READINESS_DB_TIMEOUT_MS: 2000,
      SESSION_COOKIE_SECURE: 'true',
    });
  });

  it('requires the OPAQUE setup file and the public origin', () => {
    const problems = problemsFor({ DATABASE_URL: validUrl });
    expect(problems.join('\n')).toMatch(/OPAQUE_SERVER_SETUP_FILE/);
    expect(problems.join('\n')).toMatch(/PUBLIC_ORIGIN/);
  });

  it.each([['http://127.0.0.1:3100/'], ['http://host/path'], ['ftp://host'], ['not a url']])(
    'rejects PUBLIC_ORIGIN=%s',
    (value) => {
      const problems = problemsFor({ ...required, PUBLIC_ORIGIN: value });
      expect(problems.length).toBeGreaterThan(0);
      for (const problem of problems) expect(problem).toMatch(/^PUBLIC_ORIGIN: /);
    },
  );

  it('accepts only an age X25519 public key as the backup recipient, never a private key', () => {
    const recipient = `age1${'q'.repeat(58)}`;
    expect(validateEnv({ ...required, BACKUP_AGE_RECIPIENT: recipient }).BACKUP_AGE_RECIPIENT).toBe(
      recipient,
    );
    for (const value of [
      `AGE-SECRET-KEY-1${'Q'.repeat(58)}`,
      'age1short',
      `age1pq1${'q'.repeat(58)}`,
    ]) {
      const problems = problemsFor({ ...required, BACKUP_AGE_RECIPIENT: value });
      expect(problems).toEqual(['BACKUP_AGE_RECIPIENT: Must be an age X25519 recipient (age1…)']);
      // The value itself is never echoed (it might be a secret pasted by mistake).
      expect(problems.join('\n')).not.toContain(value);
    }
  });

  it('refuses an insecure session cookie in production', () => {
    expect(
      problemsFor({ ...required, NODE_ENV: 'production', SESSION_COOKIE_SECURE: 'false' }),
    ).toEqual([expect.stringMatching(/^SESSION_COOKIE_SECURE: /)]);
    expect(validateEnv({ ...required, SESSION_COOKIE_SECURE: 'false' }).SESSION_COOKIE_SECURE).toBe(
      'false',
    );
  });

  it('allows the test-only instance-lock bypass only when NODE_ENV is test', () => {
    for (const NODE_ENV of ['production', 'development'])
      expect(
        problemsFor({ ...required, NODE_ENV, RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK: '1' }),
      ).toEqual([expect.stringMatching(/^RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK: /)]);
    expect(
      problemsFor({ ...required, NODE_ENV: 'test', RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK: 'true' }),
    ).toEqual([expect.stringMatching(/^RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK: /)]);
    expect(
      validateEnv({ ...required, NODE_ENV: 'test', RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK: '1' })
        .RUVEE_TEST_ONLY_SKIP_INSTANCE_LOCK,
    ).toBe('1');
  });

  it('coerces numeric values from strings', () => {
    const env = validateEnv({ ...required, API_PORT: '8080' });
    expect(env.API_PORT).toBe(8080);
  });

  it('treats empty strings as unset so defaults still apply', () => {
    const env = validateEnv({ ...required, API_PORT: '', API_HOST: '' });
    expect(env.API_PORT).toBe(4000);
    expect(env.API_HOST).toBe('127.0.0.1');
  });

  it('ignores unrelated variables', () => {
    const env = validateEnv({ ...required, UNRELATED: 'x' });
    expect(env).not.toHaveProperty('UNRELATED');
  });

  it('requires DATABASE_URL', () => {
    expect(problemsFor({ ...required, DATABASE_URL: undefined })).toEqual([
      expect.stringMatching(/^DATABASE_URL: /),
    ]);
  });

  it('rejects non-postgres database URLs', () => {
    expect(problemsFor({ ...required, DATABASE_URL: 'mysql://user:pw@localhost/db' })).toEqual([
      expect.stringMatching(/^DATABASE_URL: /),
    ]);
  });

  it.each([['0'], ['65536'], ['80.5'], ['not-a-port']])('rejects API_PORT=%s', (port) => {
    expect(problemsFor({ ...required, API_PORT: port })).toEqual([
      expect.stringMatching(/^API_PORT: /),
    ]);
  });

  it('rejects unknown NODE_ENV and LOG_LEVEL values', () => {
    const problems = problemsFor({
      ...required,
      NODE_ENV: 'staging',
      LOG_LEVEL: 'loud',
    });
    expect(problems).toHaveLength(2);
    expect(problems.join('\n')).toMatch(/NODE_ENV/);
    expect(problems.join('\n')).toMatch(/LOG_LEVEL/);
  });

  it('never includes rejected values in the error message', () => {
    const secretish = 'mysql://admin:do-not-print-me@db.internal/prod';
    try {
      validateEnv({ ...required, DATABASE_URL: secretish, API_PORT: 'do-not-print-port' });
      expect.unreachable();
    } catch (error) {
      const message = (error as Error).message;
      expect(message).not.toContain('do-not-print-me');
      expect(message).not.toContain('do-not-print-port');
      expect(message).toContain('DATABASE_URL');
      expect(message).toContain('API_PORT');
    }
  });
});
