import { InvalidEnvironmentError, validateEnv } from './env.js';

const validUrl = 'postgresql://ruvee:local-only@127.0.0.1:5432/ruvee';

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
  it('applies safe defaults when only DATABASE_URL is set', () => {
    expect(validateEnv({ DATABASE_URL: validUrl })).toEqual({
      NODE_ENV: 'development',
      API_HOST: '127.0.0.1',
      API_PORT: 4000,
      DATABASE_URL: validUrl,
      LOG_LEVEL: 'info',
      READINESS_DB_TIMEOUT_MS: 2000,
    });
  });

  it('coerces numeric values from strings', () => {
    const env = validateEnv({ DATABASE_URL: validUrl, API_PORT: '8080' });
    expect(env.API_PORT).toBe(8080);
  });

  it('treats empty strings as unset so defaults still apply', () => {
    const env = validateEnv({ DATABASE_URL: validUrl, API_PORT: '', API_HOST: '' });
    expect(env.API_PORT).toBe(4000);
    expect(env.API_HOST).toBe('127.0.0.1');
  });

  it('ignores unrelated variables', () => {
    const env = validateEnv({ DATABASE_URL: validUrl, UNRELATED: 'x' });
    expect(env).not.toHaveProperty('UNRELATED');
  });

  it('requires DATABASE_URL', () => {
    expect(problemsFor({})).toEqual([expect.stringMatching(/^DATABASE_URL: /)]);
  });

  it('rejects non-postgres database URLs', () => {
    expect(problemsFor({ DATABASE_URL: 'mysql://user:pw@localhost/db' })).toEqual([
      expect.stringMatching(/^DATABASE_URL: /),
    ]);
  });

  it.each([['0'], ['65536'], ['80.5'], ['not-a-port']])('rejects API_PORT=%s', (port) => {
    expect(problemsFor({ DATABASE_URL: validUrl, API_PORT: port })).toEqual([
      expect.stringMatching(/^API_PORT: /),
    ]);
  });

  it('rejects unknown NODE_ENV and LOG_LEVEL values', () => {
    const problems = problemsFor({
      DATABASE_URL: validUrl,
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
      validateEnv({ DATABASE_URL: secretish, API_PORT: 'do-not-print-port' });
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
