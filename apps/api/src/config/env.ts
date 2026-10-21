import { z } from 'zod';

const emptyToUndefined = (value: unknown) => (value === '' ? undefined : value);

export const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'test', 'production']).default('development'),
  API_HOST: z.string().min(1).default('127.0.0.1'),
  API_PORT: z.coerce.number().int().min(1).max(65_535).default(4000),
  DATABASE_URL: z.url({
    protocol: /^postgres(ql)?$/,
    error: 'Must be a postgres:// or postgresql:// connection URL',
  }),
  LOG_LEVEL: z.enum(['fatal', 'error', 'warn', 'info', 'debug', 'trace', 'silent']).default('info'),
  READINESS_DB_TIMEOUT_MS: z.coerce.number().int().min(100).max(30_000).default(2000),
});

export type Env = z.infer<typeof envSchema>;

export class InvalidEnvironmentError extends Error {
  constructor(readonly problems: string[]) {
    super(`Invalid environment configuration:\n${problems.map((p) => `  - ${p}`).join('\n')}`);
    this.name = 'InvalidEnvironmentError';
  }
}

/**
 * Validates raw environment variables. Error messages name the offending
 * variable but never echo its value, because values may hold credentials.
 */
export function validateEnv(raw: Record<string, unknown>): Env {
  const input = Object.fromEntries(
    Object.keys(envSchema.shape).map((key) => [key, emptyToUndefined(raw[key])]),
  );
  const result = envSchema.safeParse(input);
  if (!result.success) {
    const problems = result.error.issues.map(
      (issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`,
    );
    throw new InvalidEnvironmentError(problems);
  }
  return result.data;
}
