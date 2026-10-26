import { z } from 'zod';

const emptyToUndefined = (value: unknown) => (value === '' ? undefined : value);

function isOrigin(value: string): boolean {
  try {
    return new URL(value).origin === value;
  } catch {
    return false;
  }
}

const origin = z.url({ protocol: /^https?$/ }).refine(isOrigin, {
  error: 'Must be an origin: scheme, host and optional port, with no path or trailing slash',
});

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
  /** Path of the OPAQUE server setup file (a Docker secret in deployment). Never in the database. */
  OPAQUE_SERVER_SETUP_FILE: z.string().min(1),
  /** The single origin that serves the web app and the API; state-changing requests must match. */
  PUBLIC_ORIGIN: origin,
  /**
   * `false` only for loopback HTTP development: the cookie loses `Secure` and the `__Host-`
   * prefix. Refused when NODE_ENV is production.
   */
  SESSION_COOKIE_SECURE: z.enum(['true', 'false']).default('true'),
  /** Address of the reverse proxy whose X-Forwarded-For is trusted for the client IP. */
  TRUSTED_PROXY_ADDRESS: z.ipv4().or(z.ipv6()).optional(),
  /**
   * Comma-separated `chrome-extension://<id>` origins allowed to call the unauthenticated token
   * endpoints (login, refresh) without a cookie (extension-design.md §2). Empty: none.
   */
  /**
   * The age X25519 recipient (public key) `ruvee-admin backup` encrypts to (D-29). Only the public
   * key is ever configured; the identity that decrypts is held offline (backup-restore.md §3.2).
   */
  BACKUP_AGE_RECIPIENT: z
    .string()
    .regex(/^age1[02-9ac-hj-np-z]{58}$/, { error: 'Must be an age X25519 recipient (age1…)' })
    .optional(),
  EXTENSION_ORIGINS: z.preprocess(
    emptyToUndefined,
    z
      .string()
      .regex(/^chrome-extension:\/\/[a-p]{32}(,chrome-extension:\/\/[a-p]{32})*$/, {
        error: 'Must be comma-separated chrome-extension://<32 letters a-p> origins',
      })
      .optional(),
  ),
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
  const result = envSchema
    .refine((env) => !(env.NODE_ENV === 'production' && env.SESSION_COOKIE_SECURE === 'false'), {
      error: 'Must be true in production',
      path: ['SESSION_COOKIE_SECURE'],
    })
    .safeParse(input);
  if (!result.success) {
    const problems = result.error.issues.map(
      (issue) => `${issue.path.join('.') || '(root)'}: ${issue.message}`,
    );
    throw new InvalidEnvironmentError(problems);
  }
  return result.data;
}
