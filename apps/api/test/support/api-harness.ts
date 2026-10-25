import { randomUUID } from 'node:crypto';
import { Writable } from 'node:stream';
import type { NestExpressApplication } from '@nestjs/platform-express';
import request from 'supertest';
import { registerStartResponseSchema } from '@ruvee/contracts';
import { randomToken, sha256 } from '../../src/common/secrets.js';
import {
  finishRegistration,
  startRegistration,
  type SyntheticAccount,
} from './synthetic-client.js';
import { createTempDatabase, migrate, query, type TempDatabase } from './temp-database.js';

export const ORIGIN = 'http://127.0.0.1:3100';

/** Headers every state-changing cookie request needs (authentication.md §6). */
export const WRITE_HEADERS = { Origin: ORIGIN, 'X-Ruvee-Request': '1' } as const;

export interface Harness {
  readonly app: NestExpressApplication;
  readonly db: TempDatabase;
  readonly logs: string[];
  /** Every request body this harness sent, for the INV-01 capture checks. */
  readonly sent: string[];
  http(): ReturnType<typeof request>;
  post(path: string, body: unknown, cookie?: string): request.Test;
  get(path: string, cookie?: string): request.Test;
  bootstrapToken(): Promise<string>;
  close(): Promise<void>;
}

/**
 * Starts the full application against a fresh migrated database that this harness created.
 * The configuration is read when the app module is imported, so DATABASE_URL is set first.
 */
export async function startHarness(): Promise<Harness> {
  const db = await createTempDatabase();
  migrate(db.url);
  process.env.DATABASE_URL = db.url;
  const logs: string[] = [];
  const destination = new Writable({
    write(chunk: Buffer, _encoding, callback) {
      logs.push(...chunk.toString('utf8').split('\n').filter(Boolean));
      callback();
    },
  });
  const { createTestApp } = await import('../create-test-app.js');
  const { LOG_DESTINATION } = await import('../../src/logging/logger-options.js');
  const app = await createTestApp({
    override: (builder) => builder.overrideProvider(LOG_DESTINATION).useValue(destination),
  });
  const sent: string[] = [];
  const http = () => request(app.getHttpServer());
  return {
    app,
    db,
    logs,
    sent,
    http,
    post(path, body, cookie) {
      sent.push(JSON.stringify(body));
      const req = http()
        .post(path)
        .set(WRITE_HEADERS)
        .send(body as object);
      return cookie ? req.set('Cookie', cookie) : req;
    },
    get(path, cookie) {
      const req = http().get(path);
      return cookie ? req.set('Cookie', cookie) : req;
    },
    async bootstrapToken() {
      // What `ruvee-admin bootstrap-token` stores: only the hash, valid for 60 minutes.
      const token = randomToken();
      await query(
        db.url,
        `INSERT INTO bootstrap_tokens (id, token_hash, expires_at) VALUES ($1, $2, now() + interval '60 minutes')`,
        [randomUUID(), Buffer.from(sha256(Buffer.from(token, 'base64url')))],
      );
      return token;
    },
    async close() {
      await app.close();
      await db.drop();
    },
  };
}

/** The `name=value` part of the session cookie in a response, for sending it back. */
export function sessionCookie(res: request.Response): string {
  const header = res.headers['set-cookie'] as unknown as string[] | undefined;
  const cookie = header?.find((c) => c.startsWith('__Host-ruvee_session='));
  if (!cookie) throw new Error('no session cookie in the response');
  return cookie.split(';')[0] ?? '';
}

/** Registers the synthetic account through the real endpoints and returns its session cookie. */
export async function registerAccount(h: Harness, account: SyntheticAccount): Promise<string> {
  const token = await h.bootstrapToken();
  const reg = startRegistration();
  const start = await h
    .post('/api/v1/auth/register/start', {
      bootstrapToken: token,
      username: account.username,
      registrationRequest: reg.registrationRequest,
    })
    .expect(200);
  const record = finishRegistration(
    reg.clientRegistrationState,
    registerStartResponseSchema.parse(start.body).registrationResponse,
  );
  const res = await h
    .post('/api/v1/auth/register/finish', account.finish(record, token))
    .expect(201);
  return sessionCookie(res);
}
