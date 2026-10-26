import type pg from 'pg';
import { CONTROL_SCHEMA, GUARD_TABLE, createControlSchema } from './restore-control.js';

/**
 * The installation's lifecycle (predeployment-review R14). The API serves a database only when
 * its control schema says so, never because something is missing:
 *
 * - no `ruvee_control` schema: **uninitialized**, closed;
 * - `ruvee_control.installation` with `origin = 'fresh'` and no restore guard: a fresh
 *   installation, set up by `ruvee-admin init`, open;
 * - a restore guard (created by PREPARE of `ruvee-admin restore`): its state decides, and a
 *   guard table without its row is an interrupted restore, closed;
 * - anything else (a schema with neither table): closed.
 *
 * Both tables are owned by the admin role and never part of a backup.
 */
export const INSTALLATION_TABLE = `${CONTROL_SCHEMA}.installation`;

export class InstallationError extends Error {}

/**
 * `ruvee-admin init`, as the admin role: marks a database that was never restored as a fresh
 * installation. Refuses a database that already has a control schema (initialized, or restored:
 * a restored database is opened only by its reopening).
 */
export async function initInstallation(c: pg.Client): Promise<void> {
  const { rows } = await c.query<{ schema: string | null }>(
    `SELECT to_regnamespace('${CONTROL_SCHEMA}')::text AS schema`,
  );
  if (rows[0]?.schema)
    throw new InstallationError(
      'this database already has a control schema: it is initialized, or it was restored and opens only by its reopening',
    );
  await c.query('BEGIN');
  try {
    await createControlSchema(c);
    await c.query(`CREATE TABLE ${INSTALLATION_TABLE} (
      id smallint PRIMARY KEY CHECK (id = 1),
      origin text NOT NULL CHECK (origin = 'fresh'),
      initialized_at timestamptz NOT NULL DEFAULT now()
    )`);
    await c.query(`INSERT INTO ${INSTALLATION_TABLE} (id, origin) VALUES (1, 'fresh')`);
    await c.query('COMMIT');
  } catch (error) {
    await c.query('ROLLBACK');
    throw error;
  }
}

/** For the operator: what the lifecycle says about this database. */
export async function installationState(
  c: pg.Client,
): Promise<'uninitialized' | 'fresh' | 'restored' | 'incomplete'> {
  const { rows } = await c.query<{
    schema: string | null;
    guard: string | null;
    inst: string | null;
  }>(
    `SELECT to_regnamespace('${CONTROL_SCHEMA}')::text AS schema,
            to_regclass('${GUARD_TABLE}')::text AS guard,
            to_regclass('${INSTALLATION_TABLE}')::text AS inst`,
  );
  const r = rows[0];
  if (!r?.schema) return 'uninitialized';
  if (r.guard) return 'restored';
  return r.inst ? 'fresh' : 'incomplete';
}
