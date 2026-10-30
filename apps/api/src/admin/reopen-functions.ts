import type pg from 'pg';
import { REOPEN_MAX_FAILURES } from '../reopen/reopen-codes.js';

/**
 * The only way the runtime role changes restore state (follow-up review F-25; database-roles.md
 * §4). The API completes a reopening, so it must move the guard from `reopening` to `open`; it
 * gets no UPDATE on the guard or the codes for that. Instead, five functions in `ruvee_control`,
 * owned by the operator role and run with its rights (SECURITY DEFINER), each check the persisted
 * state they depend on and make one permitted change:
 *
 * - `reopen_code_find(hash)`: the usable code with this SHA-256, while reopening. Read-only;
 *   never reveals a code's hash, and a hash is useless without the code.
 * - `reopen_code_failed(code)`: counts a failed attempt on a usable code; the fifth revokes it.
 * - `reopen_code_consume(code, session, via)`: while reopening, links a usable code of this
 *   restore to a live, unlinked reopen session of the code's account, under the guard's lock.
 * - `reopen_session_via(session, account)`: the path of a reopen session still linked to an
 *   unrevoked code, while reopening. Read-only.
 * - `reopen_complete(session)`: under the guard's lock, only for a live reopen session linked to
 *   an unrevoked, consumed code of this restore: revokes every code and moves the guard to
 *   `open`. It runs inside the API's completion transaction, so the new password, Recovery Kit
 *   and session commit with it or not at all.
 *
 * Hardening: `SET search_path = pg_catalog, pg_temp` (no object of another schema, and no
 * temporary object, can stand in for a name; every table is schema-qualified anyway); EXECUTE is
 * revoked from PUBLIC and granted to the runtime role only; arguments are checked for NULL and
 * form; the maximum of failures is a constant in the body, not an argument. Nothing in them reads
 * a value the caller could choose beyond the identifiers it passes.
 *
 * They are created only where a restore guard and the code table exist (APPLY POLICY, or
 * `ruvee-admin grant-runtime` on an older restored database); a fresh installation has none.
 */

const DEFINER = `SECURITY DEFINER SET search_path = pg_catalog, pg_temp`;

export const REOPEN_FUNCTIONS_SQL = [
  `CREATE OR REPLACE FUNCTION ruvee_control.reopen_code_find(p_code_hash bytea)
  RETURNS TABLE (code_id uuid, restore_id uuid, account_id uuid)
  LANGUAGE sql STABLE ${DEFINER} AS $$
    SELECT c.id, c.restore_id, c.account_id
    FROM ruvee_control.reopen_codes c
    JOIN ruvee_control.restore_guard g
      ON g.id = 1 AND g.restore_id = c.restore_id AND g.state = 'reopening'
    WHERE p_code_hash IS NOT NULL AND octet_length(p_code_hash) = 32
      AND c.code_hash = p_code_hash AND c.revoked_at IS NULL AND c.consumed_at IS NULL
      AND c.expires_at > pg_catalog.now() AND c.failed_attempts < ${String(REOPEN_MAX_FAILURES)}
  $$`,
  `CREATE OR REPLACE FUNCTION ruvee_control.reopen_code_failed(p_code_id uuid)
  RETURNS void
  LANGUAGE sql VOLATILE ${DEFINER} AS $$
    UPDATE ruvee_control.reopen_codes c
    SET failed_attempts = c.failed_attempts + 1,
        revoked_at = CASE WHEN c.failed_attempts + 1 >= ${String(REOPEN_MAX_FAILURES)}
                          THEN pg_catalog.now() END
    WHERE c.id = p_code_id AND c.revoked_at IS NULL AND c.consumed_at IS NULL
      AND EXISTS (SELECT 1 FROM ruvee_control.restore_guard g
                  WHERE g.id = 1 AND g.restore_id = c.restore_id AND g.state = 'reopening')
  $$`,
  `CREATE OR REPLACE FUNCTION ruvee_control.reopen_code_consume(
    p_code_id uuid, p_session_id uuid, p_via text)
  RETURNS boolean
  LANGUAGE plpgsql VOLATILE ${DEFINER} AS $$
  DECLARE
    v_restore uuid;
    v_account uuid;
    v_changed integer;
  BEGIN
    IF p_code_id IS NULL OR p_session_id IS NULL OR p_via IS NULL
       OR p_via NOT IN ('password', 'recovery') THEN
      RETURN false;
    END IF;
    SELECT g.restore_id INTO v_restore FROM ruvee_control.restore_guard g
      WHERE g.id = 1 AND g.state = 'reopening' FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    SELECT c.account_id INTO v_account FROM ruvee_control.reopen_codes c
      WHERE c.id = p_code_id AND c.restore_id = v_restore FOR UPDATE;
    IF NOT FOUND THEN RETURN false; END IF;
    PERFORM 1 FROM public.sessions s
      WHERE s.id = p_session_id AND s.kind = 'reopen' AND s.account_id = v_account
        AND s.revoked_at IS NULL AND s.absolute_expires_at > pg_catalog.now()
        AND NOT EXISTS (SELECT 1 FROM ruvee_control.reopen_codes o WHERE o.session_id = s.id)
      FOR UPDATE OF s;
    IF NOT FOUND THEN RETURN false; END IF;
    UPDATE ruvee_control.reopen_codes c
      SET consumed_at = pg_catalog.now(), session_id = p_session_id, via = p_via
      WHERE c.id = p_code_id AND c.consumed_at IS NULL AND c.revoked_at IS NULL
        AND c.expires_at > pg_catalog.now()
        AND c.failed_attempts < ${String(REOPEN_MAX_FAILURES)};
    GET DIAGNOSTICS v_changed = ROW_COUNT;
    RETURN v_changed = 1;
  END
  $$`,
  `CREATE OR REPLACE FUNCTION ruvee_control.reopen_session_via(
    p_session_id uuid, p_account_id uuid)
  RETURNS text
  LANGUAGE sql STABLE ${DEFINER} AS $$
    SELECT c.via FROM ruvee_control.reopen_codes c
    JOIN ruvee_control.restore_guard g
      ON g.id = 1 AND g.restore_id = c.restore_id AND g.state = 'reopening'
    WHERE c.session_id = p_session_id AND c.account_id = p_account_id
      AND c.revoked_at IS NULL
  $$`,
  `CREATE OR REPLACE FUNCTION ruvee_control.reopen_complete(p_session_id uuid)
  RETURNS uuid
  LANGUAGE plpgsql VOLATILE ${DEFINER} AS $$
  DECLARE
    v_restore uuid;
    v_account uuid;
  BEGIN
    IF p_session_id IS NULL THEN RETURN NULL; END IF;
    -- The guard row first: ruvee-admin restore-reopen-code locks it too (review R13).
    SELECT g.restore_id INTO v_restore FROM ruvee_control.restore_guard g
      WHERE g.id = 1 AND g.state = 'reopening' FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    SELECT c.account_id INTO v_account FROM ruvee_control.reopen_codes c
      WHERE c.session_id = p_session_id AND c.restore_id = v_restore
        AND c.consumed_at IS NOT NULL AND c.revoked_at IS NULL
      FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    PERFORM 1 FROM public.sessions s
      WHERE s.id = p_session_id AND s.kind = 'reopen' AND s.account_id = v_account
        AND s.revoked_at IS NULL AND s.absolute_expires_at > pg_catalog.now()
      FOR UPDATE;
    IF NOT FOUND THEN RETURN NULL; END IF;
    UPDATE ruvee_control.reopen_codes SET revoked_at = pg_catalog.now() WHERE revoked_at IS NULL;
    UPDATE ruvee_control.restore_guard SET state = 'open', reopened_at = pg_catalog.now()
      WHERE id = 1 AND state = 'reopening';
    RETURN v_restore;
  END
  $$`,
];

const SIGNATURES = [
  'ruvee_control.reopen_code_find(bytea)',
  'ruvee_control.reopen_code_failed(uuid)',
  'ruvee_control.reopen_code_consume(uuid, uuid, text)',
  'ruvee_control.reopen_session_via(uuid, uuid)',
  'ruvee_control.reopen_complete(uuid)',
];

const ident = (name: string) => `"${name.replace(/"/g, '""')}"`;

/**
 * As the operator role, inside the caller's transaction: (re)creates the functions, owned by the
 * current role, and lets only `runtimeRole` execute them.
 */
export async function installReopenFunctions(c: pg.Client, runtimeRole: string): Promise<void> {
  for (const sql of REOPEN_FUNCTIONS_SQL) await c.query(sql);
  for (const signature of SIGNATURES) {
    await c.query(`REVOKE ALL ON FUNCTION ${signature} FROM PUBLIC`);
    await c.query(`GRANT EXECUTE ON FUNCTION ${signature} TO ${ident(runtimeRole)}`);
  }
}
