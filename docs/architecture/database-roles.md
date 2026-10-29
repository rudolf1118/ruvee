# Database roles

Status: **implemented for development (2026-10-29)**. Follow-up review F-25: the owner approved
separating the API's runtime role from the owner and administrator roles, for development.
Synthetic data only; nothing is deployed, and D-19 (independent review) is open. Setup and
migration steps: [the database roles guide](../guides/database-roles.md).

## 1. Why

Before this change the API connected as the one administrator role: it owned `ruvee_control`
(the restore guard and the reopening codes), held `CREATEROLE`, and owned every table. An SQL
injection or a leaked `DATABASE_URL` therefore had the restore authority and could change the
schema. Now the API connects as a **runtime role** that owns nothing. It can create nothing, and
it reaches restore state only through five narrow functions.

## 2. What each operation needs

Every database access path in `apps/api`, and the role it now runs as.

| Operation                                                  | Code                                                                                                    | Role                         | Needs                                                                                                                                                                                                                                                                                                               |
| ---------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- | ---------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Normal API requests                                        | `auth`, `account`, `sessions`, `pairing`, `recovery`, `vault`, `security-events`                        | runtime                      | The table privileges in `RUNTIME_GRANTS` (§3). Row locks (`SELECT … FOR UPDATE`) on `sessions`, `devices` and `vaults`, which it may update anyway, and on `accounts`, through an UPDATE grant on the one column `created_at`. Advisory locks for registration (`pg_advisory_xact_lock`, open to PUBLIC by default) |
| Maintenance-state reads                                    | `MaintenanceService`                                                                                    | runtime                      | `USAGE` on `ruvee_control`; `SELECT (id, origin)` on `installation`; `SELECT (id, state)` on `restore_guard`. Catalog lookups (`to_regnamespace`, `to_regclass`)                                                                                                                                                    |
| Reopening: code check, failure count, consumption, session | `ReopenService`, `SessionService.authenticateReopen`                                                    | runtime                      | `EXECUTE` on `reopen_code_find`, `reopen_code_failed`, `reopen_code_consume` and `reopen_session_via`. Inserting the reopen session and, on the kit path, a pending device, as for any login                                                                                                                        |
| Reopening completion                                       | `ReopenService.complete`                                                                                | runtime                      | `EXECUTE` on `reopen_complete`, plus its own updates of `account_keys`, `opaque_credentials`, `sessions` and `devices` in the same transaction                                                                                                                                                                      |
| Instance lock and health                                   | `InstanceLockService`, `DatabaseHealthService`                                                          | runtime                      | `CONNECT`; `pg_try_advisory_lock` and `pg_locks`, open to everyone by default; `SELECT 1`                                                                                                                                                                                                                           |
| Runtime cleanup                                            | Inline, no scheduled job: proof nonces (F-24), expired pairings, throttle resets                        | runtime                      | `DELETE` on `proof_nonces`, `pairings` and `auth_throttle` only                                                                                                                                                                                                                                                     |
| Migrations                                                 | `prisma migrate deploy`                                                                                 | **owner**                    | Owns `public` and everything in it, `_prisma_migrations` included                                                                                                                                                                                                                                                   |
| Backup                                                     | `ruvee-admin backup` (`pg_dump`, which skips `ruvee_control`)                                           | **operator**                 | Read access to every table in `public`, `_prisma_migrations` included, inherited from the owner                                                                                                                                                                                                                     |
| Restore: PREPARE                                           | `restoreVerified`                                                                                       | operator                     | Owns the database (it creates `ruvee_control`); grants the runtime role `CONNECT` and read access to the gate                                                                                                                                                                                                       |
| Restore: LOAD                                              | `pg_restore`                                                                                            | **loader** (one per restore) | `CONNECT`; `USAGE, CREATE` on `public` only. Made with `CREATEROLE` and dropped afterwards, unchanged from §3.2b                                                                                                                                                                                                    |
| Restore: object check, MIGRATE, APPLY POLICY               | `restoredObjectProblems`, `prisma migrate deploy`, the policy transaction                               | operator                     | Takes over the loader's objects, runs the migrations, then hands every object in `public` to the owner (`normalizeOwnership`) and applies the runtime list and the functions (`applyRuntimeGrants`)                                                                                                                 |
| Local administrator commands                               | `init`, `grant-runtime`, `bootstrap-token`, `restore-review`, `restore-complete`, `restore-reopen-code` | operator                     | The control schema (owner); data access in `public` through the owner role                                                                                                                                                                                                                                          |
| OPAQUE setup                                               | `ruvee-admin opaque-setup`                                                                              | —                            | No database                                                                                                                                                                                                                                                                                                         |

## 3. The roles

| Role          | Attributes                                                                         | Membership                                 | Owns                                                    | May do                                                                                                                                                                                                                                                                                           | Credentials                                                                                                     |
| ------------- | ---------------------------------------------------------------------------------- | ------------------------------------------ | ------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------- |
| **runtime**   | `LOGIN NOINHERIT`, none of SUPERUSER, CREATEDB, CREATEROLE, REPLICATION, BYPASSRLS | none                                       | nothing                                                 | `CONNECT`; `USAGE` on `public` and `ruvee_control`; exactly `RUNTIME_GRANTS` and `RUNTIME_CONTROL_GRANTS` (`apps/api/src/database/runtime-privileges.ts`); `EXECUTE` on the five reopening functions. No `CREATE` anywhere, no `TEMPORARY`, no `TRUNCATE`, `REFERENCES`, `TRIGGER` or `MAINTAIN` | `DATABASE_URL` of the API process, and nothing else                                                             |
| **owner**     | `LOGIN NOINHERIT`, no attributes                                                   | none                                       | the `public` schema, every table, index and enum in it  | DDL in `public` (migrations)                                                                                                                                                                                                                                                                     | Only in the environment of a migration command (`DATABASE_URL=<owner> prisma migrate deploy`)                   |
| **operator**  | `LOGIN INHERIT CREATEROLE`, no other attributes                                    | member of owner (`INHERIT TRUE, SET TRUE`) | the database; `ruvee_control`, its tables and functions | Everything the owner may do; create and drop the restore's loader role (PostgreSQL 16 and later limit `CREATEROLE` to roles it made); grant the runtime role its list                                                                                                                            | `RUVEE_ADMIN_DATABASE_URL` and `RESTORE_DATABASE_URL` of `ruvee-admin` on the host; never the API's environment |
| **loader**    | `LOGIN NOINHERIT`, no attributes, connection limit 2                               | none                                       | what the dump creates, until it is taken over           | `CONNECT`; `USAGE, CREATE` on `public`                                                                                                                                                                                                                                                           | Random, used once by `pg_restore`, never shown                                                                  |
| cluster admin | superuser                                                                          | —                                          | —                                                       | Creates the three roles and each database once (the guide)                                                                                                                                                                                                                                       | Not used by Ruvee at all                                                                                        |

`ruvee-admin` refuses to run `init` or `restore` as a superuser, or as the runtime role. A
restored dump's SQL runs with the rights of the role that loads it and of every role that later
owns it (§3.2b of [backup-restore.md](backup-restore.md)). It also refuses a runtime role that
has any attribute or membership, or that owns anything in the database.

## 4. Reopening without UPDATE on the restore state

The API must complete a reopening: one transaction replaces the password and Recovery Kit and
moves the guard from `reopening` to `open` (§3.13 of backup-restore.md). Instead of UPDATE on
`restore_guard` and `reopen_codes`, the runtime role gets five functions in `ruvee_control`
(`apps/api/src/admin/reopen-functions.ts`). Each checks the persisted state it depends on and
makes exactly one change:

| Function                                  | Checks                                                                                                                                                                                              | Changes                                                    |
| ----------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------- |
| `reopen_code_find(hash)`                  | 32-byte hash; the guard is `reopening`; the code is of this restore, unrevoked, unconsumed, unexpired, with fewer than 5 failures                                                                   | nothing (returns its id, restore and account)              |
| `reopen_code_failed(code)`                | the code is usable and of the restore in `reopening`                                                                                                                                                | +1 failure; the fifth revokes it                           |
| `reopen_code_consume(code, session, via)` | under the guard's row lock: `reopening`; the code is of this restore; the session is a live, unrevoked `reopen` session of the code's account, linked to no code; `via` is `password` or `recovery` | links the code to the session (once: a conditional UPDATE) |
| `reopen_session_via(session, account)`    | the guard is `reopening`; the session's code is unrevoked and of that account                                                                                                                       | nothing (returns the path)                                 |
| `reopen_complete(session)`                | under the guard's row lock: `reopening`; the session is live and of kind `reopen`, linked to a consumed, unrevoked code of this restore and the same account                                        | revokes every code; guard → `open`; returns the restore id |

**Atomicity.** `reopen_complete` runs inside the API's completion transaction, before the
credential updates. If anything later in that transaction fails (a stale row version, a failed
event insert), PostgreSQL rolls the guard and the codes back with it. The guard row's lock is
taken first, as before, so a host's `restore-reopen-code` either commits first, and the
completion sees the revoked code, or waits for the completion (R13).

**Hardening.**

- `SECURITY DEFINER`, owned by the operator.
- `SET search_path = pg_catalog, pg_temp`, so no other schema or temporary object can stand in
  for a name. Every table is written with its schema anyway (`ruvee_control.…`, `public.…`), and
  `now()` is called as `pg_catalog.now()`.
- `EXECUTE` is revoked from PUBLIC and granted to the runtime role only.
- Arguments are checked for NULL and form, and the failure limit is a constant in the body.
- The runtime role can neither replace the functions (it does not own them) nor create objects
  in the schema.
- They exist only where a restore guard exists (APPLY POLICY, or `grant-runtime` on an older
  restored database). `restoredObjectProblems` runs before APPLY POLICY, so it never sees them.

## 5. What a compromised runtime role can still do

Someone who can run SQL as the runtime role (an SQL injection, a stolen `DATABASE_URL`) still
has every privilege in §3. Concretely:

- **Read** every row the API reads: ciphertext, wraps, OPAQUE records (offline password guessing
  together with the OPAQUE setup file, which is not in the database), hashes of sessions, refresh
  tokens and setup tokens, devices, events. None of it decrypts a vault (INV-18).
- **Write as the API does.** It can insert a session row and so act as any account and device
  through the API. It can activate a device, replace wraps and keysets (clients check them
  against the account's verification key and their own checkpoints), revoke sessions, delete
  throttle rows and so reset login limits, delete pairings and nonces, add or change items and
  commits (clients verify the manifest chain), and insert false security events.
- **Use a code it has.** A reopening completes for whoever holds a usable code, and the API
  process sees the code in the request body. A compromised API **process** can therefore consume
  the code during a real reopening and complete it with credentials of its choosing. The database
  cannot check OPAQUE, so the functions cannot prevent that.

It **cannot**:

- open a restored installation without a usable code: it cannot read the codes or their hashes,
  and a code id is only found by hashing the code;
- move the guard any other way, or touch `installation`;
- issue, extend, un-revoke or reset a code;
- change the schema, or create a function, trigger, view or temporary table (no persistence
  through objects);
- replace, take over or drop the control schema or its functions;
- grant itself or anyone a privilege, create a role, or `SET ROLE` to the owner or operator;
- delete accounts, devices, sessions, keys, items or commits, or truncate anything;
- read or write files on the host (`COPY … PROGRAM`), or set superuser-only settings.

This is a boundary between the runtime role and the other roles, inside one PostgreSQL cluster.
It does not protect against:

- the operator's or the owner's credentials;
- a compromised host, where the operator credentials, `.env` and the OPAQUE setup file are;
- a PostgreSQL vulnerability that escalates privileges;
- a compromised API process during a reopening, as above.

## 6. Future migrations

- A migration runs as the owner, so new tables are the owner's, and the runtime role gets
  nothing on them. `grant-runtime` refuses to run while any table is missing from
  `RUNTIME_GRANTS`, and a unit test requires `RUNTIME_GRANTS` to cover exactly the backup
  inventory.
- A unit test refuses any migration that contains `GRANT`, `REVOKE`, `OWNER TO`, a role
  statement, `ALTER DEFAULT PRIVILEGES`, `SECURITY DEFINER`, `SET ROLE`, a function or an
  extension.
- `grant-runtime` revokes everything the runtime role held in the database before it grants the
  list, then checks the result with `privilegeProblems`. That check compares every table, column,
  sequence, function, schema and database privilege, ownership, membership and attribute against
  the list.
- The API runs the same check once, as itself. In production, any privilege **beyond** the
  list closes every route but health (`503 server_unavailable`, logged), until a restart. In
  development and tests it logs a warning. A privilege the role **lacks** is not counted there:
  it fails closed where it is used, and a database before `init` or during a restore is meant to
  lack some. Such an API answers `maintenance` and opens once the grants arrive, without a
  restart.
- If the API cannot read the gate (a grant missing after a restore or a migration), the gate
  answers `maintenance`, never an error that could be read as open.

## 7. Tests

- `apps/api/test/review/f25-roles.int-spec.ts` uses real roles made with the guide's statements.
  It covers:
  - the exact privileges, owners and function hardening;
  - 37 forbidden statements as the runtime role (33 on a restored database, 4 on a fresh one), all `42501`;
  - every function refusal and the rollback of an authorized transition;
  - closed answers when a grant is missing;
  - administrative steps refusing a superuser and the runtime role;
  - backup and migration failing as the runtime role;
  - an extra grant detected, closing production, and undone;
  - in production, an API started before `init` answering `maintenance`, then serving after it;
  - the move of an existing database (the guide's statements) ending with exactly the list.
- `apps/api/test/database-roles.spec.ts` checks:
  - the list against the inventory;
  - the migrations against privilege statements;
  - the functions' `search_path` and qualified names;
  - that `ruvee-admin` never reads the API's `DATABASE_URL`.
- The integration suite runs the API as each database's own runtime role
  (`test/support/temp-database.ts`), and the restore and reopening suites run `ruvee-admin` as the
  operator. The browser stacks (`apps/api/scripts/e2e-roles.mjs`) do the same.
- Negative control: the reopening code from before this change (direct UPDATEs on
  `ruvee_control`) fails all 19 reopening tests under the runtime role.
