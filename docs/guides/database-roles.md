# Database roles: setup and migration

How to give Ruvee's API a least-privilege database role (follow-up review F-25). The design and
the privilege matrix are in [database-roles.md](../architecture/database-roles.md).

> **Development only.** Synthetic data only; nothing here is deployed, and D-19 (independent
> review) is open. These are instructions: nothing in this repository applies them to an
> existing database or changes your `.env`. Try them on a database you can throw away first.

The names below are suggestions (`ruvee_owner`, `ruvee_operator`, `ruvee_runtime`, database
`ruvee`). The SQL is exactly what `roleSetupStatements`, `databaseSetupStatements` and
`existingDatabaseStatements` in `apps/api/src/admin/database-roles.ts` produce. The tests and the
browser stacks run those same functions.

## 1. Who holds which credentials

| Variable                   | Role             | Where it lives                                                       |
| -------------------------- | ---------------- | -------------------------------------------------------------------- |
| `DATABASE_URL`             | `ruvee_runtime`  | The API's environment (`.env`). Nothing else.                        |
| (migration only)           | `ruvee_owner`    | Typed into a migration command's environment; never in `.env`        |
| `RUVEE_ADMIN_DATABASE_URL` | `ruvee_operator` | `ruvee-admin`'s environment on the host; never the API's             |
| `RESTORE_DATABASE_URL`     | `ruvee_operator` | `ruvee-admin restore*`, pointing at the restore target               |
| `RUVEE_RUNTIME_ROLE`       | (a name)         | `ruvee-admin init`, `grant-runtime` and `restore`: the role to grant |

All URLs are plain `postgresql://user:password@host:port/database` URLs, with no query
parameters. `ruvee-admin` never reads `DATABASE_URL`.

## 2. A new installation

As the cluster administrator (a superuser, for example the `POSTGRES_USER` of the Docker
container), once per cluster:

```sql
CREATE ROLE "ruvee_owner" LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS NOCREATEROLE NOINHERIT;
CREATE ROLE "ruvee_operator" LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS CREATEROLE INHERIT;
GRANT "ruvee_owner" TO "ruvee_operator" WITH INHERIT TRUE, SET TRUE;
CREATE ROLE "ruvee_runtime" LOGIN NOSUPERUSER NOCREATEDB NOREPLICATION NOBYPASSRLS NOCREATEROLE NOINHERIT;
\password ruvee_owner
\password ruvee_operator
\password ruvee_runtime
```

Use three different, long random passwords (`\password` keeps them out of the server log and
the shell history). Then, once per database:

```sql
CREATE DATABASE ruvee OWNER ruvee_operator;
\c ruvee
ALTER DATABASE "ruvee" OWNER TO "ruvee_operator";
REVOKE ALL ON DATABASE "ruvee" FROM PUBLIC;
GRANT CONNECT ON DATABASE "ruvee" TO "ruvee_owner", "ruvee_runtime";
ALTER SCHEMA public OWNER TO "ruvee_owner";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

Then, on the host:

```bash
pnpm --filter @ruvee/api build
cd apps/api
DATABASE_URL='postgresql://ruvee_owner:…@127.0.0.1:5432/ruvee' npx prisma migrate deploy
RUVEE_ADMIN_DATABASE_URL='postgresql://ruvee_operator:…@127.0.0.1:5432/ruvee' RUVEE_RUNTIME_ROLE=ruvee_runtime node dist/admin/cli.js init
RUVEE_ADMIN_DATABASE_URL='postgresql://ruvee_operator:…@127.0.0.1:5432/ruvee' node dist/admin/cli.js bootstrap-token
```

`init` marks the database as a fresh installation and gives `ruvee_runtime` exactly its list.
Finally set the API's `DATABASE_URL` to `ruvee_runtime`'s URL and start the API. (Put a leading
space before commands that contain a password if your shell keeps history, or export the
variable from a file only you can read.)

## 3. After every migration

```bash
DATABASE_URL='<owner URL>' npx prisma migrate deploy
RUVEE_ADMIN_DATABASE_URL='<operator URL>' RUVEE_RUNTIME_ROLE=ruvee_runtime node dist/admin/cli.js grant-runtime
```

`grant-runtime` revokes everything the runtime role holds in this database, grants the list in
`apps/api/src/database/runtime-privileges.ts`, and checks the result. It refuses to run while a
table is missing from that list. A new table must be classified in the code first: the runtime
role never gets access to a table just because a migration created it. If `grant-runtime`
removed a privilege the role should not have had, restart the API afterwards: it checks its own
privileges for anything beyond the list once, at its first request.

### 3.1 The shared-limits migration (`20261029090000_shared_limits`)

This migration adds `rate_windows` and `login_states` (follow-up review §17.2 option B). It holds
no data to convert: both tables start empty and stay transient. On an existing installation:

1. Stop the API (pending logins of the old process are lost; their clients log in again).
2. As the owner: `prisma migrate deploy` (above).
3. As the operator: `ruvee-admin grant-runtime` (above). It grants the runtime role exactly
   `SELECT, INSERT, UPDATE, DELETE` on `rate_windows` and `SELECT, INSERT, DELETE` on
   `login_states`, and nothing else.
4. Start the new API build. Every process that serves the database must use the same OPAQUE setup
   file (it already had to): the login states are sealed under a key derived from it.

If step 3 is skipped, the API fails closed: every login and every authenticated request is
refused with `500 internal_error` (permission denied on the new tables) until `grant-runtime`
runs. No limit is skipped. Nothing needs cleaning: expired windows and login states are removed
by the API itself, a few hundred at a time, as new ones are added. To empty both tables by hand
(for example after a test), as the operator: `DELETE FROM rate_windows; DELETE FROM login_states;`.

The instance lock stays: run one API process per database. It is now an operational guard only;
no limit depends on it (README, "Deployment topology").

## 4. Moving an existing database (set up before F-25)

Before F-25 the API connected as one administrator role that owned everything. Do this during a
maintenance window, with a fresh encrypted backup first (server-backup-restore.md §3).

1. Stop the API.
2. As the cluster administrator: create the three roles (§2, first block).
3. Connected to the database, as the cluster administrator: the database statements of §2,
   then hand every object to its role. Nothing here changes a row:

   ```sql
   DO $$ DECLARE r record; BEGIN
     FOR r IN SELECT c.relname, c.relkind FROM pg_class c
         JOIN pg_namespace n ON n.oid = c.relnamespace
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'S') LOOP
       EXECUTE format('ALTER %s public.%I OWNER TO "ruvee_owner"',
         CASE r.relkind WHEN 'S' THEN 'SEQUENCE' ELSE 'TABLE' END, r.relname);
     END LOOP;
     FOR r IN SELECT t.typname FROM pg_type t JOIN pg_namespace n ON n.oid = t.typnamespace
         WHERE n.nspname = 'public' AND t.typtype = 'e' LOOP
       EXECUTE format('ALTER TYPE public.%I OWNER TO "ruvee_owner"', r.typname);
     END LOOP;
     IF to_regnamespace('ruvee_control') IS NOT NULL THEN
       EXECUTE 'ALTER SCHEMA ruvee_control OWNER TO "ruvee_operator"';
       EXECUTE 'REVOKE ALL ON SCHEMA ruvee_control FROM PUBLIC';
       FOR r IN SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
           WHERE n.nspname = 'ruvee_control' AND c.relkind = 'r' LOOP
         EXECUTE format('ALTER TABLE ruvee_control.%I OWNER TO "ruvee_operator"', r.relname);
       END LOOP;
     END IF;
   END $$;
   ```

4. As the operator: `ruvee-admin grant-runtime` (§3). On a restored database that is still
   `reopening`, this also installs the reopening functions; the reopening continues as before.
5. Set the API's `DATABASE_URL` to the runtime role and start it. Check §6.
6. The old administrator role is no longer needed by Ruvee. If it is the container's superuser,
   keep it for cluster administration only. Otherwise remove its password or drop it once
   nothing else uses it.

This exact sequence is tested on a synthetic database
(`f25-roles.int-spec.ts`, "the guide's move of a database set up before F-25").

## 5. A restore target

The restore needs a **new, empty** database owned by the operator, with `public` owned by the
schema owner. As the cluster administrator:

```sql
CREATE DATABASE ruvee_restored OWNER ruvee_operator;
\c ruvee_restored
ALTER DATABASE "ruvee_restored" OWNER TO "ruvee_operator";
REVOKE ALL ON DATABASE "ruvee_restored" FROM PUBLIC;
GRANT CONNECT ON DATABASE "ruvee_restored" TO "ruvee_owner", "ruvee_runtime";
ALTER SCHEMA public OWNER TO "ruvee_owner";
REVOKE ALL ON SCHEMA public FROM PUBLIC;
```

Then follow server-backup-restore.md §4 with `RESTORE_DATABASE_URL` set to the operator's URL
for `ruvee_restored` and `RUVEE_RUNTIME_ROLE=ruvee_runtime`. The restore refuses a superuser,
the runtime role, or a `public` schema that the schema owner does not own. It ends with every
object owned by `ruvee_owner` and the runtime role holding exactly its list.

## 6. Checking a database

As any role, this lists what the runtime role holds beyond its list; it must return no rows of
concern (compare with `privilegeProblems` in runtime-privileges.ts, which the API and the tests
run):

```sql
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
FROM pg_roles WHERE rolname = 'ruvee_runtime';                         -- all false
SELECT count(*) FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member
WHERE r.rolname = 'ruvee_runtime';                                     -- 0
SELECT n.nspname, c.relname, o.rolname FROM pg_class c
JOIN pg_namespace n ON n.oid = c.relnamespace JOIN pg_roles o ON o.oid = c.relowner
WHERE n.nspname IN ('public', 'ruvee_control') AND c.relkind = 'r';   -- owner / operator only
```

In production the API itself refuses to serve (`503 server_unavailable`, with an error in its
log) when its role holds more than the list.

## 7. Local development

`docker compose` creates a superuser (`POSTGRES_USER`). The API still runs with it in
development and logs a warning that its role is not the runtime role. `ruvee-admin init` and
`restore` refuse a superuser, though. To use them locally, create the three roles and a database
as in §2, with the container's superuser as the cluster administrator, and point the three
variables at them. To run as deployed, set `DATABASE_URL` to the runtime role.
