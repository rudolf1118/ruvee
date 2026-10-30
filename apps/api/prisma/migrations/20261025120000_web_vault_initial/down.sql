-- Rolls back 20261025120000_web_vault_initial on a disposable database. Prisma has no down
-- migrations; test/migrations.int-spec.ts applies this to check that the migration reverses
-- cleanly. Never run it against a database that holds data you want to keep.
DROP TABLE IF EXISTS "vault_commits", "vault_items", "vaults", "security_events",
  "bootstrap_tokens", "auth_throttle", "sessions", "devices", "account_keys",
  "opaque_credentials", "accounts" CASCADE;
DROP TYPE IF EXISTS "commit_kind", "security_event_type", "throttle_scope", "revoke_reason",
  "session_kind", "enrolled_via", "device_status", "device_platform";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261025120000_web_vault_initial';
