-- PostgreSQL cannot drop enum values; rebuild the three types without them on a disposable database.
DELETE FROM "security_events" WHERE "type"::text IN ('reopen_code_issued', 'reopen_started', 'reopen_failed', 'restore_reopened');
ALTER TYPE "security_event_type" RENAME TO "security_event_type_old";
CREATE TYPE "security_event_type" AS ENUM ('login_succeeded', 'login_failed', 'session_revoked', 'refresh_reuse', 'password_changed', 'recovery_started', 'recovery_failed', 'recovery_completed', 'recovery_key_rotated', 'secret_key_rotated', 'device_pairing_requested', 'device_enrolled', 'device_revoked', 'pairing_mac_failed', 'vault_reset', 'bootstrap_used', 'bootstrap_failed', 'integrity_warning_reported', 'server_restored', 'restore_review_completed');
ALTER TABLE "security_events" ALTER COLUMN "type" TYPE "security_event_type" USING "type"::text::"security_event_type";
DROP TYPE "security_event_type_old";
DELETE FROM "sessions" WHERE "kind"::text = 'reopen';
UPDATE "sessions" SET "revoke_reason" = 'restored' WHERE "revoke_reason"::text = 'reopened';
ALTER TYPE "revoke_reason" RENAME TO "revoke_reason_old";
CREATE TYPE "revoke_reason" AS ENUM ('logout', 'user', 'device_revoked', 'password_changed', 'recovery', 'refresh_reuse', 'expired', 'superseded', 'restored');
ALTER TABLE "sessions" ALTER COLUMN "revoke_reason" TYPE "revoke_reason" USING "revoke_reason"::text::"revoke_reason";
DROP TYPE "revoke_reason_old";
-- The token-session check compares "kind" with a literal of the type; it is re-created after.
ALTER TABLE "sessions" DROP CONSTRAINT "sessions_token_access_expiry";
ALTER TYPE "session_kind" RENAME TO "session_kind_old";
CREATE TYPE "session_kind" AS ENUM ('cookie', 'token', 'recovery');
ALTER TABLE "sessions" ALTER COLUMN "kind" TYPE "session_kind" USING "kind"::text::"session_kind";
DROP TYPE "session_kind_old";
ALTER TABLE "sessions"
  ADD CONSTRAINT "sessions_token_access_expiry" CHECK (("kind" = 'token') = ("access_expires_at" IS NOT NULL));
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261026170000_reopening';
