-- PostgreSQL cannot drop enum values; rebuild the two types without them on a disposable database.
DROP TABLE "proof_nonces";
ALTER TABLE "pairings" DROP COLUMN "request_device_public_key";
ALTER TABLE "sessions" DROP COLUMN "proven_at";
ALTER TABLE "account_keys" DROP COLUMN "ak_verify_key";
ALTER TABLE "devices" DROP COLUMN "public_key";
DELETE FROM "security_events" WHERE "type"::text = 'device_proof_failed';
ALTER TYPE "security_event_type" RENAME TO "security_event_type_old";
CREATE TYPE "security_event_type" AS ENUM ('login_succeeded', 'login_failed', 'session_revoked', 'refresh_reuse', 'password_changed', 'recovery_started', 'recovery_failed', 'recovery_completed', 'recovery_key_rotated', 'secret_key_rotated', 'device_pairing_requested', 'device_enrolled', 'device_revoked', 'pairing_mac_failed', 'vault_reset', 'bootstrap_used', 'bootstrap_failed', 'integrity_warning_reported', 'server_restored', 'restore_review_completed', 'reopen_code_issued', 'reopen_started', 'reopen_failed', 'restore_reopened');
ALTER TABLE "security_events" ALTER COLUMN "type" TYPE "security_event_type" USING "type"::text::"security_event_type";
DROP TYPE "security_event_type_old";
UPDATE "sessions" SET "revoke_reason" = 'user' WHERE "revoke_reason"::text = 'proof_failed';
ALTER TYPE "revoke_reason" RENAME TO "revoke_reason_old";
CREATE TYPE "revoke_reason" AS ENUM ('logout', 'user', 'device_revoked', 'password_changed', 'recovery', 'refresh_reuse', 'expired', 'superseded', 'restored', 'reopened');
ALTER TABLE "sessions" ALTER COLUMN "revoke_reason" TYPE "revoke_reason" USING "revoke_reason"::text::"revoke_reason";
DROP TYPE "revoke_reason_old";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261026200000_device_proof';
