-- PostgreSQL cannot drop an enum value; rebuild the type without it on a disposable database.
ALTER TYPE "security_event_type" RENAME TO "security_event_type_old";
CREATE TYPE "security_event_type" AS ENUM ('login_succeeded', 'login_failed', 'session_revoked', 'refresh_reuse', 'password_changed', 'recovery_started', 'recovery_completed', 'recovery_key_rotated', 'device_pairing_requested', 'device_enrolled', 'device_revoked', 'pairing_mac_failed', 'vault_reset', 'bootstrap_used', 'bootstrap_failed', 'integrity_warning_reported');
DELETE FROM "security_events" WHERE "type"::text = 'recovery_failed';
ALTER TABLE "security_events" ALTER COLUMN "type" TYPE "security_event_type" USING "type"::text::"security_event_type";
DROP TYPE "security_event_type_old";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261025140000_recovery_failed_event';
