-- PostgreSQL cannot drop an enum value; rebuild the type without it on a disposable database.
ALTER TYPE "revoke_reason" RENAME TO "revoke_reason_old";
CREATE TYPE "revoke_reason" AS ENUM ('logout', 'user', 'device_revoked', 'password_changed', 'recovery', 'refresh_reuse', 'expired');
UPDATE "sessions" SET "revoke_reason" = 'user' WHERE "revoke_reason"::text = 'superseded';
ALTER TABLE "sessions" ALTER COLUMN "revoke_reason" TYPE "revoke_reason" USING "revoke_reason"::text::"revoke_reason";
DROP TYPE "revoke_reason_old";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261026090000_session_superseded';
