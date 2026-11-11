ALTER TABLE "sessions" DROP CONSTRAINT "sessions_token_access_expiry";
DROP TABLE "refresh_tokens";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261025160000_token_sessions';
