-- Both tables hold only transient state (pending logins, request windows); nothing is lost.
DROP TABLE "login_states";
DROP TYPE "login_purpose";
DROP TABLE "rate_windows";
DROP TYPE "rate_scope";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261029090000_shared_limits';
