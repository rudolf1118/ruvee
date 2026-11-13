-- Reload tickets are transient; dropping them only makes the next reload ask for the password.
DROP TABLE "reload_tickets";
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261112090000_reload_tickets';
