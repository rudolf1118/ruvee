-- Rolls back 20261025130000_pairings_and_device_state on a disposable database (see the first
-- migration's down.sql).
DROP TABLE IF EXISTS "pairings";
DROP TYPE IF EXISTS "pairing_state";
ALTER TABLE "devices" DROP CONSTRAINT IF EXISTS "devices_pending_not_enrolled";
ALTER TABLE "devices" DROP CONSTRAINT IF EXISTS "devices_active_enrolled";
ALTER TABLE "devices"
  ADD CONSTRAINT "devices_enrolled_via_when_enrolled" CHECK (("status" = 'pending') = ("enrolled_via" IS NULL));
DELETE FROM "_prisma_migrations" WHERE "migration_name" = '20261025130000_pairings_and_device_state';
