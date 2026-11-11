-- Rehearsal-only migration probe (A-22, rollback across a migration). Never merged.
-- A comment changes no table, column, privilege or behavior; it only makes this release's
-- schema differ from the previous one, so the rollback has to restore the pre-upgrade backup.
COMMENT ON TABLE "accounts" IS 'ruvee rehearsal migration probe 20261111150000';
