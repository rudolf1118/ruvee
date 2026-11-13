-- D-34 (web-reload-unlock.md §5): the server's side of a web reload ticket. One live ticket per
-- web session. The ticket id is stored only as its SHA-256; the server half H_srv is never stored:
-- it is recomputed from a key of the OPAQUE setup file, the ticket id the tab holds, the session
-- and the device (reload-ticket.ts). Transient, like login_states: a backup holds the definition
-- but no rows, and a restore empties it (backup-restore.md §3.2c).
CREATE TABLE "reload_tickets" (
    "id_hash" BYTEA NOT NULL,
    "account_id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "idle_seconds" INTEGER NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "idle_expires_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "reload_tickets_pkey" PRIMARY KEY ("id_hash"),
    CONSTRAINT "reload_tickets_id_hash_length" CHECK (octet_length("id_hash") = 32),
    CONSTRAINT "reload_tickets_idle_seconds_range" CHECK ("idle_seconds" BETWEEN 60 AND 28800),
    CONSTRAINT "reload_tickets_times" CHECK ("expires_at" > "created_at" AND "idle_expires_at" > "created_at")
);
CREATE UNIQUE INDEX "reload_tickets_session_id_key" ON "reload_tickets"("session_id");
CREATE INDEX "reload_tickets_expires_at_idx" ON "reload_tickets"("expires_at");
ALTER TABLE "reload_tickets" ADD CONSTRAINT "reload_tickets_account_id_fkey"
  FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "reload_tickets" ADD CONSTRAINT "reload_tickets_device_id_fkey"
  FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "reload_tickets" ADD CONSTRAINT "reload_tickets_session_id_fkey"
  FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
