-- Follow-up review §17.2 option B: the per-address and per-session request windows and the
-- pending logins live in the database, so they hold however many API processes serve it.
-- Both tables are transient: a backup holds their definitions but no rows, and a restore
-- empties them (backup-restore.md §3.2c).

-- One fixed window per (scope, SHA-256 of the key). Keys are client addresses (normalized,
-- backup-restore.md R17), and session ids; never stored in the clear.
CREATE TYPE "rate_scope" AS ENUM ('address', 'wrong_code', 'session');

CREATE TABLE "rate_windows" (
    "scope" "rate_scope" NOT NULL,
    "key_hash" BYTEA NOT NULL,
    "window_start" TIMESTAMPTZ(3) NOT NULL,
    "hits" INTEGER NOT NULL,
    CONSTRAINT "rate_windows_pkey" PRIMARY KEY ("scope", "key_hash"),
    CONSTRAINT "rate_windows_key_hash_length" CHECK (octet_length("key_hash") = 32),
    CONSTRAINT "rate_windows_hits_range" CHECK ("hits" BETWEEN 0 AND 1000)
);
CREATE INDEX "rate_windows_scope_window_start_idx" ON "rate_windows"("scope", "window_start");

-- A started OPAQUE login, step-up or reopening (authentication.md §4). The id is stored as its
-- SHA-256; the OPAQUE server state and the device challenge are sealed under a key of the OPAQUE
-- server setup and the client-held login id, neither of which is in the database
-- (authentication.md §4.1; 0x02 envelope, 74 to 585 bytes).
CREATE TYPE "login_purpose" AS ENUM ('login', 'reauth', 'reopen');

CREATE TABLE "login_states" (
    "id_hash" BYTEA NOT NULL,
    "purpose" "login_purpose" NOT NULL,
    "login_subject" BYTEA NOT NULL,
    "account_id" UUID,
    "device_id" UUID,
    "platform" "device_platform" NOT NULL,
    "session_id" UUID,
    "reopen_code_id" UUID,
    "sealed" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    CONSTRAINT "login_states_pkey" PRIMARY KEY ("id_hash"),
    CONSTRAINT "login_states_id_hash_length" CHECK (octet_length("id_hash") = 32),
    CONSTRAINT "login_states_login_subject_length" CHECK (octet_length("login_subject") = 32),
    CONSTRAINT "login_states_sealed_length" CHECK (octet_length("sealed") BETWEEN 74 AND 585),
    CONSTRAINT "login_states_lifetime" CHECK ("expires_at" > "created_at" AND "expires_at" <= "created_at" + interval '5 minutes'),
    CONSTRAINT "login_states_reauth_binding" CHECK (("purpose" = 'reauth') = ("session_id" IS NOT NULL)),
    CONSTRAINT "login_states_reopen_binding" CHECK (("purpose" = 'reopen') = ("reopen_code_id" IS NOT NULL)),
    CONSTRAINT "login_states_account_binding" CHECK ("purpose" = 'login' OR "account_id" IS NOT NULL)
);
CREATE INDEX "login_states_expires_at_idx" ON "login_states"("expires_at");
ALTER TABLE "login_states" ADD CONSTRAINT "login_states_account_id_fkey"
  FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "login_states" ADD CONSTRAINT "login_states_session_id_fkey"
  FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;
