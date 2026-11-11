-- Device proof of possession (docs/security/device-proof.md, D-31 A). Public keys only; no
-- existing row changes, so every existing session is unproven and keeps no privilege (§9).
ALTER TABLE "devices" ADD COLUMN "public_key" BYTEA;
ALTER TABLE "devices"
  ADD CONSTRAINT "devices_public_key_length" CHECK ("public_key" IS NULL OR octet_length("public_key") = 32);
ALTER TABLE "account_keys" ADD COLUMN "ak_verify_key" BYTEA;
ALTER TABLE "account_keys"
  ADD CONSTRAINT "account_keys_ak_verify_key_length" CHECK ("ak_verify_key" IS NULL OR octet_length("ak_verify_key") = 32);
ALTER TABLE "sessions" ADD COLUMN "proven_at" TIMESTAMPTZ(3);
ALTER TABLE "pairings" ADD COLUMN "request_device_public_key" BYTEA;
ALTER TABLE "pairings"
  ADD CONSTRAINT "pairings_request_device_public_key_length" CHECK ("request_device_public_key" IS NULL OR octet_length("request_device_public_key") = 32);

-- Single-use, session-bound server nonces (§6). Only SHA-256 of a nonce is stored.
CREATE TABLE "proof_nonces" (
    "id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "session_id" UUID NOT NULL,
    "operation" SMALLINT NOT NULL,
    "nonce_hash" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "consumed_at" TIMESTAMPTZ(3),
    CONSTRAINT "proof_nonces_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "proof_nonces_nonce_hash_length" CHECK (octet_length("nonce_hash") = 32),
    CONSTRAINT "proof_nonces_operation_range" CHECK ("operation" BETWEEN 1 AND 255)
);
CREATE UNIQUE INDEX "proof_nonces_nonce_hash_key" ON "proof_nonces"("nonce_hash");
CREATE INDEX "proof_nonces_session_id_idx" ON "proof_nonces"("session_id");
ALTER TABLE "proof_nonces" ADD CONSTRAINT "proof_nonces_account_id_fkey"
  FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;
ALTER TABLE "proof_nonces" ADD CONSTRAINT "proof_nonces_session_id_fkey"
  FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TYPE "security_event_type" ADD VALUE 'device_proof_failed' AFTER 'restore_reopened';
ALTER TYPE "revoke_reason" ADD VALUE 'proof_failed' AFTER 'reopened';
