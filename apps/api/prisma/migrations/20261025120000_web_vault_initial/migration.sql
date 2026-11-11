
-- CreateEnum
CREATE TYPE "device_platform" AS ENUM ('web', 'extension', 'ios', 'android');

-- CreateEnum
CREATE TYPE "device_status" AS ENUM ('pending', 'active', 'revoked');

-- CreateEnum
CREATE TYPE "enrolled_via" AS ENUM ('bootstrap', 'pairing', 'recovery');

-- CreateEnum
CREATE TYPE "session_kind" AS ENUM ('cookie', 'token', 'recovery');

-- CreateEnum
CREATE TYPE "revoke_reason" AS ENUM ('logout', 'user', 'device_revoked', 'password_changed', 'recovery', 'refresh_reuse', 'expired');

-- CreateEnum
CREATE TYPE "throttle_scope" AS ENUM ('login', 'recovery', 'bootstrap', 'pairing');

-- CreateEnum
CREATE TYPE "security_event_type" AS ENUM ('login_succeeded', 'login_failed', 'session_revoked', 'refresh_reuse', 'password_changed', 'recovery_started', 'recovery_completed', 'recovery_key_rotated', 'device_pairing_requested', 'device_enrolled', 'device_revoked', 'pairing_mac_failed', 'vault_reset', 'bootstrap_used', 'bootstrap_failed', 'integrity_warning_reported');

-- CreateEnum
CREATE TYPE "commit_kind" AS ENUM ('normal', 'reseed', 'rotation');

-- CreateTable
CREATE TABLE "accounts" (
    "id" UUID NOT NULL,
    "username_normalized" TEXT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "accounts_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "opaque_credentials" (
    "account_id" UUID NOT NULL,
    "registration_record" BYTEA NOT NULL,
    "config_id" TEXT NOT NULL,
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "opaque_credentials_pkey" PRIMARY KEY ("account_id")
);

-- CreateTable
CREATE TABLE "account_keys" (
    "account_id" UUID NOT NULL,
    "kdf_profile" SMALLINT NOT NULL,
    "salt_pw" BYTEA NOT NULL,
    "ak_id" BYTEA NOT NULL,
    "ak_epoch" INTEGER NOT NULL,
    "wrapped_ak_password" BYTEA NOT NULL,
    "recovery_key_id" BYTEA NOT NULL,
    "wrapped_ak_recovery" BYTEA NOT NULL,
    "recovery_verifier" BYTEA NOT NULL,
    "keyset_version" BIGINT NOT NULL,
    "keyset" BYTEA NOT NULL,
    "row_version" BIGINT NOT NULL DEFAULT 1,
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "account_keys_pkey" PRIMARY KEY ("account_id")
);

-- CreateTable
CREATE TABLE "devices" (
    "id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "platform" "device_platform" NOT NULL,
    "status" "device_status" NOT NULL,
    "enrolled_via" "enrolled_via",
    "approved_by_device_id" UUID,
    "label" BYTEA,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "enrolled_at" TIMESTAMPTZ(3),
    "last_seen_at" TIMESTAMPTZ(3),
    "revoked_at" TIMESTAMPTZ(3),

    CONSTRAINT "devices_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "sessions" (
    "id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "device_id" UUID NOT NULL,
    "kind" "session_kind" NOT NULL,
    "secret_hash" BYTEA NOT NULL,
    "access_expires_at" TIMESTAMPTZ(3),
    "auth_at" TIMESTAMPTZ(3) NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "last_used_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "idle_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "absolute_expires_at" TIMESTAMPTZ(3) NOT NULL,
    "revoked_at" TIMESTAMPTZ(3),
    "revoke_reason" "revoke_reason",

    CONSTRAINT "sessions_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "auth_throttle" (
    "scope" "throttle_scope" NOT NULL,
    "subject_hash" BYTEA NOT NULL,
    "failure_count" INTEGER NOT NULL DEFAULT 0,
    "window_start" TIMESTAMPTZ(3) NOT NULL,
    "blocked_until" TIMESTAMPTZ(3),

    CONSTRAINT "auth_throttle_pkey" PRIMARY KEY ("scope","subject_hash")
);

-- CreateTable
CREATE TABLE "bootstrap_tokens" (
    "id" UUID NOT NULL,
    "token_hash" BYTEA NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,
    "used_at" TIMESTAMPTZ(3),

    CONSTRAINT "bootstrap_tokens_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "security_events" (
    "id" UUID NOT NULL,
    "account_id" UUID,
    "device_id" UUID,
    "type" "security_event_type" NOT NULL,
    "ip" INET,
    "user_agent" VARCHAR(256),
    "details" JSONB NOT NULL DEFAULT '{}',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "security_events_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vaults" (
    "id" UUID NOT NULL,
    "account_id" UUID NOT NULL,
    "vk_id" BYTEA NOT NULL,
    "current_seq" BIGINT NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vaults_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "vault_items" (
    "vault_id" UUID NOT NULL,
    "item_id" UUID NOT NULL,
    "revision" BIGINT NOT NULL,
    "record" BYTEA,
    "tombstone" BOOLEAN NOT NULL,
    "updated_seq" BIGINT NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_items_pkey" PRIMARY KEY ("vault_id","item_id")
);

-- CreateTable
CREATE TABLE "vault_commits" (
    "vault_id" UUID NOT NULL,
    "seq" BIGINT NOT NULL,
    "commit_id" UUID NOT NULL,
    "request_hash" BYTEA NOT NULL,
    "device_id" UUID NOT NULL,
    "manifest" BYTEA NOT NULL,
    "mutation_count" INTEGER NOT NULL,
    "kind" "commit_kind" NOT NULL DEFAULT 'normal',
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "vault_commits_pkey" PRIMARY KEY ("vault_id","seq")
);

-- CreateIndex
CREATE UNIQUE INDEX "accounts_username_normalized_key" ON "accounts"("username_normalized");

-- CreateIndex
CREATE INDEX "devices_account_id_idx" ON "devices"("account_id");

-- CreateIndex
CREATE UNIQUE INDEX "sessions_secret_hash_key" ON "sessions"("secret_hash");

-- CreateIndex
CREATE INDEX "sessions_account_id_idx" ON "sessions"("account_id");

-- CreateIndex
CREATE INDEX "sessions_device_id_idx" ON "sessions"("device_id");

-- CreateIndex
CREATE UNIQUE INDEX "bootstrap_tokens_token_hash_key" ON "bootstrap_tokens"("token_hash");

-- CreateIndex
CREATE INDEX "security_events_account_id_created_at_idx" ON "security_events"("account_id", "created_at");

-- CreateIndex
CREATE UNIQUE INDEX "vaults_account_id_key" ON "vaults"("account_id");

-- CreateIndex
CREATE INDEX "vault_items_vault_id_updated_seq_idx" ON "vault_items"("vault_id", "updated_seq");

-- CreateIndex
CREATE UNIQUE INDEX "vault_commits_vault_id_commit_id_key" ON "vault_commits"("vault_id", "commit_id");

-- AddForeignKey
ALTER TABLE "opaque_credentials" ADD CONSTRAINT "opaque_credentials_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "account_keys" ADD CONSTRAINT "account_keys_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "devices" ADD CONSTRAINT "devices_approved_by_device_id_fkey" FOREIGN KEY ("approved_by_device_id") REFERENCES "devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "security_events" ADD CONSTRAINT "security_events_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vaults" ADD CONSTRAINT "vaults_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_items" ADD CONSTRAINT "vault_items_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "vaults"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_commits" ADD CONSTRAINT "vault_commits_vault_id_fkey" FOREIGN KEY ("vault_id") REFERENCES "vaults"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "vault_commits" ADD CONSTRAINT "vault_commits_device_id_fkey" FOREIGN KEY ("device_id") REFERENCES "devices"("id") ON DELETE NO ACTION ON UPDATE CASCADE;

-- Byte lengths and consistency rules from docs/architecture/database-design.md that Prisma cannot
-- express. The API checks the same limits first; these keep the database honest on its own.
ALTER TABLE "accounts"
  ADD CONSTRAINT "accounts_username_length" CHECK (char_length("username_normalized") BETWEEN 1 AND 64);

ALTER TABLE "opaque_credentials"
  ADD CONSTRAINT "opaque_credentials_record_length" CHECK (octet_length("registration_record") BETWEEN 1 AND 1024),
  ADD CONSTRAINT "opaque_credentials_config_id_length" CHECK (char_length("config_id") BETWEEN 1 AND 128);

ALTER TABLE "account_keys"
  ADD CONSTRAINT "account_keys_kdf_profile" CHECK ("kdf_profile" >= 1),
  ADD CONSTRAINT "account_keys_salt_pw_length" CHECK (octet_length("salt_pw") = 16),
  ADD CONSTRAINT "account_keys_ak_id_length" CHECK (octet_length("ak_id") = 16),
  ADD CONSTRAINT "account_keys_ak_epoch" CHECK ("ak_epoch" >= 0),
  ADD CONSTRAINT "account_keys_wrapped_ak_password_length" CHECK (octet_length("wrapped_ak_password") = 93),
  ADD CONSTRAINT "account_keys_recovery_key_id_length" CHECK (octet_length("recovery_key_id") = 16),
  ADD CONSTRAINT "account_keys_wrapped_ak_recovery_length" CHECK (octet_length("wrapped_ak_recovery") = 93),
  ADD CONSTRAINT "account_keys_recovery_verifier_length" CHECK (octet_length("recovery_verifier") = 32),
  ADD CONSTRAINT "account_keys_keyset_version" CHECK ("keyset_version" >= 0 AND "keyset_version" <= 4294967295),
  ADD CONSTRAINT "account_keys_keyset_length" CHECK (octet_length("keyset") BETWEEN 61 AND 16445),
  ADD CONSTRAINT "account_keys_row_version" CHECK ("row_version" >= 1);

ALTER TABLE "devices"
  ADD CONSTRAINT "devices_label_length" CHECK ("label" IS NULL OR octet_length("label") BETWEEN 61 AND 189),
  ADD CONSTRAINT "devices_enrolled_via_when_enrolled" CHECK (("status" = 'pending') = ("enrolled_via" IS NULL));

ALTER TABLE "sessions"
  ADD CONSTRAINT "sessions_secret_hash_length" CHECK (octet_length("secret_hash") = 32),
  ADD CONSTRAINT "sessions_revoked_consistent" CHECK (("revoked_at" IS NULL) = ("revoke_reason" IS NULL));

ALTER TABLE "auth_throttle"
  ADD CONSTRAINT "auth_throttle_subject_hash_length" CHECK (octet_length("subject_hash") = 32),
  ADD CONSTRAINT "auth_throttle_failure_count" CHECK ("failure_count" >= 0);

ALTER TABLE "bootstrap_tokens"
  ADD CONSTRAINT "bootstrap_tokens_token_hash_length" CHECK (octet_length("token_hash") = 32);

ALTER TABLE "vaults"
  ADD CONSTRAINT "vaults_vk_id_length" CHECK (octet_length("vk_id") = 16),
  ADD CONSTRAINT "vaults_current_seq" CHECK ("current_seq" >= 0);

ALTER TABLE "vault_items"
  ADD CONSTRAINT "vault_items_tombstone" CHECK ("tombstone" = ("record" IS NULL)),
  ADD CONSTRAINT "vault_items_record_length" CHECK ("record" IS NULL OR octet_length("record") BETWEEN 1 AND 65702),
  ADD CONSTRAINT "vault_items_revision" CHECK ("revision" >= 1),
  ADD CONSTRAINT "vault_items_updated_seq" CHECK ("updated_seq" >= 1);

ALTER TABLE "vault_commits"
  ADD CONSTRAINT "vault_commits_seq" CHECK ("seq" >= 1),
  ADD CONSTRAINT "vault_commits_request_hash_length" CHECK (octet_length("request_hash") = 32),
  ADD CONSTRAINT "vault_commits_manifest_length" CHECK (octet_length("manifest") = 198),
  ADD CONSTRAINT "vault_commits_mutation_count" CHECK ("mutation_count" BETWEEN 0 AND 100);
