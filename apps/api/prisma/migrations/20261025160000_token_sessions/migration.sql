-- Token sessions for the extension (authentication.md §5, Phase 5): rotating refresh tokens.
CREATE TABLE "refresh_tokens" (
    "token_hash" BYTEA NOT NULL,
    "session_id" UUID NOT NULL,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "rotated_at" TIMESTAMPTZ(3),

    CONSTRAINT "refresh_tokens_pkey" PRIMARY KEY ("token_hash")
);

CREATE INDEX "refresh_tokens_session_id_idx" ON "refresh_tokens"("session_id");

ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_session_id_fkey" FOREIGN KEY ("session_id") REFERENCES "sessions"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "refresh_tokens"
  ADD CONSTRAINT "refresh_tokens_token_hash_length" CHECK (octet_length("token_hash") = 32);

-- Only token sessions have an access-token expiry, and every token session has one.
ALTER TABLE "sessions"
  ADD CONSTRAINT "sessions_token_access_expiry" CHECK (("kind" = 'token') = ("access_expires_at" IS NOT NULL));
