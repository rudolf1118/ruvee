-- Pairings (device-enrollment.md §3) and a corrected device-state rule.

-- CreateEnum
CREATE TYPE "pairing_state" AS ENUM ('open', 'requested', 'approved');

-- CreateTable
CREATE TABLE "pairings" (
    "pairing_id" BYTEA NOT NULL,
    "account_id" UUID NOT NULL,
    "initiator_device_id" UUID NOT NULL,
    "state" "pairing_state" NOT NULL,
    "requester_device_id" UUID,
    "request_platform" "device_platform",
    "request_epk" BYTEA,
    "request_mac" BYTEA,
    "requested_at" TIMESTAMPTZ(3),
    "response_ciphertext" BYTEA,
    "response_mac" BYTEA,
    "created_at" TIMESTAMPTZ(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "expires_at" TIMESTAMPTZ(3) NOT NULL,

    CONSTRAINT "pairings_pkey" PRIMARY KEY ("pairing_id")
);

-- CreateIndex
CREATE INDEX "pairings_account_id_idx" ON "pairings"("account_id");

-- AddForeignKey
ALTER TABLE "pairings" ADD CONSTRAINT "pairings_account_id_fkey" FOREIGN KEY ("account_id") REFERENCES "accounts"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pairings" ADD CONSTRAINT "pairings_initiator_device_id_fkey" FOREIGN KEY ("initiator_device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "pairings" ADD CONSTRAINT "pairings_requester_device_id_fkey" FOREIGN KEY ("requester_device_id") REFERENCES "devices"("id") ON DELETE CASCADE ON UPDATE CASCADE;


ALTER TABLE "pairings"
  ADD CONSTRAINT "pairings_pairing_id_length" CHECK (octet_length("pairing_id") = 16),
  ADD CONSTRAINT "pairings_request_epk_length" CHECK ("request_epk" IS NULL OR octet_length("request_epk") = 32),
  ADD CONSTRAINT "pairings_request_mac_length" CHECK ("request_mac" IS NULL OR octet_length("request_mac") = 32),
  ADD CONSTRAINT "pairings_response_ciphertext_length" CHECK ("response_ciphertext" IS NULL OR octet_length("response_ciphertext") BETWEEN 49 AND 4096),
  ADD CONSTRAINT "pairings_response_mac_length" CHECK ("response_mac" IS NULL OR octet_length("response_mac") = 32),
  ADD CONSTRAINT "pairings_request_complete" CHECK (
    ("state" = 'open') = ("requester_device_id" IS NULL)
    AND ("requester_device_id" IS NULL) = ("request_epk" IS NULL)
    AND ("request_epk" IS NULL) = ("request_mac" IS NULL)
    AND ("request_mac" IS NULL) = ("request_platform" IS NULL)
    AND ("request_platform" IS NULL) = ("requested_at" IS NULL)),
  ADD CONSTRAINT "pairings_response_complete" CHECK (
    ("state" = 'approved') = ("response_ciphertext" IS NOT NULL)
    AND ("response_ciphertext" IS NULL) = ("response_mac" IS NULL));

-- The first migration required (pending) = (no enrolled_via), which made a never-enrolled
-- device impossible to revoke. Pending devices have no enrolment method; active ones do.
ALTER TABLE "devices" DROP CONSTRAINT "devices_enrolled_via_when_enrolled";
ALTER TABLE "devices"
  ADD CONSTRAINT "devices_pending_not_enrolled" CHECK ("status" <> 'pending' OR "enrolled_via" IS NULL),
  ADD CONSTRAINT "devices_active_enrolled" CHECK ("status" <> 'active' OR "enrolled_via" IS NOT NULL);
