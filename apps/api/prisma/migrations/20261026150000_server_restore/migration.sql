-- Server restore (backup-restore.md §3.5 and §3.6): sessions ended by a restore, and its events.
ALTER TYPE "revoke_reason" ADD VALUE 'restored' AFTER 'superseded';
ALTER TYPE "security_event_type" ADD VALUE 'server_restored' AFTER 'integrity_warning_reported';
ALTER TYPE "security_event_type" ADD VALUE 'restore_review_completed' AFTER 'server_restored';
