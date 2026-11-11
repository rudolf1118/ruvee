-- Reopening after a restore (backup-restore.md §3.13, D-30 option B): the restricted reopen
-- session, the revocations it causes, and its events. The codes themselves live in the restore
-- tool's own table (ruvee_reopen_codes), which is never part of a backup.
ALTER TYPE "session_kind" ADD VALUE 'reopen' AFTER 'recovery';
ALTER TYPE "revoke_reason" ADD VALUE 'reopened' AFTER 'restored';
ALTER TYPE "security_event_type" ADD VALUE 'reopen_code_issued' AFTER 'restore_review_completed';
ALTER TYPE "security_event_type" ADD VALUE 'reopen_started' AFTER 'reopen_code_issued';
ALTER TYPE "security_event_type" ADD VALUE 'reopen_failed' AFTER 'reopen_started';
ALTER TYPE "security_event_type" ADD VALUE 'restore_reopened' AFTER 'reopen_failed';
