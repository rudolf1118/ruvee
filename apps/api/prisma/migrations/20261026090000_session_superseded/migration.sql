-- A new login for a known device ends that device's older sessions (authentication.md §5).
ALTER TYPE "revoke_reason" ADD VALUE 'superseded' AFTER 'expired';
