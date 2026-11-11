-- A failed recovery attempt is a security event like any other failure (authentication.md §7).
ALTER TYPE "security_event_type" ADD VALUE 'recovery_failed' AFTER 'recovery_started';
