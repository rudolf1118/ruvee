-- D-24: rotating the Secret Key is recorded like the other key changes (cryptographic-design §6.2).
ALTER TYPE "security_event_type" ADD VALUE 'secret_key_rotated' AFTER 'recovery_key_rotated';
