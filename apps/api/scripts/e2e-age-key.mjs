// Test-only: prints a fresh, synthetic age X25519 key pair as JSON for the restore browser test.
// It protects nothing real; the test writes the identity to its own temporary file (mode 0600)
// and deletes it afterwards. A real owner's identity is never made by Ruvee's tools.
import { generateX25519Identity, identityToRecipient } from 'age-encryption';

const identity = await generateX25519Identity();
process.stdout.write(JSON.stringify({ identity, recipient: await identityToRecipient(identity) }));
