import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { EXTENSION_VAULT_METHODS, requestSchema } from './messages';

/**
 * Follow-up review F-21: the service worker accepts from the extension's pages exactly the vault
 * methods those pages call, so nothing unused (an item's notes through `detail`, the whole list
 * through `items`) can be asked for.
 */
describe('the extension pages’ vault methods', () => {
  const ui = new URL('./ui/', import.meta.url).pathname;
  const called = new Set(
    readdirSync(ui)
      .filter((f) => /\.tsx?$/.test(f) && !f.includes('.test.'))
      .flatMap((f) =>
        [...readFileSync(join(ui, f), 'utf8').matchAll(/kind: 'vault',\s*method: '(\w+)'/g)].map(
          (m) => m[1],
        ),
      ),
  );

  it('allows exactly the methods the pages call', () => {
    expect([...EXTENSION_VAULT_METHODS].sort()).toEqual([...called].sort());
  });

  it('refuses the methods the pages never use', () => {
    for (const method of ['detail', 'items', 'acknowledgeRecoveryNotice', 'secret'])
      expect(requestSchema.safeParse({ kind: 'vault', method }).success).toBe(false);
    expect(requestSchema.safeParse({ kind: 'vault', method: 'phase' }).success).toBe(true);
  });
});
