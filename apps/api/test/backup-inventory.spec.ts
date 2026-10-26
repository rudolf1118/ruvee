import { CONFIG_INVENTORY, TABLE_INVENTORY } from '../src/admin/backup-inventory.js';
import { envSchema } from '../src/config/env.js';
import { COLUMN_CLASSES } from '../src/database/column-classes.js';

describe('server backup inventory (backup-restore.md §3.1)', () => {
  it('classifies every configuration variable', () => {
    expect(Object.keys(CONFIG_INVENTORY).sort()).toEqual(Object.keys(envSchema.shape).sort());
  });

  it('describes every table, and marks the ones holding secret material', () => {
    expect(Object.keys(TABLE_INVENTORY).sort()).toEqual(Object.keys(COLUMN_CLASSES).sort());
    // A table with any vault-secret (V) or ciphertext (C) column counts as secret material.
    for (const [table, columns] of Object.entries(COLUMN_CLASSES)) {
      const secret = Object.values(columns).some((c) => c === 'V' || c === 'C');
      if (secret) expect(TABLE_INVENTORY[table]?.secretMaterial, table).toBe(true);
    }
  });
});
