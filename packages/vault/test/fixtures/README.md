# Export fixtures (synthetic, test-only)

| File                         | What it is                                                                                                                                                                                    |
| ---------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `export-v1.expected.json`    | **Hand-written.** The four items the fixture was generated from, one deleted item, and the export date. Tests compare imports against this file, not against output of the reader under test. |
| `export-v1.ruvee`            | A format-version-1 encrypted export (backup-restore.md §4.2), generated once on 2026-10-26                                                                                                    |
| `export-v1.recovery-key.txt` | The **synthetic** Recovery Key that opens it. It protects nothing real: it was made for this fixture and its account existed only in an in-memory test server.                                |

**Provenance.** `export-v1.ruvee` was produced by the real engine against the in-memory
`FakeServer`, with a fixed clock, by the test "is regenerated on request" in
`src/import.test.ts`:

```sh
WRITE_EXPORT_FIXTURE=1 pnpm --filter @ruvee/vault exec vitest run src/import.test.ts -t regenerated
```

It saves the items of `export-v1.expected.json` in order, at their `createdAtMs`, moves the bank
login to Trash at its `trashedAtMs`, creates and permanently deletes a fifth item, and exports at
`asOfMs`. Every key, nonce and id in it is random, so regenerating produces a different file that
must still satisfy the same tests. **Regenerate only when the format version changes**; the point
of a fixed file is that future readers keep opening an export written by today's code.

Checks that do not use the reader: `src/import.test.ts` "has the documented structure, checked
without the export reader" reads the JSON and envelope headers with plain `Buffer` code.
