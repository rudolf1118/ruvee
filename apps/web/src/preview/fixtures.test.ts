import { previewItems, previewVaults } from './fixtures';

const allText = previewItems.flatMap((item) => [
  item.title,
  item.subtitle,
  ...item.searchText,
  ...item.fields.map((field) => field.display),
]);

describe('preview fixtures', () => {
  it('only reference reserved .example domains', () => {
    const websites = previewItems.flatMap((item) =>
      item.fields.filter((field) => field.label === 'Website').map((field) => field.display),
    );
    const emailDomains = allText.flatMap((text) =>
      [...text.matchAll(/@([a-z0-9.-]+)/gi)].map((match) => match[1] ?? ''),
    );
    const domains = [...websites, ...emailDomains];
    expect(domains.length).toBeGreaterThan(0);
    for (const domain of domains) expect(domain).toMatch(/\.example$/);
  });

  it('never carry a value in concealed fields, only a mask', () => {
    const concealed = previewItems.flatMap((item) => item.fields.filter((f) => f.concealed));
    expect(concealed.length).toBeGreaterThan(0);
    for (const field of concealed) expect(field.display).toMatch(/^[• ]+(0000)?$/);
  });

  it('conceal every password, card number and security code field', () => {
    const sensitive = /password|card number|security code|cvv|pin/i;
    for (const item of previewItems) {
      for (const field of item.fields) {
        if (sensitive.test(field.label)) expect(field.concealed).toBe(true);
      }
    }
  });

  it('use only fictional 555-01xx phone numbers', () => {
    const phones = allText.flatMap((text) => text.match(/\(\d{3}\) \d{3}-\d{4}/g) ?? []);
    for (const phone of phones) expect(phone).toMatch(/^\(555\) 01\d-\d{4}$/);
  });

  it('reference only known vaults', () => {
    const vaultIds = new Set(previewVaults.map((v) => v.id));
    for (const item of previewItems) expect(vaultIds.has(item.vaultId)).toBe(true);
  });
});
