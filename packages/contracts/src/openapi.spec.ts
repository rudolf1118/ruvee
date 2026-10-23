import { readFileSync } from 'node:fs';
import { buildOpenApiDocument } from './openapi.js';

const committedPath = new URL('../openapi.json', import.meta.url);

function refs(value: unknown, found: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) refs(item, found);
  } else if (value !== null && typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (key === '$ref' && typeof child === 'string') found.push(child);
      else refs(child, found);
    }
  }
  return found;
}

describe('OpenAPI document', () => {
  const document = buildOpenApiDocument();

  it('matches the committed openapi.json (run `pnpm openapi:write` after changing contracts)', () => {
    const committed = readFileSync(committedPath, 'utf8');
    expect(committed).toBe(`${JSON.stringify(document, null, 2)}\n`);
  });

  it('documents only the implemented endpoints', () => {
    expect(Object.keys(document.paths as object)).toEqual(['/health/live', '/health/ready']);
  });

  it('resolves every internal reference', () => {
    for (const pointer of refs(document)) {
      expect(pointer.startsWith('#/')).toBe(true);
      let node: unknown = document;
      for (const part of pointer.slice(2).split('/')) {
        node = (node as Record<string, unknown> | undefined)?.[part];
      }
      expect(node, pointer).toBeDefined();
    }
  });

  it('declares no security scheme, because no endpoint is protected', () => {
    expect(document).not.toHaveProperty('security');
    expect(document.components).not.toHaveProperty('securitySchemes');
  });
});
