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
    expect(Object.keys(document.paths as object).sort()).toEqual([
      '/api/v1/account',
      '/api/v1/account/keys',
      '/api/v1/account/password/finish',
      '/api/v1/account/password/start',
      '/api/v1/account/secret-key',
      '/api/v1/auth/login/finish',
      '/api/v1/auth/login/start',
      '/api/v1/auth/logout',
      '/api/v1/auth/reauth/finish',
      '/api/v1/auth/reauth/start',
      '/api/v1/auth/register/finish',
      '/api/v1/auth/register/start',
      '/api/v1/devices',
      '/api/v1/devices/current',
      '/api/v1/devices/{deviceId}/revoke',
      '/api/v1/pairings',
      '/api/v1/pairings/{pairingId}',
      '/api/v1/pairings/{pairingId}/approve',
      '/api/v1/pairings/{pairingId}/complete',
      '/api/v1/pairings/{pairingId}/request',
      '/api/v1/recovery/complete',
      '/api/v1/recovery/material',
      '/api/v1/recovery/password/start',
      '/api/v1/recovery/start',
      '/api/v1/sessions',
      '/api/v1/sessions/{sessionId}',
      '/api/v1/sync/changes',
      '/api/v1/sync/commits',
      '/api/v1/vault',
      '/health/live',
      '/health/ready',
    ]);
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

  it('marks every operation with its access level, and protected ones with the session cookie', () => {
    for (const [path, operations] of Object.entries(document.paths as Record<string, object>)) {
      for (const [method, op] of Object.entries(
        operations as Record<string, Record<string, unknown>>,
      )) {
        if (path.startsWith('/health/')) continue;
        const access = op['x-ruvee-access'];
        expect(['none', 'session', 'active', 'step-up', 'recovery'], `${method} ${path}`).toContain(
          access,
        );
        if (access === 'none') expect(op.security, `${method} ${path}`).toBeUndefined();
        else
          expect(op.security, `${method} ${path}`).toEqual([
            access === 'recovery' ? { recoveryCookie: [] } : { sessionCookie: [] },
          ]);
      }
    }
  });
});
