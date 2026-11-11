// Regenerates openapi.json from the built contracts. Run with `pnpm openapi:write`.
import { writeFileSync } from 'node:fs';
import { buildOpenApiDocument } from '../dist/openapi.js';

const target = new URL('../openapi.json', import.meta.url);
writeFileSync(target, `${JSON.stringify(buildOpenApiDocument(), null, 2)}\n`);
console.log(`wrote ${target.pathname}`);
