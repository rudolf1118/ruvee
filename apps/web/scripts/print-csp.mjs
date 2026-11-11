// Prints the production CSP for the current static export (hashes change with the HTML).
import { productionCsp } from './csp-from-export.mjs';

process.stdout.write(`${await productionCsp()}\n`);
