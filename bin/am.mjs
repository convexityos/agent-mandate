#!/usr/bin/env node
/**
 * `am` entry point.
 *
 * A shim rather than the CLI itself, so `src/cli/index.ts` exports a `run` the
 * tests can call directly instead of spawning a process per assertion.
 */
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

const built = new URL('../dist/src/cli/index.js', import.meta.url);
if (!existsSync(fileURLToPath(built))) {
  process.stderr.write('am: not built yet — run `npm run build` first\n');
  process.exit(2);
}

const { run } = await import(built.href);
process.exitCode = await run(process.argv.slice(2));
