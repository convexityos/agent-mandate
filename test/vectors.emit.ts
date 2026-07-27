import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { buildVectors } from './vectors.build.js';

/**
 * Writes `vectors/*.json`. Run with `npm run vectors`.
 *
 * The output is committed: it is the artifact third parties test against, and a
 * generator nobody has run is not a conformance suite. `vectors.test.ts` checks
 * the committed files still match this, so they cannot quietly drift.
 */
// Anchored to the package root rather than to this file: the script is run from
// `dist/` after a build, where `import.meta.url` would put the output in
// `dist/vectors/` instead of the committed directory.
const dir = join(process.cwd(), 'vectors');
mkdirSync(dir, { recursive: true });

for (const [name, body] of Object.entries(buildVectors())) {
  // Trailing newline and two-space indent so the files diff like source rather
  // than like a blob.
  writeFileSync(join(dir, name), `${JSON.stringify(body, null, 2)}\n`, 'utf8');
  process.stderr.write(`wrote vectors/${name}\n`);
}
