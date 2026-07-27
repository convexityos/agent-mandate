import { mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

import { THREATS, renderCatalog } from './threats.build.js';

/**
 * Writes `threats/README.md` and `threats/catalog.json`. Run with `npm run threats`.
 *
 * Committed, like the vectors, and for the same reason: the markdown is the
 * artifact a reader actually opens, and a generator nobody has run is a document
 * that says whatever it said last time. `threats.test.ts` checks the committed
 * files still match, so the catalogue cannot drift from the tests it cites.
 */
const dir = join(process.cwd(), 'threats');
mkdirSync(dir, { recursive: true });

writeFileSync(join(dir, 'README.md'), renderCatalog(), 'utf8');
writeFileSync(join(dir, 'catalog.json'), `${JSON.stringify(THREATS, null, 2)}\n`, 'utf8');
process.stderr.write(
  `wrote threats/README.md and threats/catalog.json (${THREATS.length} entries)\n`,
);
