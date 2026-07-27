import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

import { THREATS, type ThreatEntry, type TestRef, renderCatalog } from './threats.build.js';

/**
 * §3.3 — the check that stops the threat catalogue becoming fiction.
 *
 * A security document decays in one specific way: the code moves, the tests are
 * renamed, and the table goes on asserting a mitigation that nothing enforces.
 * It reads exactly the same either way, which is why it is a bad format for
 * anything anyone relies on.
 *
 * So the entries name tests, and this file resolves every one of them against
 * the actual suite. Rename a test that a catalogue entry cites and the build
 * fails — the entry has to be re-examined rather than silently left claiming
 * coverage that has moved or gone.
 *
 * It does **not** check that the named test tests the right thing. Nothing
 * mechanical can. What it removes is the failure mode where the citation points
 * at nothing at all, which is the one that happens by accident.
 */

const ROOT = fileURLToPath(new URL('../', import.meta.url));

/**
 * Every `it(...)` / `test(...)` title in the suite, by file.
 *
 * Parsed from source rather than collected from a vitest run: a test file that
 * shells out to vitest inside vitest is a deadlock waiting for a slow machine,
 * and the failure this needs to catch — a citation pointing at nothing — is
 * visible statically.
 *
 * Dynamic titles (`it(\`... ${x}\`)`) are not extracted, so an entry may not
 * cite one. That is a real limitation and the reason `store-suite.ts` entries
 * cite the inner test names, which are literals, rather than the parameterized
 * describe blocks around them.
 */
const TITLE_RE = /\b(?:it|test)(?:\.[A-Za-z]+(?:\([^)]*\))?)*\(\s*(['"])((?:\\.|(?!\1).)*)\1/g;

function titlesIn(file: string): string[] {
  const src = readFileSync(join(ROOT, file), 'utf8');
  return [...src.matchAll(TITLE_RE)].map((m) => m[2]!.replace(/\\(['"\\])/g, '$1'));
}

const suite = new Map<string, string[]>();
for (const f of readdirSync(join(ROOT, 'test')).filter((f) => f.endsWith('.ts'))) {
  suite.set(`test/${f}`, titlesIn(`test/${f}`));
}

const allRefs = (e: ThreatEntry): TestRef[] =>
  e.test === null ? [] : Array.isArray(e.test) ? e.test : [e.test];

describe('every entry is structurally complete', () => {
  it('has a unique kebab-case id', () => {
    const ids = THREATS.map((e) => e.id);
    expect(new Set(ids).size, 'duplicate ids').toBe(ids.length);
    for (const id of ids) expect(id, `id ${id}`).toMatch(/^[a-z0-9]+(-[a-z0-9]+)*$/);
  });

  it('says what the attack is, why it works, and what stops it', () => {
    for (const e of THREATS) {
      // Length floors rather than mere presence: the failure mode of a security
      // table is the entry that technically has a mitigation column.
      expect(e.attack.length, `${e.id}.attack`).toBeGreaterThan(40);
      expect(e.why.length, `${e.id}.why`).toBeGreaterThan(60);
      expect(e.check.length, `${e.id}.check`).toBeGreaterThan(40);
      expect(e.code.length, `${e.id}.code`).toBeGreaterThan(0);
    }
  });

  it('cites a test, or says out loud that it cannot', () => {
    for (const e of THREATS) {
      if (e.test !== null) continue;
      expect(e.gap, `${e.id} has no test and no stated gap`).toBeDefined();
      expect(e.gap!.length, `${e.id}.gap`).toBeGreaterThan(60);
    }
  });

  it('points at source files that exist', () => {
    for (const e of THREATS) {
      for (const path of e.code) {
        expect(existsSync(join(ROOT, path)), `${e.id} → ${path}`).toBe(true);
      }
    }
  });
});

describe('every cited test resolves to a real test', () => {
  // One `it` per entry rather than one loop: a failure names the entry that
  // broke, which is the thing you need to know when a rename breaks four of them.
  for (const e of THREATS) {
    const refs = allRefs(e);
    if (refs.length === 0) continue;
    it(`${e.id}`, () => {
      for (const ref of refs) {
        const titles = suite.get(ref.file);
        expect(titles, `${e.id} cites ${ref.file}, which is not a test file`).toBeDefined();
        expect(
          titles!,
          `${e.id} cites "${ref.name}" in ${ref.file}, which has no such test`,
        ).toContain(ref.name);
      }
    });
  }
});

describe('the catalogue and the spec agree', () => {
  const spec = readFileSync(join(ROOT, 'spec/agent-mandate-v1.md'), 'utf8');

  it('references only spec sections that exist', () => {
    for (const e of THREATS) {
      for (const section of e.spec) {
        // `§10.3.1` must appear as a heading, not merely as a cross-reference —
        // otherwise a typo'd section number cites itself into existence.
        const n = section.replace('§', '');
        expect(
          new RegExp(`^#{2,4} ${n.replace(/\./g, '\\.')}[ .]`, 'm').test(spec),
          `${e.id} cites ${section}, which is not a heading in the spec`,
        ).toBe(true);
      }
    }
  });

  it('covers every row of the §16 table', () => {
    // §16 is the index and this is the long form, so the index may not grow a
    // row the catalogue does not answer. The link is by id, written into the
    // table, so renaming an attack in one place breaks the other.
    const section = /## 16\. Security considerations([\s\S]*?)\n---/.exec(spec);
    expect(section, 'spec §16 not found').not.toBeNull();

    // Parsed as table rows with the id in the last cell, rather than by
    // scanning for anything backticked and kebab-shaped: §16 is full of
    // backticked identifiers, and a check that matched `alg` as an entry id
    // would pass on rows that name no entry at all.
    const cited = section![1]!
      .split('\n')
      // `.trim()` before anything looks at the line: this file is CRLF on
      // Windows checkouts, and a `$`-anchored test for the separator row
      // silently stops matching when there is a `\r` after the last pipe — so
      // `---` sails through as an entry id and the failure names the wrong thing.
      .map((l) => l.trim())
      .filter((l) => l.startsWith('|') && !/^\|[\s\-:|]+\|$/.test(l))
      .map((l) => l.split('|').slice(1, -1).map((c) => c.trim()))
      .filter((cells) => cells.length === 3 && cells[0] !== 'Attack')
      .map((cells) => cells[2]!.replace(/`/g, ''));

    expect(cited.length, '§16 rows carry no catalogue ids').toBeGreaterThan(20);
    for (const id of cited) expect(id, 'last cell is not an entry id').toMatch(/^[a-z0-9-]+$/);

    const known = new Set(THREATS.map((e) => e.id));
    for (const id of cited) {
      expect(known.has(id), `§16 cites ${id}, which is not in the catalogue`).toBe(true);
    }
    // And the other way: an entry nobody indexed is an entry nobody will find.
    const indexed = new Set(cited);
    for (const e of THREATS) {
      expect(indexed.has(e.id), `${e.id} is in the catalogue but not in §16`).toBe(true);
    }
  });

  it('calls each attack by the same name in both places', () => {
    // Weaker-looking than the id check and it catches a different drift: the two
    // documents staying linked while quietly disagreeing about what the attack
    // is called, which is how a reader ends up unable to find the long form of
    // the row they are reading.
    const section = /## 16\. Security considerations([\s\S]*?)\n---/.exec(spec)![1]!;
    const titles = new Map(
      section
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.startsWith('|'))
        .map((l) => l.split('|').slice(1, -1).map((c) => c.trim()))
        .filter((cells) => cells.length === 3)
        .map((cells) => [cells[2]!.replace(/`/g, ''), cells[0]!] as const),
    );
    for (const e of THREATS) {
      expect(titles.get(e.id), `§16 calls ${e.id} something else`).toBe(e.title);
    }
  });
});

describe('the committed catalogue matches the generator', () => {
  it('threats/README.md is up to date', () => {
    const path = join(ROOT, 'threats/README.md');
    expect(existsSync(path), 'run `npm run threats`').toBe(true);
    expect(readFileSync(path, 'utf8')).toBe(renderCatalog());
  });

  it('threats/catalog.json is up to date', () => {
    const path = join(ROOT, 'threats/catalog.json');
    expect(existsSync(path), 'run `npm run threats`').toBe(true);
    expect(readFileSync(path, 'utf8')).toBe(`${JSON.stringify(THREATS, null, 2)}\n`);
  });
});

describe('the extractor this all rests on', () => {
  // If `titlesIn` silently returned nothing, every citation check above would
  // pass vacuously. This is the load-bearing assumption, so it gets its own test.
  it('finds the tests in this very file', () => {
    const mine = suite.get('test/threats.test.ts');
    expect(mine).toContain('finds the tests in this very file');
    expect(mine).toContain('has a unique kebab-case id');
  });

  it('reads the whole suite, not a corner of it', () => {
    const total = [...suite.values()].reduce((n, ts) => n + ts.length, 0);
    expect(total).toBeGreaterThan(400);
    // Titles containing an apostrophe are the ones a naive regex truncates.
    expect(suite.get('test/status.test.ts')).toContain(
      "caps how long an intermediary may hold a list to the list's own lifetime",
    );
  });
});
