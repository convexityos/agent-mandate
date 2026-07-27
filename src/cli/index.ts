import { readFileSync, writeFileSync } from 'node:fs';

import {
  type Caveats,
  REGISTERED_CAVEATS,
  meetCaveats,
  narrows,
  validateCaveats,
} from '../caveats.js';
import { thumbprintOfDidKey } from '../didkey.js';
import { parseCompactJws } from '../jws.js';
import { Ledger } from '../ledger/ledger.js';
import { MemoryLedgerStore } from '../ledger/store.js';
import { type Money, isMoney, toScaled } from '../money.js';
import { type AgentKey, agentKeyFromSeed, generateAgentKey, signMandate } from '../sign.js';
import { PROTOCOL_VERSION, type MandateClaims } from '../types.js';
import { ANY_LEDGER, verifyChain } from '../verify.js';
import { bold, caveats, cyan, dim, green, indent, money, red, shortDid, yellow } from './format.js';

/**
 * §1.4 — `am`.
 *
 * `am inspect` is the reason this exists. The §7 non-transitivity defect — a
 * grandchild re-declaring what its grandparent forbade, while every parent-child
 * check passes — took property tests to find, and takes about four seconds to
 * see once the accumulated meet is printed beside each link. Everything else
 * here is in service of being able to produce a chain to point it at.
 */

const USAGE = `am — Agent Mandate Protocol (${PROTOCOL_VERSION})

  am keygen   [--out FILE]
  am mint     --key FILE --sub DID --cav JSON [--exp SECS] [--jti ID] [--ledger URL]
  am attenuate --key FILE --sub DID --cav JSON [--chain FILE] [--exp SECS] [--jti ID]
  am verify   [--chain FILE] --trust DID --resource URL --amount "1.00 USD"
              [--purpose P] [--task T] [--effect read|write|irreversible] [--now TS]
              [--ledger URL]   the ledger you serve; the chain must name it (§7)
  am inspect  [--chain FILE]
  am replay   [--chain FILE] --trust DID --spends FILE

A chain is a JSON array of compact JWS strings, read from --chain or stdin.
--json prints machine-readable output instead of the human rendering.
`;

// ---------------------------------------------------------------- arguments

interface Args {
  command: string;
  flags: Record<string, string | boolean>;
}

function parseArgs(argv: string[]): Args {
  const [command = 'help', ...rest] = argv;
  const flags: Record<string, string | boolean> = {};
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i]!;
    if (!token.startsWith('--')) continue;
    const name = token.slice(2);
    const next = rest[i + 1];
    if (next === undefined || next.startsWith('--')) {
      flags[name] = true;
    } else {
      flags[name] = next;
      i++;
    }
  }
  return { command, flags };
}

class UsageError extends Error {}

function str(flags: Args['flags'], name: string): string {
  const v = flags[name];
  if (typeof v !== 'string') throw new UsageError(`--${name} is required`);
  return v;
}

function optional(flags: Args['flags'], name: string): string | undefined {
  const v = flags[name];
  return typeof v === 'string' ? v : undefined;
}

// -------------------------------------------------------------------- input

function readStdin(): string {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

function loadChain(flags: Args['flags']): string[] {
  const file = optional(flags, 'chain');
  const raw = file === undefined ? readStdin() : readFileSync(file, 'utf8');
  if (raw.trim() === '') {
    throw new UsageError('no chain given: pass --chain FILE or pipe one on stdin');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new UsageError('chain must be a JSON array of compact JWS strings');
  }
  if (!Array.isArray(parsed) || parsed.some((t) => typeof t !== 'string')) {
    throw new UsageError('chain must be a JSON array of compact JWS strings');
  }
  return parsed as string[];
}

function loadKey(flags: Args['flags']): AgentKey {
  const seed = optional(flags, 'seed');
  if (seed !== undefined) return agentKeyFromSeed(Uint8Array.from(Buffer.from(seed, 'hex')));

  const file = str(flags, 'key');
  const jwk = JSON.parse(readFileSync(file, 'utf8')) as { d?: string };
  if (typeof jwk.d !== 'string') {
    throw new UsageError(`${file} has no private key material (\`d\`)`);
  }
  // Re-derived from the seed rather than imported, so a key file and a
  // `--seed` behave identically and there is one code path to be wrong.
  return agentKeyFromSeed(Uint8Array.from(Buffer.from(jwk.d, 'base64url')));
}

function parseCaveats(raw: string): Caveats {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new UsageError('--cav must be JSON');
  }
  const check = validateCaveats(parsed);
  if (!check.ok) {
    const hint =
      check.code === 'unknown_caveat'
        ? `\n  registered caveats: ${REGISTERED_CAVEATS.join(', ')}`
        : '';
    throw new UsageError(`${check.detail}${hint}`);
  }
  return parsed as Caveats;
}

/** `"1.00 USD"` or `"1.00USD"`, because both get typed. */
function parseAmount(raw: string): Money {
  const m = /^\s*([0-9]+(?:\.[0-9]+)?)\s*([A-Z]{3,8})\s*$/.exec(raw);
  if (m === null) throw new UsageError(`--amount must look like "1.00 USD", got ${raw}`);
  const amount = { cur: m[2]!, amt: m[1]! };
  if (!isMoney(amount)) throw new UsageError(`--amount is not a valid amount: ${raw}`);
  return amount;
}

const now = (flags: Args['flags']): number => {
  const given = optional(flags, 'now');
  return given === undefined ? Math.floor(Date.now() / 1000) : Number(given);
};

// ----------------------------------------------------------------- commands

function keygen(flags: Args['flags'], out: (s: string) => void): number {
  const key = generateAgentKey();
  const jwk = {
    ...key.jwk,
    d: (key.privateKey.export({ format: 'jwk' }) as { d?: string }).d,
  };
  const file = optional(flags, 'out');

  if (file !== undefined) {
    // 0600: this is a spending key, and the default umask is not.
    writeFileSync(file, `${JSON.stringify(jwk, null, 2)}\n`, { encoding: 'utf8', mode: 0o600 });
    out(`${green('wrote')} ${file}  ${dim(key.did)}`);
    out(dim('  keep it out of version control; anything holding it can issue mandates'));
    return 0;
  }

  out(JSON.stringify(jwk, null, 2));
  return 0;
}

function issue(flags: Args['flags'], parent: string[] | null, out: (s: string) => void): number {
  const signer = loadKey(flags);
  const sub = str(flags, 'sub');
  const cav = parseCaveats(str(flags, 'cav'));
  const issuedAt = now(flags);
  const ttl = Number(optional(flags, 'exp') ?? 3600);

  let par: string | null = null;
  let ledgerUrl = optional(flags, 'ledger') ?? 'https://ledger.example.com';

  if (parent !== null) {
    const last = parseCompactJws(parent[parent.length - 1]!);
    if (last === null) throw new UsageError('the chain to attenuate does not parse');
    const claims = last.payload as unknown as MandateClaims;
    par = claims.jti;
    // Inherited rather than re-specified: §7 requires every link to agree on the
    // ledger, so asking for it again is only an opportunity to disagree.
    ledgerUrl = claims.ledger;
    if (claims.sub !== signer.did) {
      throw new UsageError(
        `--key is ${shortDid(signer.did)} but the chain's last link was issued to ${shortDid(claims.sub)}\n` +
          '  a link must be signed by the holder of the link above it (§7 step 2)',
      );
    }
  }

  const claims: MandateClaims = {
    v: PROTOCOL_VERSION,
    typ: 'mandate',
    jti: optional(flags, 'jti') ?? `mnd_${Math.random().toString(36).slice(2, 12)}`,
    iss: signer.did,
    sub,
    par,
    iat: issuedAt,
    nbf: issuedAt,
    exp: issuedAt + ttl,
    cnf: { jkt: thumbprintOf(sub) },
    ledger: ledgerUrl,
    cav,
  };

  const token = signMandate(claims, signer, signer.did);
  out(JSON.stringify(parent === null ? [token] : [...parent, token], null, 2));
  return 0;
}

/**
 * `cnf.jkt` binds the mandate to the holder's key, so it is derived from the
 * subject DID rather than asked for separately — a mismatch there produces a
 * mandate nobody can present.
 */
function thumbprintOf(did: string): string {
  const jkt = thumbprintOfDidKey(did);
  if (jkt === null) throw new UsageError(`--sub is not a did:key: ${did}`);
  return jkt;
}

async function verify(flags: Args['flags'], out: (s: string) => void): Promise<number> {
  const tokens = loadChain(flags);
  const trust = str(flags, 'trust');
  const request = {
    resource: str(flags, 'resource'),
    amount: parseAmount(str(flags, 'amount')),
    ...(optional(flags, 'purpose') !== undefined ? { purpose: optional(flags, 'purpose') } : {}),
    ...(optional(flags, 'task') !== undefined ? { taskId: optional(flags, 'task') } : {}),
    ...(optional(flags, 'effect') !== undefined
      ? { effect: optional(flags, 'effect') as Caveats['effect'] }
      : {}),
  };

  // `--ledger` is how you ask the §7 step 3 question from the CLI. Without it
  // this is a bystander inspecting a credential it has no relationship with, and
  // saying so is more honest than comparing against a made-up URL — but a
  // deployment checking its *own* mandates should pass it, because a chain that
  // verifies here and is refused by the ledger is the confusing outcome.
  const expectLedger = optional(flags, 'ledger');

  const result = await verifyChain(tokens, {
    now: now(flags),
    request: request as never,
    ledger: expectLedger ?? ANY_LEDGER,
    isTrustedRootIssuer: (iss) => iss === trust,
  });

  if (flags['json'] === true) {
    out(JSON.stringify(result, null, 2));
    return result.ok ? 0 : 1;
  }

  if (!result.ok) {
    out(`${red('✗')} ${bold(result.code)}${result.link !== undefined ? dim(` at link ${result.link}`) : ''}`);
    out(`  ${result.detail}`);
    return 1;
  }
  out(`${green('✓')} admitted`);
  out(`  ${dim('effective')}  ${indent(caveats(result.effective), '             ')}`);
  out(`  ${dim('window')}     ${result.window.nbf} → ${result.window.exp}`);
  out(`  ${dim('chain')}      ${result.chainHash}`);
  return 0;
}

/**
 * The command this item exists for.
 *
 * Prints, for every link, what it declares and the accumulated meet after
 * folding it in. A grandchild re-declaring what its grandparent forbade is then
 * a line where `declares` disagrees with the `meet` printed directly above it,
 * which is a thing you notice rather than a thing you derive.
 *
 * Deliberately does not require a request context, unlike `verify`: this is
 * about the lattice, and a chain that would fail §8 coverage still has a fold
 * worth reading.
 */
function inspect(flags: Args['flags'], out: (s: string) => void): number {
  const tokens = loadChain(flags);
  const links: MandateClaims[] = [];
  for (const [i, token] of tokens.entries()) {
    const jws = parseCompactJws(token);
    if (jws === null) throw new UsageError(`link ${i} does not parse as a compact JWS`);
    links.push(jws.payload as unknown as MandateClaims);
  }

  if (flags['json'] === true) {
    let acc: Caveats = {};
    const rows = links.map((l) => {
      const before = acc;
      acc = meetCaveats(acc, l.cav);
      const check = narrows(l.cav, before);
      return {
        jti: l.jti,
        iss: l.iss,
        sub: l.sub,
        declares: l.cav,
        meet: acc,
        narrows: check.ok,
        ...(check.ok ? {} : { code: check.code, detail: check.detail }),
      };
    });
    out(JSON.stringify({ links: rows }, null, 2));
    return rows.every((r) => r.narrows) ? 0 : 1;
  }

  out(`${bold('chain')}  ${links.length} link${links.length === 1 ? '' : 's'}`);
  out('');

  let acc: Caveats = {};
  let failed = false;

  for (const [i, link] of links.entries()) {
    const before = acc;
    const check = narrows(link.cav, before);
    acc = meetCaveats(acc, link.cav);

    out(`  ${cyan(`[${i}]`)} ${bold(link.jti)}  ${dim(`${shortDid(link.iss)} → ${shortDid(link.sub)}`)}`);
    out(`      ${dim('declares')}  ${indent(caveats(link.cav), '                ')}`);
    out(`      ${dim('meet')}      ${indent(caveats(acc), '                ')}`);

    // The whole point. A link that declares nothing on a dimension inherits the
    // accumulated constraint, and saying so is what stops a reader assuming the
    // opposite.
    const inherited = Object.keys(before).filter((k) => !(k in link.cav));
    if (inherited.length > 0 && i > 0) {
      out(`      ${dim('inherits')}  ${dim(inherited.sort().join(', '))}`);
    }

    if (!check.ok) {
      failed = true;
      out(`      ${red('✗')} ${bold(check.code)} ${dim('against the accumulated meet')}`);
      out(`        ${check.detail}`);
      out(
        `        ${yellow('note')} every parent-child check may still pass here — §7 requires`,
      );
      out(`             comparing each link against the meet of everything above it`);
    }
    out('');
  }

  out(`  ${failed ? red('✗ chain does not attenuate') : green('✓ every link narrows the accumulated meet')}`);
  return failed ? 1 : 0;
}

/**
 * The stateful counterpart to `verify`.
 *
 * `verify` answers whether a chain *may* authorize a request. It cannot answer
 * whether the budget is still there, because `max_total` and `rate` are
 * consumption state the ledger walks the ancestor path to enforce (§10.1–10.2).
 * This runs a sequence of requests against a throwaway in-memory ledger so the
 * question "what will this mandate actually let through" has an answer that does
 * not require deploying anything.
 */
async function replay(flags: Args['flags'], out: (s: string) => void): Promise<number> {
  const tokens = loadChain(flags);
  const trust = str(flags, 'trust');
  const spendsRaw = readFileSync(str(flags, 'spends'), 'utf8');

  let spends: Array<{ resource: string; amount: Money; taskId?: string; purpose?: string }>;
  try {
    spends = JSON.parse(spendsRaw);
  } catch {
    throw new UsageError('--spends must be a JSON array of request contexts');
  }
  if (!Array.isArray(spends)) throw new UsageError('--spends must be a JSON array');

  // The simulated ledger answers as the one the chain names. A placeholder here
  // would be refused by `reserve`'s §7 step 3 check on every chain there is, and
  // rightly — the question `replay` answers is "what would *my* ledger let
  // through", so adopting the chain's own `ledger` is the only reading of it.
  // Same inheritance, and the same reason for it, as `attenuate` above.
  const rootClaims = parseCompactJws(tokens[0]!)?.payload as unknown as MandateClaims | undefined;
  if (rootClaims?.ledger === undefined) throw new UsageError('the chain does not parse');

  let clock = now(flags);
  const ledger = new Ledger({
    url: rootClaims.ledger,
    key: generateAgentKey(),
    store: new MemoryLedgerStore(() => clock),
    isTrustedRootIssuer: (iss) => iss === trust,
    clock: () => clock,
    // Off by default: the breakers are anomaly detection against a spending
    // history this ephemeral ledger does not have, so leaving them on would
    // report trips that say more about the replay than the mandate.
    breakers: { novelMerchant: 'off', velocityMinSamples: 1e9 },
  });

  // Every link's jti, because the number a reader needs is the *binding*
  // remaining — the tightest budget on the path — not the root's. Reporting the
  // root's is how you print "90 USD remaining" on the line above
  // `budget_exhausted` and look like you are contradicting yourself.
  const jtis = tokens
    .map((t) => (parseCompactJws(t)?.payload as unknown as MandateClaims | undefined)?.jti)
    .filter((j): j is string => j !== undefined);

  const binding = async (): Promise<{ jti: string; left: Money } | null> => {
    let tightest: { jti: string; left: Money } | null = null;
    for (const jti of jtis) {
      const left = await ledger.remaining(jti);
      if (left === null) continue;
      if (tightest === null || toScaled(left) < toScaled(tightest.left)) {
        tightest = { jti, left };
      }
    }
    return tightest;
  };

  const results: Array<Record<string, unknown>> = [];
  let admitted = 0;

  for (const [i, spend] of spends.entries()) {
    const r = await ledger.reserve({ tokens, request: spend as never });
    const tight = await binding();
    results.push({
      index: i,
      resource: spend.resource,
      amount: spend.amount,
      ok: r.ok,
      ...(r.ok ? { spendId: r.spendId } : { code: r.code, detail: r.detail }),
      ...(tight !== null ? { binding: { jti: tight.jti, remaining: tight.left } } : {}),
    });
    if (r.ok) admitted++;

    if (flags['json'] !== true) {
      const mark = r.ok ? green('✓') : red('✗');
      const what = `${money(spend.amount)} ${dim('→')} ${spend.resource}`;
      const tail = r.ok
        ? dim(tight === null ? '' : `  ${tight.jti} has ${money(tight.left)} left`)
        : `  ${bold(r.code)} ${dim(r.detail)}`;
      out(`  ${mark} ${what}${tail}`);
    }
    // Advance a second per spend so rate windows behave like a sequence of
    // calls rather than a single instant.
    clock += 1;
  }

  if (flags['json'] === true) {
    out(JSON.stringify({ spends: results }, null, 2));
  } else {
    out('');
    out(`  ${admitted}/${spends.length} admitted`);
  }
  return admitted === spends.length ? 0 : 1;
}

// ------------------------------------------------------------------ dispatch

export async function run(
  argv: string[],
  out: (s: string) => void = (s) => process.stdout.write(`${s}\n`),
  err: (s: string) => void = (s) => process.stderr.write(`${s}\n`),
): Promise<number> {
  const { command, flags } = parseArgs(argv);

  try {
    switch (command) {
      case 'keygen':
        return keygen(flags, out);
      case 'mint':
        return issue(flags, null, out);
      case 'attenuate':
        return issue(flags, loadChain(flags), out);
      case 'verify':
        return await verify(flags, out);
      case 'inspect':
        return inspect(flags, out);
      case 'replay':
        return await replay(flags, out);
      case 'help':
      case '--help':
      case '-h':
        out(USAGE);
        return 0;
      default:
        err(`unknown command: ${command}`);
        err(USAGE);
        return 2;
    }
  } catch (e) {
    if (e instanceof UsageError) {
      err(`${red('error')} ${e.message}`);
      return 2;
    }
    err(`${red('error')} ${e instanceof Error ? e.message : String(e)}`);
    return 1;
  }
}
