#!/usr/bin/env node
/**
 * `am-hook` — the PreToolUse / PostToolUse entry point.
 *
 * Reads the hook payload on stdin, writes the decision on stdout (or stderr for
 * a block, which is where the harness reads the reason from), exits 0 or 2.
 *
 * Configured by `AM_HOOK_CONFIG`, a path to JSON:
 *
 *   {
 *     "tokens":  ["eyJ…", "eyJ…"],
 *     "stateDir": "/home/you/.claude/am-hook",
 *     "store":   { "kind": "sqlite", "location": "/home/you/.claude/am.db" },
 *     "ledgerKeySeed": "…64 hex chars…",
 *     "trustedRootIssuer": "did:key:z6Mk…",
 *     "taskId": "tsk_session",
 *     "prices": {
 *       "mcp__public-com__place_order": { "price": {"cur":"USD","amt":"0.01"},
 *                                         "effect": "irreversible" }
 *     }
 *   }
 *
 * A hook runs on every tool call, so this stays deliberately small: no build
 * step at call time, no network unless the ledger is remote, and any failure to
 * even parse the input exits 0 rather than wedging the session.
 */
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

/**
 * stderr is a channel, not a log.
 *
 * On a block this process exits 2 and the harness reads *stderr* as the reason
 * it shows the model. Node writes its own diagnostics there too — loading
 * `node:sqlite` prints an ExperimentalWarning — and a `process.on('warning')`
 * listener does **not** suppress that; only `--no-warnings` does, which a
 * shebang cannot portably pass.
 *
 * So stderr is swallowed for the body of this script and everything this file
 * genuinely wants to say goes through `emit`. Without it the model receives a
 * refusal reason with a Node warning stapled to it, which is at best confusing
 * and at worst unparseable.
 */
const emit = process.stderr.write.bind(process.stderr);
process.stderr.write = () => true;

const built = new URL('../dist/src/index.js', import.meta.url);
if (!existsSync(fileURLToPath(built))) {
  emit('am-hook: not built — run `npm run build`\n');
  process.exit(0); // never wedge the session over our own packaging
}

const { Ledger, MandateHook, MemoryLedgerStore, agentKeyFromSeed, parseCompactJws, renderHookOutput } =
  await import(built.href);

function readStdin() {
  try {
    return readFileSync(0, 'utf8');
  } catch {
    return '';
  }
}

let out;
try {
  const configPath = process.env.AM_HOOK_CONFIG;
  if (configPath === undefined) throw new Error('AM_HOOK_CONFIG is not set');
  const cfg = JSON.parse(readFileSync(configPath, 'utf8'));

  const raw = readStdin();
  const event = raw.trim() === '' ? {} : JSON.parse(raw);

  let store;
  if (cfg.store?.kind === 'sqlite') {
    const { SqliteStore } = await import(
      new URL('../dist/src/ledger/sql/sqlite.js', import.meta.url).href
    );
    store = new SqliteStore({ location: cfg.store.location });
  } else {
    // In-memory means every hook invocation starts with an empty ledger, so
    // budgets never actually accumulate. Fine for a smoke test, useless as a
    // control, and said out loud rather than left to be discovered.
    emit('am-hook: no durable store configured; budgets will not persist\n');
    store = new MemoryLedgerStore();
  }

  // §7 step 3: a ledger must be the one the chain names, so this cannot be an
  // arbitrary placeholder — `https://ledger.local` used to be, and would now
  // refuse every priced call against a mandate naming anything else. The chain's
  // own claim is the right default: this ledger is a local metering counter
  // whose identity is not independently meaningful, and the same config supplies
  // both halves, so requiring them to be typed twice protects nobody.
  // `ledgerUrl` stays available for a deployment where it is meaningful.
  const chainLedger = parseCompactJws(cfg.tokens?.[0] ?? '')?.payload?.ledger;

  const ledger = new Ledger({
    url: cfg.ledgerUrl ?? chainLedger ?? 'https://ledger.local',
    key: agentKeyFromSeed(Uint8Array.from(Buffer.from(cfg.ledgerKeySeed, 'hex'))),
    store,
    isTrustedRootIssuer: (iss) => iss === cfg.trustedRootIssuer,
  });

  const hook = new MandateHook({
    ledger,
    tokens: cfg.tokens,
    prices: cfg.prices ?? {},
    stateDir: cfg.stateDir,
    ...(cfg.taskId !== undefined ? { taskId: cfg.taskId } : {}),
    ...(cfg.onLedgerError !== undefined ? { onLedgerError: cfg.onLedgerError } : {}),
  });

  out = renderHookOutput(await hook.handle(event));
} catch (err) {
  // A broken hook must not be able to stop the session. Refusing on a
  // configuration mistake would make every tool call fail for a reason that has
  // nothing to do with spending — so this reports and gets out of the way, and
  // the deliberate fail-closed behaviour lives in `onLedgerError`, where it is
  // about the ledger rather than about this file.
  emit(`am-hook: ${err instanceof Error ? err.message : String(err)}\n`);
  process.exit(0);
}

if (out.stdout !== '') process.stdout.write(out.stdout);
if (out.stderr !== '') emit(out.stderr);
process.exitCode = out.code;
