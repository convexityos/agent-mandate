# Working in this repo

**Read [`ROADMAP.md`](ROADMAP.md) first.** It is kept accurate, it records what
was found as well as what was built, and its "Where it stands" table is the
fastest way to know what exists.

## What this is

The **Agent Mandate Protocol (`am/1`)** — a control plane for delegated,
attenuable, auditable spending authority for autonomous agents. It sits *above*
payment rails (x402, cards) rather than beside them: it answers "on whose
authority, up to what limit, and who eats the loss", which rails do not.

[`spec/agent-mandate-v1.md`](spec/agent-mandate-v1.md) is normative. The code is
the reference implementation of it, and where the two disagree that is a bug in
one of them worth naming explicitly rather than papering over.

## Commands

```bash
npm test                          # 377 tests
npx tsc -p tsconfig.json --noEmit # typecheck
```

17 further tests need Postgres and 10 are live-network, both opt-in:

```bash
docker run --rm -d --name am-ledger-pg -p 15432:5432 -e POSTGRES_PASSWORD=am postgres:16-alpine
```

Then `PG_URL=postgres://postgres:am@localhost:15432/postgres npx vitest run`.
Port 15432 rather than 55432: Windows reserves ranges in the 55xxx band for
Hyper-V and the bind failure reads like a permissions problem. `LIVE_RPC=1`
enables the read-only Base mainnet and Base Sepolia tests.

## Safety posture — carry this forward

**No payment has ever been made from this codebase, no funded key has ever been
loaded into it, and the user has not authorized either.** Everything to date is
read-only `eth_call` plus ephemeral and testnet keys. The agent signer will
happily sign for Base mainnet if pointed there; its mandatory policy allowlist is
the only thing between it and a live transfer. **Ask before anything that could
move value.** Testnet before mainnet, always.

## Before touching `src/caveats.ts`

Spec §17.3 governs everything: caveat lattice semantics are a wire-format
commitment, and a mandate stored for 30 days must verify identically on day 30.
Adding a caveat is free. Changing what an existing comparator *means* is a
security regression no version bump retroactively fixes for credentials already
in the wild. Review any diff against that sentence before reviewing it for
anything else.

Several correctness rules are non-obvious and were found by property tests rather
than by reading code — `narrows` is not pairwise transitive, `foldMeet` is
load-bearing rather than defensive, settlement failures have three outcomes
rather than two, and refunds credit budget but not rate counters. The comments at
each site explain why; they are load-bearing documentation, not decoration.

## How this codebase expects to be worked on

Four of the most valuable findings so far were not missing features. They were
**things that existed and did not work**, each found by building the component
that finally used it:

- `SELECT … FOR UPDATE` locks nothing when the row is absent, and a mandate's
  first spend has no row.
- `step_up_required` handed the agent a handle and accepted it back as approval.
- `settlingSince` was written since the state was invented and read by nothing.
- `setGlobalKill` and `revoke` took no credential.

So: when a component claims a guarantee, check that something enforces it. When a
field exists, check that something reads it. And when a test passes, it is worth
asking whether it would fail if the thing under test were broken — several fixes
here were confirmed by reverting them and watching the suite go red.

Prefer stating a limitation plainly over engineering around it. The README status
line, the "preventive control only over a channel" note on the MCP gateway, and
the "this page asks you to paste a spending key into a web form" warning on the
console are all examples of the house style.
