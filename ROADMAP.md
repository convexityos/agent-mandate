# Roadmap

This began "the protocol is largely done, the system does not exist", ordered
against a README status line that read *not audited, not production-ready, **no
ledger***.

The system exists now. State is durable and the concurrency properties run
against real row locks; a gateway puts a mandate in front of real tool calls; a
reconciler resolves what settles and escalates what will not; and the principal
has a console with a working kill switch. Still not audited, still not
production-ready, and no payment has ever been made from it.

What is worth recording is that the three biggest findings in this document were
not features that were missing. They were **things that existed and did not
work** — a `settlingSince` nobody read, a step-up an agent could approve for
itself, a `FOR UPDATE` that locked nothing on a mandate's first spend. Each was
found by building the thing that finally used it, which is the argument for the
ordering below rather than for any particular item in it.

## Where it stands

| | Built | Missing |
|---|---|---|
| Semantics | full §6.2 comparator table incl. the `effect` axis, `meet`, `narrows`, pattern containment | — |
| Verification | §7 chain verification against the accumulated meet, 52 published conformance vectors | — |
| Ledger | reserve / settle / refund / revoke / reconcile, path-walk debit, breakers, step-up, durable store, reconciler, HTTP service | — |
| Settlement | custodial + non-custodial x402, card/ACH-shaped rail, EIP-712/3009, `authorizationState` | escrow (deliberately — see triage) |
| Transport | §14 binding, merchant verifier, agent client | a `fetch` anyone would actually import |
| Agents | signer, directive execution, MCP mandate gateway | harness integration |
| Humans | signed step-up and control decisions, approval queue, principal console | — |

The pattern: every seam is defined and every seam terminates in an in-memory
reference implementation or an unanswered call.

---

## 1. Make it a system

### 1.1 Durable store — **done**

[`src/ledger/store.ts`](src/ledger/store.ts) documents exactly what a SQL
implementation must do: map `transact` onto one transaction, take
`SELECT … FOR UPDATE` on the path's nodes **in root-to-leaf order**, and it
explains why the ordering is load-bearing rather than cosmetic (every spend under
a principal touches the same root row, so paths overlap constantly and mixed lock
order deadlocks under normal traffic, not adversarial traffic).

Then it shipped a `Map`. Both stores now exist:

- [`SqliteStore`](src/ledger/sql/sqlite.ts) — single-writer, trivial
  serialization, right for local dev and the CLI.
- [`PostgresStore`](src/ledger/sql/postgres.ts) — the real one. Root-to-leaf lock
  ordering, a retry policy for deadlock and serialization failure.

Two things had to change to get there, both of them findings rather than
plumbing:

- `LedgerTx` was synchronous. The file's own comment described a SQL
  implementation that its type signature forbade, since every read over a socket
  is a round trip. It is async now, and `lockPath` replaced the hand-rolled
  ancestor walks so the lock ordering is a property of the store rather than of
  the direction two `for` loops happen to run in.
- Nodes are locked by key, not by row. `SELECT ... FOR UPDATE` on a row that does
  not exist locks nothing, and a mandate's *first* spend has no row — so two
  concurrent first spends would each read `spent = 0`, and the second would
  overwrite the first's debit rather than add to it. Overdraw, on the first two
  calls against any new mandate.

The concurrency properties in [`test/store-suite.ts`](test/store-suite.ts) run
once per store, alongside a conformance suite that pins the behaviour the ledger
silently depends on. Against the `Map` they prove the promise-chain critical
section holds; against Postgres, where each caller has its own connection, they
prove the locks and their ordering do.

Everything else in this document assumes state survives a restart. It does.

### 1.2 Ledger service — **done**

[`src/http/service.ts`](src/http/service.ts) over the existing objects, plus a
`node:http` binding in [`serve.ts`](src/http/serve.ts) so it is a daemon rather
than a library. All three of the things that get written last:

**Idempotency is inside the transaction, not around it.** `Idempotency-Key`
passes through to `Ledger.reserve`, which claims the key in the *same*
transaction as the debit. A service that claimed, called, then recorded has
three failure windows — crash before and the key is stranded so the caller can
never learn the outcome, crash after and the retry debits twice, and two
concurrent first uses race unless the claim itself is atomic. Which is the dual-
write problem this ledger already solved once for settlement, so it gets the same
answer.

Two details that matter more than they look:

- A key reused with a *different* request is refused, not answered with the
  earlier result. Silently returning the first response is worse than either
  debiting or failing — the caller believes something went through that never
  did.
- A refusal is recorded too, including `step_up_required`, where a replay must
  return the same handle rather than queue the question twice. A retry asks "did
  my request go through?", and "yes, and it was refused" is an answer.

**The audit log is emitted by the ledger, not the service.** The transitions that
matter most are the ones the reconciler makes at 3am with no request to attribute
them to, and a service-level log cannot see those. Events are flat, keyed by
`spendId`, emitted after commit — an event describing a change that rolled back
is what makes a log untrustworthy — and a throwing sink is swallowed, because a
failing log must not turn a completed spend into an error the caller retries.

Writing the tests found the gap: §7 refusals never reached the log at all,
because `reserve` returns before it opens a transaction. A request outside the
grant is the *most* common refusal and the one an incident asks about first.

**`am_settling_outstanding` is the number to page on.** It is money that is
neither spent nor available, and it trending upward means a rail has stopped
answering.

Not built here, deliberately: the service does not authenticate the presenter.
§7 step 9 needs a thumbprint the transport already verified, so `presenterJkt` is
an input via `resolvePresenter`, and `requirePresenter` defaults to on so
disabling proof-of-possession has to be a choice rather than an omission.

### 1.3 Reconciler — **done**

[`src/ledger/reconciler.ts`](src/ledger/reconciler.ts). Ask the rail, escalate
what it cannot resolve past a configured age, sweep what expired unredeemed,
report what is still outstanding. On a timer, with an overlap guard, and a
throwing rail degrades a pass rather than ending it.

What building it exposed: **`settlingSince` was written since the state was
invented and read by nothing.** The custodial `reconcile()` answered
`still_unknown` forever and told no one — open question 8's "silence is the wrong
default" was a literal description of the code. The field existed for
stuck-payment alerting; nothing alerted.

Three things worth keeping:

- **Escalation moves no money.** The reservation stays `settling` and stays
  debited. It is there because nobody knows whether it landed, and §12.2.1 is
  already emphatic that guessing costs a double-spend or a stranded balance.
  Escalation changes only who knows.
- **Ask before escalating.** A reservation the rail resolves on this pass is
  never escalated, so a human is only interrupted for something genuinely
  undecidable.
- **Non-custodial escalation is not a clock.** §12.4.5 escalates on the rail's
  declared capabilities, and from `reserved` rather than `settling` — an agent
  can execute a directive and never report. A reconciler that only reads the
  `settling` queue misses them entirely, which is a bug this one had until a
  test caught it.

Open question 8 is answered in spec §12.2.3: the duration stays deployment
policy, the requirement to have one does not.

### 1.4 CLI — **done**

[`src/cli/`](src/cli/) — `am keygen | mint | attenuate | verify | inspect |
replay`. No dependencies, `--json` on everything, and `run()` is exported so the
tests drive it directly rather than spawning a process per assertion.

`am inspect` was the justification, and it delivers. On the grandchild-escape
chain:

```
  [1] mnd_a   …qVBiyH → …rHPrf2
      declares  max_total 10.00 USD
      meet      aud *.weatherco.com · max_per_txn 1.00 USD · max_total 10.00 USD
                settle escrow_schema
      inherits  aud, depth, max_per_txn, settle

  [2] mnd_b   …rHPrf2 → …wT9TUP
      declares  settle immediate
      meet      … settle escrow_schema
      ✗ attenuation_violation against the accumulated meet
```

The middle link *inherits* `settle`; the next one re-declares it. Printed beside
each other, that is a thing you notice rather than a thing you derive — which
was the claim.

Two additions beyond the listed five:

- **`keygen`**, because `mint` needs a key and there was no way to make one.
  Writes 0600 and says out loud that anything holding it can issue mandates.
- **`replay`** turned out to mean the stateful counterpart to `verify`. `verify`
  answers whether a chain *may* authorize a request; it structurally cannot
  answer whether the budget is still there, because `max_total` and `rate` are
  consumption state. `replay` runs a sequence of requests against a throwaway
  in-memory ledger, so "what will this mandate actually let through" has an
  answer that does not require deploying anything.

One thing worth keeping from building it: `replay` first reported the *root's*
remaining after each spend, which put `90 USD left` directly above
`budget_exhausted` and read as a contradiction. It reports the **binding** node —
the tightest budget on the path — because that is the number that governs.

---

## 2. The agentic wedge

Section 1 makes it work. This section is why anyone uses it.

### 2.1 MCP mandate gateway — **done**

[`src/mcp/`](src/mcp/) — an MCP server to the client, an MCP client to each
server it fronts, a mandate in between. Price and `effect` per tool, `resources`
patterns over `mcp://server/tool`, budget optionally scoped to a task. The
wrapped server implements nothing, which is the same zero-integration wedge that
made paying x402 *on the agent's behalf* the right call, pointed at the ecosystem
agents actually run in.

Unlike the non-custodial rail this is a **preventive** control: the gateway is on
the call path, so a refusal is a call that does not happen. That holds exactly as
long as the client reaches the upstream only through the gateway — a client with
the server also configured directly has routed around it. The gateway constrains
a channel, not an agent.

Two decisions worth keeping:

- **`tools/list` is the mandate, rendered.** Unpriced and unpermitted tools are
  not listed, not merely refused. On a 140-tool session an agent cannot misuse
  what it was never shown, and every tool listed carries its price and effect in
  the description so the model can budget instead of discovering limits by being
  refused.
- **A failed tool does not simply refund.** MCP signals tool failure two ways —
  a JSON-RPC error, or a result with `isError: true` — and neither proves the
  call had no effect. So: a failed `read` refunds, a failed `write` or
  `irreversible` *settles*, and a transport failure holds the reservation for
  reconciliation. This is the §12 three-outcome rule reappearing one layer up.
  Refunding a failed order is how an agent retries a trade it already placed.

The motivating example stopped being hypothetical while this was being written:
the session that built it was itself carrying `place_equity_order`,
`place_option_order` and `flatten_and_go_short`, with nothing in front of them.

### 2.2 `mandatedFetch()`

[`src/http/client.ts`](src/http/client.ts) has the loop. Nobody wants to assemble
it. One import, drop-in for `fetch`, handling 402 → present → mint → sign →
retry, returning a refusal rather than throwing on policy veto.

Adoption is an ergonomics problem now, not a protocol problem. Merchant-side
conformance is five checks by design (§1.1); agent-side should be one line.

### 2.3 Harness integration

A `PreToolUse` hook for Claude Code / the Agent SDK that reserves against a
mandate before a priced tool fires and refunds when it fails. Small, and it makes
the control plane something that runs in the loop you already use rather than
something you demo.

### 2.4 A capability axis in the registry — **done**

`effect` over `irreversible ⊐ write ⊐ read`, ordered so a child may narrow toward
`read` and never widen — structurally identical to `settle`, so the existing
lattice property tests cover it by construction once it is in the generator.

Landed as one change per §17.3: registry entry, comparator, `meet`,
`RequestContext.effect`, the `effect_not_permitted` check in §8 coverage, the
spec table, and the error code. Purely additive, and the "a mandate issued before
`effect` existed verifies exactly as before" case is pinned by a test rather than
asserted.

One consequence to keep in view: absence is ⊤, so a mandate that omits `effect`
grants `irreversible`. That uniformity is what the whole algebra rests on and is
not special-cased. Deciding what an *unclassified tool* may do is an
enforcement-layer question, and the gateway answers it by refusing to price a
call it cannot classify.

---

## 3. Adoption and trust

### 3.1 Conformance vectors — **done**

[`vectors/`](vectors/) — 52 vectors across §7 chain verification, §6 the lattice
and §6.4 URI handling, generated by
[`test/vectors.build.ts`](test/vectors.build.ts) and committed.

The discipline that makes them worth anything: **every expectation is written by
hand from the spec, never recorded from the implementation.** Vectors snapshotted
from a reference implementation cannot disagree with it, so they encode its bugs
as conformance requirements and certify future implementations for reproducing
them. `test/vectors.test.ts` then runs all of them and asserts the hand-written
verdict, so a disagreement means one of the two is wrong.

Six disagreements turned up. All six were errors in the vectors rather than in
the code, and two were worth keeping as vectors in their own right — an encoded
slash is *not* a path separator and must stay encoded, and a child claiming a
longer `exp` than its parent is rejected outright rather than silently clamped.

They have teeth, which was checked rather than assumed. Swapping the verifier to
compare each link against its immediate parent — the natural-looking
implementation — fails exactly the two grandchild-escape vectors and nothing
else. Reordering canonicalization to resolve dot-segments before decoding fails
exactly the vector that names it.

Two places the spec turned out not to be normative enough, both recorded in
[`vectors/README.md`](vectors/README.md): §8 rule precedence when a request
violates several coverage rules at once, and the fact that reserved characters
staying percent-encoded looks like a bug until you see why it is not.

The vectors deliberately stop at stateless verification. `max_total` and `rate`
are ledger state, and a vector for them would have to ship an initial and
expected ledger — a different, larger format.

### 3.2 Revocation distribution

§10.3 revokes in the ledger's own state and nothing propagates it. Online mode
tolerates that because the ledger is on the spend path; offline mode (§13) does
not, and bounds revocation only by `exp` — which is the stated justification for
the one-hour cap.

A bitstring status list is the standard answer and is roughly a day's work.

### 3.3 Threat catalog

§16 is prose. The `jti` re-issue finding and the replay-ordering finding show the
format that actually works: the attack, why it succeeds, the check that stops it,
the test that proves the check. One entry per attack, each with a test id.

---

## 4. Open questions — triage

Numbering follows §18.

| # | Question | Call |
|---|---|---|
| 3 | Quote binding | **Build.** Tractable, closes a real hole, and [`x402-live.json`](test/fixtures/x402-live.json) already holds the challenge bytes to bind against. |
| 6 | AP2 / ACP interop | **Build.** The spec calls an adapter tractable and worth prototyping early; it is the clearest evidence this sits *above* rails rather than beside them. |
| 5 | Privacy of `path` in receipts | **Build.** Receipts currently hand the org chart to anyone who reads one, which undercuts the privacy claim in §1.1. Salted-hash form preserves rollup; accept the audit cost. |
| 9 | Co-signed spend accounts | **Design now, build deliberately.** The only route from detective to preventive control without custody — session keys plus a timelock for unilateral principal withdrawal. Needs a contract and an audit, so it is not a sprint. |
| 8 | Reconciliation cadence | **Answered.** §1.3 built; spec §12.2.3 written. |
| 1 | Cross-ledger delegation | **Defer.** Inter-ledger consumption accounting is a second system. The §7 "all links agree on `ledger`" rule is a fine answer for now. |
| 10 | Non-EIP-3009 rails | **Defer.** [`DelegatedTransferRail`](src/rail/delegated-transfer.ts) already keeps the abstraction honest by declaring neither guarantee. |
| 4 | Human-to-human sub-delegation | **Defer.** Product and regulatory question, not a technical one. |
| 2, 7 | Escrow | **Leave alone.** The spec is honest that this is the largest unresolved gap, and every path through it ends with the ledger holding the float — becoming a custodian, with everything that implies. |

---

## 5. The missing human

### 5.1 Step-up loop — **done**

This was written as "the ledger side is already built; this is the other half of
an existing protocol feature". That was wrong, and the way it was wrong is the
most useful thing this item produced.

`step_up_required` minted a handle, handed it to the agent in the error response,
and accepted it back on the retry. There was no approval state — the record was
created already-valid. So **an agent that could read its own error response could
approve its own spend**, and `step_up` is the only mechanism in the protocol for
keeping a high-value transaction attended. It bound the retry to one root,
resource, currency and amount, and stopped replay. It did not require a human.
The test asserting the old behaviour called re-presenting the handle "once
approved".

What landed:

- **A state machine.** `pending → approved | denied`, and only `approved` admits
  a spend. Requests for identical terms collapse onto one handle, because §10.5
  has the agent polling and a question asked once per poll is a queue nobody
  reads.
- **Signed decisions** ([`src/stepup.ts`](src/stepup.ts)). A decision is a JWS
  from the mandate's trusted root issuer — the same key that granted the
  authority is the one that may exceed its threshold, so no new trust root. It
  **restates the terms** (`root`, `res`, `amt`) and the ledger re-checks them,
  because a signature over a bare handle attests only that the principal saw an
  opaque string.
- **An `Approver` seam**, notified after commit rather than inside the critical
  section, and unable to decide anything itself — an approver that could approve
  would put the decision back inside the ledger's own trust boundary.
- **An HTTP surface** ([`src/http/approval.ts`](src/http/approval.ts)),
  framework-agnostic like the merchant side, carrying no auth of its own on
  purpose: the authority is the signature inside the decision, so exposing it to
  the agent's own network is safe in a way a bearer secret is not.
- **Gateway wiring.** A step-up is reported as `awaiting_approval` rather than
  `denied` — one is a question, the other is a no, and collapsing them teaches an
  agent to abandon a spend that was about to be approved.

### 5.2 Principal console — **done**

[`src/http/console.ts`](src/http/console.ts) and a single static page in
[`console-page.ts`](src/http/console-page.ts): budget tree, spend feed,
settlement state with escalations, the step-up queue, and a button that stops
everything. No build step, no dependencies, one `overview` call so every panel
renders from the same instant.

Building it turned up more protocol than page:

- **`setGlobalKill` and `revoke` had no credential.** Fine while the only caller
  was code inside the deployment; not fine once a console puts them on a network
  whose most likely other occupant is the agent the kill switch exists to stop.
  They are signed decisions now (§10.6), with a **durable one-time nonce** —
  unlike a step-up decision there is no handle to bind replay to, and a captured
  `release` would otherwise sit and wait for the next incident.
- **Nodes did not record who issued them.** `isTrustedRootIssuer` answers "is
  this DID a principal we trust", not "is this DID *this subtree's* principal",
  so on a ledger serving two principals either could halt or revoke the other's
  mandates. `MandateNode.issuer` closes it, and a control action is checked
  against the root node's issuer rather than merely against the trust list.
- **The page computed ages against the reader's clock.** Caught by looking at it
  rather than by a test: the feed rendered "-919s ago". The ledger's clock is
  authoritative and may run on a skew, so the overview now carries `now` and
  every age is relative to that.

The key story: the page imports the principal's JWK through WebCrypto as
**non-extractable**, holds it in a closure variable, and never persists it. That
was verified in a real browser — signatures from `crypto.subtle` verify against
the Node-side verifier, and `exportKey` on the imported key throws
`InvalidAccessError`. It is also, plainly, a page that asks a human to paste a
spending key into a web form. A principal who would rather not is right to sign
offline instead; the endpoints take a JWS from anywhere.

---

## Recommended sequence

1. ~~**[§1.1] Postgres store**~~ — done. A ledger that cannot be overdrawn after a restart.
2. ~~**[§2.1] MCP mandate gateway**~~ — done, with **[§2.4]** the `effect` axis under it.
3. ~~**[§5.1] Step-up loop**~~ — done. A human who can say no, and whose yes is a signature.

That order was not arbitrary, and running it in that order is what made the
step-up hole visible: the gateway put real tool calls in front of the ledger, and
a spend that needed a human was the first thing to walk straight through.

All three exist, and §1.3 and §5.2 with them. §5 is closed: the principal is no
longer the only party in the protocol without an interface.

**Section 1 is complete.** The honest shortlist from here is §2.2/§2.3
(`mandatedFetch` and the harness hook, both small and both pure adoption), §3.2
(revocation distribution, roughly a day's work and the thing offline mode
currently bounds only by `exp`), and §3.3 (the threat catalogue, which is the
last piece of §3 and now has a conformance suite to point its entries at).

One thing this pass exposed that is not on the list anywhere: **there is no
migration story.** `CREATE TABLE IF NOT EXISTS` does nothing to a table that
already exists, so the §10.5 columns would have hard-failed every deployment that
predated them. Both SQL stores now apply additive columns idempotently, which is
a stopgap and not a framework — no version table, no rename, no backfill. The
next schema change that is not purely additive needs one.

Two deliberately excluded from the sequence:

- **Escrow**, for the reasons in the triage table.
- **The Optera product page**, deferred at the user's request until the platform
  is worth linking to. It must match the shared design system in `C:\dev\optera`
  — cool near-black ground, cobalt accent, static HTML, no build step — and
  should be modeled on the existing product pages.

## The constraint that outranks everything here

§17.3, restated because it governs every item above:

> The caveat lattice semantics are a wire-format commitment. A mandate issued
> under `am/1` and stored for 30 days must verify identically on day 30.

Additive changes are free. Changing what an existing comparator means is a
security regression that no version bump retroactively fixes for credentials
already in the wild. Any proposal that touches [`src/caveats.ts`](src/caveats.ts)
gets reviewed against that sentence before it gets reviewed for anything else.
