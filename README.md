# agent-mandate

Reference implementation of the caveat lattice and chain verifier for the
**Agent Mandate Protocol v1** ([`spec/agent-mandate-v1.md`](spec/agent-mandate-v1.md)) —
delegated, attenuable, auditable spending authority for autonomous agents.

```bash
npm install && npm test
```

## What's here

| Module | Role |
|---|---|
| [`src/caveats.ts`](src/caveats.ts) | The registry, the partial orders, `narrows`, `meet`, `foldMeet` |
| [`src/verify.ts`](src/verify.ts) | Spec §7 chain verification |
| [`src/uri.ts`](src/uri.ts) | Canonicalization and decidable pattern containment |
| [`src/money.ts`](src/money.ts) | Exact decimal amounts to 9 dp; no floats anywhere |
| [`src/jws.ts`](src/jws.ts), [`src/didkey.ts`](src/didkey.ts) | Ed25519 JWS, `did:key`, RFC 7638 thumbprints |
| [`src/sign.ts`](src/sign.ts) | Issuer-side helpers, kept out of the verifier's dependency graph |
| [`src/ledger/ledger.ts`](src/ledger/ledger.ts) | §10 — reserve / settle / refund / revoke, path-walk debit |
| [`src/ledger/store.ts`](src/ledger/store.ts) | Persistence seam; in-memory reference impl with a real critical section |
| [`src/ledger/sql/sqlite.ts`](src/ledger/sql/sqlite.ts) | Durable store on `node:sqlite` — one writer, serialization for free |
| [`src/ledger/sql/postgres.ts`](src/ledger/sql/postgres.ts) | Durable store on Postgres — root-to-leaf lock order, retry on deadlock |
| [`src/ledger/breakers.ts`](src/ledger/breakers.ts) | §10.4 — velocity, burn rate, task ceiling, novel merchant, kill |
| [`src/ledger/reconciler.ts`](src/ledger/reconciler.ts) | §12.2.3 — resolve `settling`, escalate the undecidable, sweep the expired |
| [`src/spend.ts`](src/spend.ts) | §9 — spend token mint, and the five-check merchant verifier |
| [`src/receipt.ts`](src/receipt.ts) | §11 — canonical JSON, dual-signable receipts |
| [`src/http/signature.ts`](src/http/signature.ts) | RFC 9421 HTTP Message Signatures, Ed25519 |
| [`src/http/sfv.ts`](src/http/sfv.ts) | RFC 8941 Structured Fields (the dictionary subset) |
| [`src/http/merchant.ts`](src/http/merchant.ts) | §14 merchant side: 402 challenge, verify, admit |
| [`src/http/client.ts`](src/http/client.ts) | §14 agent side: parse challenge, sign, retry once |
| [`src/rail/rail.ts`](src/rail/rail.ts) | §12.2 — the custodial settlement seam, and atomic-unit conversion |
| [`src/rail/x402.ts`](src/rail/x402.ts) | Custodial x402 adapter (HTTP 402 + EIP-3009 on Base) |
| [`src/rail/noncustodial.ts`](src/rail/noncustodial.ts) | §12.4 — directives, rail capabilities, the non-custodial seam |
| [`src/rail/x402-noncustodial.ts`](src/rail/x402-noncustodial.ts) | Non-custodial x402: trustless oracle, hard expiry |
| [`src/rail/delegated-transfer.ts`](src/rail/delegated-transfer.ts) | Card/ACH-shaped rail: neither guarantee |
| [`src/chain/eip712.ts`](src/chain/eip712.ts) | EIP-712/3009 digests and secp256k1 recovery |
| [`src/chain/ethcall.ts`](src/chain/ethcall.ts) | `authorizationState` over JSON-RPC `eth_call` |
| [`src/agent/signer.ts`](src/agent/signer.ts) | Agent-side signer — policy-enforcing, key never leaves the closure |
| [`src/agent/directive.ts`](src/agent/directive.ts) | Verify a ledger directive, then sign it |
| [`src/stepup.ts`](src/stepup.ts) | §10.5 — decisions signed by the principal, terms restated inside the signature |
| [`src/control.ts`](src/control.ts) | §10.6 — signed kill / release / revoke, with a one-time nonce |
| [`src/http/approval.ts`](src/http/approval.ts) | The approval queue and approve/deny, framework-agnostic |
| [`src/http/console.ts`](src/http/console.ts) | §5.2 — the principal console: budget tree, spend feed, kill switch |
| [`src/mcp/gateway.ts`](src/mcp/gateway.ts) | MCP mandate gateway — a mandate per tool call, wrapped server unmodified |
| [`src/mcp/jsonrpc.ts`](src/mcp/jsonrpc.ts) | JSON-RPC 2.0 and the stdio framer, hand-rolled |
| [`src/mcp/stdio.ts`](src/mcp/stdio.ts) | stdio transport: spawn an upstream server, serve a client |

The split to keep in mind: **`verifyChain` decides whether a chain *may*
authorize a request. The `Ledger` decides whether the budget is still there.**
The first is stateless and offline-verifiable; the second is stateful and
necessarily online.

`Merchant` and the client are framework-agnostic — they take a request shape and
return a decision, so the same logic drops into Express, Hono, a Cloudflare
Worker, or an MCP server's tool dispatch without any of them being able to skip a
step. [`test/http.e2e.test.ts`](test/http.e2e.test.ts) drives the whole loop:
402 → reserve → signed retry → serve → settle → receipt.

## Usage

```ts
import { verifyChain, generateAgentKey } from './src/index.js';

const result = await verifyChain(chainOfJwsStrings, {
  now: Math.floor(Date.now() / 1000),
  request: {
    resource: 'https://api.weatherco.com/v3/forecast/94110',
    amount: { cur: 'USD', amt: '0.02' },
    purpose: 'research.readonly',
    taskId: 'tsk_01J8QQ...',
  },
  isTrustedRootIssuer: (iss) => iss === principalDid,
  presenterJkt, // from your RFC 9421 verification
});

if (!result.ok) return problemJson(result.code, result.detail);
// result.effective is the folded authority; hand it to the ledger to debit.
```

`verifyChain` returns a result rather than throwing. It runs on
attacker-controlled input on the spend path, and a thrown exception is one stray
`try/catch` away from being swallowed into an allow.

### Putting a mandate in front of an MCP server

The gateway is an MCP server to your client and an MCP client to the server it
wraps. **The wrapped server is not modified and does not know it is there.**

```ts
import { McpMandateGateway, StdioUpstream, serveStdio } from './src/index.js';

const broker = new StdioUpstream({ command: 'npx', args: ['-y', 'some-mcp-server'] });
await broker.start();

const gateway = new McpMandateGateway({
  ledger,                       // a Ledger over a durable store
  tokens: chainOfJwsStrings,    // the mandate this session spends against
  isTrustedRootIssuer: (iss) => iss === principalDid,
  taskId: 'tsk_01J8QQ...',      // optional: scope the budget to one task
  upstreams: [
    {
      name: 'broker',           // becomes the host of mcp://broker/<tool>
      server: broker,
      tools: {
        get_quotes:  { price: { cur: 'USD', amt: '0.001' }, effect: 'read' },
        place_order: { price: { cur: 'USD', amt: '0.001' }, effect: 'irreversible' },
      },
    },
  ],
});

serveStdio(gateway, { input: process.stdin, output: process.stdout });
```

Both tools cost a tenth of a cent, and a mandate carrying `effect: 'read'`
admits the first and refuses the second. That is the whole argument for a blast-
radius axis: price is not a proxy for consequence.

A tool with no entry in `tools` is not callable **and is not listed** — the
gateway will not price a call it cannot classify, and an agent cannot misuse a
tool it was never shown.

### Letting a human say no

A spend over `step_up.over` returns `step_up_required` with a handle. The handle
is the *question*; the answer is a JWS signed by the principal that restates the
terms, so the bytes signed are the terms agreed:

```ts
import { ApprovalService, signStepUpDecision } from './src/index.js';

// Mount anywhere; it carries no auth of its own, because the authority is the
// signature inside the decision, not reachability of the endpoint.
const approvals = new ApprovalService({ ledger, basePath: '/step-ups' });
const { stepUps } = (await approvals.handle({ method: 'GET', path: '/step-ups' })).body;

const decision = signStepUpDecision(
  {
    v: 'am/1', typ: 'approval',
    handle: stepUps[0].handle,
    iss: principalDid,
    verdict: 'approve',
    root: stepUps[0].root,
    res: stepUps[0].resource,
    amt: stepUps[0].amount,
    iat: now, exp: now + 900,
  },
  principalKey,          // the key that granted the mandate in the first place
);

await approvals.handle({
  method: 'POST',
  path: `/step-ups/${stepUps[0].handle}`,
  body: { decision },
});
```

The agent then retries and the spend goes through, once. Presenting the handle
without a decision does not work, and a decision signed by anything other than a
trusted root issuer does not verify — which matters, because the ledger hands
that handle to the agent.

### The principal console

```ts
import { ConsoleService } from './src/index.js';

const console_ = new ConsoleService({ ledger, basePath: '/console' });
// Mount console_.handle(req) on your server. It serves one static page and
// a small JSON API; the page has no build step and no dependencies.
```

Budget tree, spend feed, settlement state with escalations, the step-up queue,
and a button that halts the principal. Kill, release and revoke are **signed
decisions** (§10.6) checked against the root node's recorded issuer — so being
able to reach the endpoint is not being allowed to use it, which matters because
the network the kill switch most needs to be reachable from is the agent's.

Two things to know before mounting it:

- **Put the read side behind your own auth.** The feed and the tree disclose what
  an agent is spending, on what, and for whom — the org chart, effectively. The
  control side needs no auth because the authority is in the signature; the read
  side has no such excuse.
- **The page asks for your principal key.** It imports the JWK through WebCrypto
  as non-extractable, keeps it in a closure, and never persists or transmits it —
  but it is still a web form asking for a spending key, which is the gesture a
  phishing page wants to teach. Signing offline and POSTing the JWS to the same
  endpoints works identically, and is the right call if that trade bothers you.

### Running the reconciler

Paying is an external call, so it has a third outcome: neither settled nor safe
to refund. Those wait in `settling` until something asks the rail what happened.

```ts
import { Reconciler } from './src/index.js';

const reconciler = new Reconciler({
  ledger,
  stuckAfterSeconds: 900,   // no universal value — it depends on your rail
  intervalMs: 60_000,
  sweepLimit: 500,
  onEscalation: (e) => page(`${e.spendId}: ${e.amount.amt} ${e.amount.cur} to ${e.merchant}, stuck ${e.ageSeconds}s`),
  onPass: (p) => metrics.gauge('am.settling.outstanding', p.outstanding),
});

reconciler.start();
```

`outstanding` trending upward is the number to page on — it means a rail has
stopped answering and the ledger is accumulating money that is neither spent nor
available.

Escalation moves no money. The reservation stays `settling` and stays debited,
because it is there precisely because nobody knows whether the payment landed;
refunding on a timeout pays the merchant *and* hands the money back. If you want
an escalation to halt spending, call `ledger.setGlobalKill(root, true)` from
`onEscalation` — that is deliberately not the default, since one slow rail should
not be able to stop every agent under a principal.

## Three things the property tests found

The lattice looked clean on paper. Writing `fast-check` properties against it
surfaced four bugs, three of which were defects in the spec rather than in the
code:

**1. `⊑` is not transitive across links.** With `a = {settle: escrow_schema}`,
`b = {}`, `c = {settle: immediate}`: `b ⊑ a` holds, `c ⊑ b` holds, `c ⊑ a` does
not. A middle link that merely *omits* a caveat is ⊤ on that dimension, so a
grandchild can re-declare what its grandparent forbade while every parent-child
check passes. Verifiers must compare each link against the **accumulated meet**
of everything above it. See the regression test in
[`test/verify.test.ts`](test/verify.test.ts).

**2. `meet` was not commutative.** The meet of `task: t1` and `task: t2` is
neither operand — it is ⊥. Returning one of them made a chain's effective
authority depend on fold order. Same for cross-currency amounts, and for pattern
sets that cover each other without being equal.

**3. The depth decrement is not a lattice relation.** `child ≤ parent − 1` is not
reflexive, so it cannot live in the registry without breaking `meet` and every
algebraic law. It moved into the verifier as a structural counter.

The fourth was ordinary: `rate`'s meet tie-broke on argument order when two
windows had equal duration but different spellings (`PT60M` vs `PT1H`).

## Three things building the ledger exposed

**1. A `jti` can be re-issued to reset a budget.** The consumption counter is
keyed by `jti`. Nothing in the signature chain stops an issuer re-signing a
mandate that reuses a spent `jti` with a fresh `max_total` — every signature
valid, every caveat narrowing, budget back to full. The ledger now binds each
`jti` to the hash of the JWS that introduced it and rejects any later
presentation that disagrees. Spec §10.1.

**2. Replay-check ordering is load-bearing.** If a merchant records `jti` in its
replay cache before verifying the ledger's signature, anyone can burn a
legitimate spend by presenting a forgery carrying that `jti` — the real token
then bounces as a replay while the money is already debited. Signature and
audience first, always. Spec §9.2.

**3. Refunds must not credit rate counters.** Budget yes, rate no. A refunded
call still reached the merchant and consumed a request slot; restoring it turns a
consistently failing endpoint into an unlimited-rate endpoint, which is exactly
the retry storm the caveat exists to bound. Spec §12.1.

The concurrency properties in [`test/ledger.props.test.ts`](test/ledger.props.test.ts)
fire interleaved reserves and assert no path can be overdrawn. They matter
because `reserve` awaits chain verification before it debits, and anything after
an `await` can interleave — "Node is single-threaded" is not on its own a defence
against a double-spend.

## Two things building the HTTP layer exposed

**1. The spec's `Accept-Payment` example was not valid Structured Fields.** It
was written as a parameterized Item with `settle=("immediate" "escrow_schema")`,
but RFC 8941 parameter values cannot be Inner Lists. All three headers are now
Dictionaries. Also: `amount` is a String, never an sf-Decimal — decimals carry
three fractional digits and are floating point, and pricing runs below a tenth of
a cent.

**2. Verifying the spend token is necessary and not sufficient.** A merchant must
additionally check that the token's `res` matches the canonicalized request URI
and its `amt` matches the current price — otherwise a token minted for a cheap
endpoint pays for an expensive one inside its 60-second window. Spec §14.5.

A third, smaller one caught by the tests: header lookup has to be
case-insensitive. Node lowercases what it parses off the wire while a client
assembling a request writes `Payment`, so exact-match lookup produces a signature
that verifies in one direction and not the other.

## Settlement

The project was prompted by an [x402 storefront](https://x402.fablerlabs.com/) —
an autonomous agent-operated catalog paid with HTTP 402 + USDC on Base. x402
answers *how this agent pays for this request*. It does not answer *on whose
authority, up to what limit, and who eats the loss*. That gap is what this is.

The two compose. `SettlementRail` is the seam; `X402Rail` pays x402 **on the
agent's behalf**, so the storefront sees an ordinary x402 client and implements
nothing. The agent never holds the wallet, which is the point — a held wallet is
unbounded authority.

Nothing here performs live network or chain I/O: the signer and the transport are
both injected, and the tests replay a **byte-exact capture** of the storefront's
real 402 challenges ([x402-live.json](test/fixtures/x402-live.json), captured
2026-07-27). Wiring a real signer means supplying `viem` or `ethers` behind the
`Eip3009Signer` interface; the private key never enters protocol code.

Capturing that fixture invalidated almost every assumption in the first draft of
the adapter. x402 **v2** — which is what this storefront runs — differs from the
widely-documented v1 shape on nearly every field that matters:

| | assumed (v1) | actual (v2) |
|---|---|---|
| Challenge location | JSON response body | base64 `PAYMENT-REQUIRED` **response header**; body is always `{}` |
| Payment header | `X-PAYMENT` | `PAYMENT-SIGNATURE` |
| Price field | `accepts[].maxAmountRequired` | `accepts[].amount` |
| Network | `"base"` | `"eip155:8453"` (CAIP-2) |
| `resource` | string inside `accepts` | object at the top level |
| EIP-712 domain name | `"USDC"` | `"USD Coin"` |

That last one is the quiet one: `"USDC"` produces a signature that looks
completely valid and that the token contract will not accept. The adapter now
reads the domain from the challenge's own `extra` block rather than assuming it.
Both wire shapes are accepted on the read path.

The storefront declares **no settlement-receipt header**, so a bare 2xx is what a
successful payment looks like. Rather than treat that as unverifiable, the ref
falls back to `eip3009:{from}:{nonce}` — `(from, nonce)` uniquely identifies the
authorization and is checkable on-chain via `authorizationState()`, so it is a
real reconciliation key rather than a placeholder.

**Three things the rail forced into the design:**

**1. Rail failures have three outcomes, not two.** Success, *terminal* failure
(definitely did not transfer — refund the budget), and *indeterminate* (timeout,
5xx, unparseable — do **not** refund). Refunding on a timeout pays the merchant
and hands the money back to the agent; capturing on one charges for a request
that may never have been served. Reservations gained a `settling` state and the
ledger gained `reconcile()`.

**2. The idempotency key belongs on the rail, not in our books.** The EIP-3009
nonce is `sha256("am/1:x402:" + spendId)`, so a settlement retried after a crash
is deduplicated *by the token contract* regardless of what state our records
ended up in — a stronger guarantee than bookkeeping on this side of the wire can
provide.

**3. Precision does not round down.** Our amounts carry 9 decimals; USDC carries
6. `0.0000005` is a valid mandate price and unrepresentable on Base. Truncating
it to zero atomic units means the merchant serves the request free, forever, with
nothing reporting a problem — so it is a terminal failure instead.

## Non-custodial mode

The ledger can authorize without ever holding funds ([§12.4](spec/agent-mandate-v1.md)).
It issues a **Directive** naming exactly one payment the agent may execute with
its own key, records the commitment, and confirms the outcome against an oracle
rather than against the agent's word.

The limit is stated in the code as well as the spec, because it decides who the
product is for:

> **A non-custodial mandate cannot prevent a spend. It can only account for one.**

An agent holding its own key can always bypass the ledger. What you get is
detective control — every authorized transfer bound to a directive, every
unmatched outflow detectable. Selling that as prevention is how a principal sets
a budget they are not actually willing to lose.

**Rails declare what they can guarantee, and the ledger adapts.** Two ship, with
deliberately opposite capabilities:

| | `trustlessOracle` | `hardExpiry` | Unconfirmed past the deadline means |
|---|---|---|---|
| `X402NonCustodialRail` | yes — `authorizationState(from, nonce)` | yes — past `validBefore` the signature is dead | **refund**, soundly |
| `DelegatedTransferRail` (card/ACH-shaped) | no — a third party asserts it | no — settlement can arrive days late | **escalate**, never refund |

That second rail exists to keep the abstraction honest. If it only worked for
rails with chain-grade guarantees it would not be an abstraction, it would be
EIP-3009 with extra steps. Auto-refunding a card authorization that is merely
slow is a double-spend, so the ledger reads `hardExpiry` and refuses.

Three things worth knowing:

- **The ledger chooses the nonce**, deterministically from the spend id. That is
  what makes `confirm()` possible at all — §12.2.2 introduced it for idempotency,
  and non-custodial observability turned out to be the load-bearing reason.
- **The ledger never contacts the merchant.** The agent forwards the quote it
  already received. A dishonest quote is self-limiting: an inflated amount spends
  the agent's own funds, a redirected destination means the merchant never
  serves, and an unsigned directive simply expires and refunds.
- **`sweepExpired` refuses to touch a reservation carrying a directive.** An
  agent can execute and never report, so silence is not evidence of inaction —
  blind-refunding one hands back money that has already left the payer.

`payer` joins the caveat registry as a discrete equality caveat, shaped exactly
like `task`: pin it, never widen it, ⊥ on disagreement. It is how a parent hands
a subagent a small hot wallet without exposing the treasury account its own
mandate could otherwise reach.

### The chain seams are wired

`NobleEip712Verifier` and `EthCallChainReader` are real implementations, not
stubs. Elliptic-curve work goes to `@noble/curves` and keccak to
`@noble/hashes` — both audited, both tiny, and hand-rolling secp256k1 recovery
would be the single worst place in this codebase to write original code.
Everything else (struct hashing, ABI word packing, EIP-55) is deterministic
encoding with no secrets in it, so it is implemented directly.

Both are **verification-only**. No private key enters this codebase anywhere.

Four external vectors are asserted in [test/chain.test.ts](test/chain.test.ts),
because a digest that is merely self-consistent is a digest that is confidently
wrong:

| | |
|---|---|
| `keccak256("")` | `0xc5d2…a470` |
| `EIP712Domain` typehash | `0x8b73c3c6…400f` |
| `TransferWithAuthorization` typehash | `0x7c7c6cdb…2267` |
| `authorizationState` selector | `0xe94a0102` (derived, never hard-coded) |

**Validated against the deployed contract.** [test/chain.live.test.ts](test/chain.live.test.ts)
runs read-only `eth_call`s against Base mainnet — no key, no transaction, nothing
spent. Opt in with `LIVE_RPC=1`; skipped by default so CI never depends on a
public endpoint.

```bash
LIVE_RPC=1 npx vitest run test/chain.live.test.ts
```

The one that matters: USDC's `DOMAIN_SEPARATOR()` returns
`0x02fa7265…7834f`, and our locally computed `domainSeparator()` produces the
same value. That is the typehash, the string hashing, the ABI word packing and
the field order all confirmed correct against the real contract rather than
merely self-consistent. The contract also independently confirms
`name() == "USD Coin"` and `version() == "2"` — the values the live 402 capture
advertised, and the ones a hard-coded `"USDC"` would have gotten wrong.

Two behaviours worth calling out:

- **High-`s` signatures are rejected.** USDC's EIP-3009 verifies through
  OpenZeppelin's ECDSA, which refuses `s > n/2`. Accepting one here would settle
  a reservation in our books against a transfer the token contract can never
  execute.
- **Empty `eth_call` return data throws, it does not decode to `false`.** `0x` is
  what a call to a non-contract address returns, so reading it as "not consumed"
  would let one wrong token address quietly refund every payment ever made. The
  rail reports that as `unknown`, not `not_paid`.

## The agent-side signer

The only component here that can move money, and therefore the only one written
defensively against its own caller.

Non-custodial mode is worthless if the agent signs whatever the ledger sends — a
compromised or merely buggy ledger would then have exactly the custodial power
the design set out to remove. **The signer is the principal's last line of
defence**, so it re-derives everything and enforces its own limits. There is a
test asserting the signer vetoes a directive the ledger considered perfectly
fine.

Three rules it will not bend:

1. **It never signs an opaque digest.** The interface takes a structured domain
   and authorization and computes the hash itself. A signer that accepts a
   pre-computed digest can be handed the hash of a completely different
   transaction — `transfer(attacker, balance)` — and will authorize it.
2. **Policy is mandatory.** `maxPerTransfer`, `allowedAssets` and
   `allowedChainIds` are required; there is no default-open construction,
   because a signer with no limits is a hot wallet with extra steps.
3. **A nonce binds to one set of parameters, permanently.** Re-requesting the
   same nonce returns the identical signature; requesting it for a different
   destination or amount is refused outright.

Also enforced: value ceilings (per-transfer and cumulative), destination
allowlists, validity-window length, expiry both ways, and that the authorization
funds *this* signer's own address. `inspect()` reports what would happen without
consuming the nonce or the budget, and `onSign` / `onRefuse` hooks make both
outcomes observable rather than silent.

The private key lives in a `#private` field, and `toJSON` plus the Node inspect
hook are both overridden — there is a test asserting it appears in neither, nor
in a thrown `PolicyViolation`. `signerFromEnv()` exists and is documented as the
weakest acceptable option: environment variables leak into child processes and
crash reporters. Anything holding real value belongs behind a KMS or hardware
signer implementing `Eip3009Signer` directly, which is why that interface exists
at all — so the key never has to be in this process.

`executeDirective()` is the agent-side loop: verify the ledger's signature on the
directive, check it is bound to this agent and internally consistent, then sign.
It returns a refusal rather than throwing, because a policy veto is a normal
outcome mid-task and not a crash. **Signing and submitting are separate steps**,
so a signature can be produced, inspected and discarded with no chance it was
broadcast first.

## Testnet

The whole non-custodial flow runs against **Base Sepolia**, read-only, with a
freshly generated ephemeral key:

```bash
LIVE_RPC=1 npx vitest run test/testnet.live.test.ts
```

<sub>PowerShell: `$env:LIVE_RPC=1; npx vitest run test/testnet.live.test.ts`</sub>

```
  Base Sepolia dry run
    payer          0x5Cf14575B6D0c911Ba0c9560031469552a9183AF
    asset          0x036CbD53842c5426634e7929541eC2318f3dCF7e (USDC v2)
    signature      0xd95db4d388ece313b1830435…
    recovered      0x5Cf14575B6D0c911Ba0c9560031469552a9183AF
    on-chain used  false   <- nothing was broadcast
```

Reserve → directive → verify → sign → report → reconcile, with a genuine
EIP-3009 signature and live `eth_call`s to Base Sepolia. The run deliberately
does **not** broadcast, and the final assertion reads `authorizationState` from
the chain to prove it: the authorization is unused, so no value moved. That
assertion is only possible because signing and submitting are separate steps.

### The `name()` trap is inverted between networks

| | `name()` | address |
|---|---|---|
| Base **mainnet** | `"USD Coin"` | `0x8335…2913` |
| Base **Sepolia** | `"USDC"` | `0x036C…CF7e` |

Both read from the deployed contracts. A single hard-coded EIP-712 domain name
is therefore wrong on one network or the other, and the failure is silent — the
signature stays well-formed and the token contract simply refuses it. Testing on
Sepolia with the mainnet constant would fail confusingly; shipping to mainnet
with the Sepolia constant would fail expensively.

[`src/chain/networks.ts`](src/chain/networks.ts) holds the verified per-network
values, and the live tests re-read them from chain rather than trusting the
table. Adapters still prefer whatever the merchant's challenge advertises; this
is the fallback, and the reason that fallback cannot be a constant.

## Status

Not audited, not production-ready.

Ledger state is now durable — SQLite and Postgres, with the concurrency
properties run against real row locks rather than a `Map` — the MCP gateway puts
a mandate in front of real tool calls, a step-up needs a signature from the
principal rather than the handle the agent was just handed, a reconciler resolves
stuck settlements and escalates the ones it cannot, and the principal has a
console with a working kill switch. Still missing: a ledger *service*, and
conformance vectors a third party could run.

No payment has ever been made from this codebase and no funded key has ever been
loaded into it. Every network test is a read-only `eth_call` or a testnet
signature with an ephemeral key.

The caveat comparators are the part worth reviewing hardest — their semantics are
a wire-format commitment, and a mandate issued today has to verify identically in
30 days (spec §17.3).
