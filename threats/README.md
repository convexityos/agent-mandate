# Threat catalogue

Spec [§16](../spec/agent-mandate-v1.md) is an index: attack, mitigation. This is
the long form, one entry per attack, in the shape that turned out to be the
useful one — **the attack, why it works against the obvious implementation, the
check that stops it, and the test that proves the check runs.**

The third column is the one worth having. Knowing that a `jti` must be bound to
its JWS hash is much less use than knowing what happens if it is not, so the
entries below try to state the failure rather than restate the rule.

The fourth is the one that keeps this file honest. Every test named here is
checked mechanically by [`test/threats.test.ts`](../test/threats.test.ts) —
rename or delete one and the suite fails — because three of the four most
valuable findings in this project were mitigations that **existed and did not
work**, and a catalogue that cannot tell the difference is worse than no
catalogue at all.

57 entries. 56 cite at least one test; 1 cannot, and 4 carry a stated gap. Those are listed first, because an unproven mitigation is what this document exists to surface rather than to bury.

Generated from [`test/threats.build.ts`](../test/threats.build.ts) by `npm run threats`.

## Where the defence is partial or absent

- **Agent bypasses the Ledger entirely** <sub>`agent-bypasses-the-ledger`</sub> — Detective only, and the reconciliation it depends on is not implemented here — `DelegatedTransferRail` declares the weaker guarantees, but nothing in this repo watches a payer account. Stated rather than engineered around.
- **Cross-merchant parallel spend** <sub>`cross-merchant-parallel-spend`</sub> — Bounded, never prevented — that is what §13 buys and it is the whole trade. `offlineRiskBudget` computes the figure §13 says MUST be surfaced to the principal, but nothing in this repo *tracks* live offline grants to feed it, and the 60-second reporting requirement is not enforced anywhere either. A deployment has to wire both.
- **Reaching the upstream server without the gateway** <sub>`routing-around-the-gateway`</sub> — Structural, not fixable inside the gateway. A deployment that needs this guarantee needs egress control or a sandbox, which this project does not provide and does not claim to.
- **Ledger compromise** <sub>`ledger-compromise`</sub> — Full compromise of the principal's funds, stated as residual risk in §16 rather than mitigated. Nothing in this repo enforces HSM-backed keys or runs the independent reconciliation that would detect it.

## Entries

### Unknown-caveat bypass

<sub>`unknown-caveat-bypass` · §6.3 · preventive control</sub>

**The attack.** Issue a mandate carrying a caveat key the verifier does not recognize, so the restriction it names is silently not enforced.

**Why it works.** A verifier that skips keys it does not know treats an unknown restriction as no restriction. The mandate looks tighter than it is to a human reading it, and looser than it reads to the code enforcing it.

**The check.** The registry is pinned by `v`. An unregistered key rejects the whole chain rather than being ignored, and the same rule applies inside `narrows` so a comparison involving an unknown key cannot return "narrower".

**Where.** [`src/caveats.ts`](../src/caveats.ts)

**Proven by.** [`test/caveats.test.ts`](../test/caveats.test.ts) — *fails closed on unregistered keys*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *rejects an unregistered caveat key anywhere in the chain*<br>[`test/props.test.ts`](../test/props.test.ts) — *an unregistered caveat key rejects the whole comparison*

---

### Grandchild escape past an omitted caveat

<sub>`grandchild-escape` · §7 · preventive control</sub>

**The attack.** A middle link omits a caveat the root declared; the grandchild re-declares it wider. Every parent-child pair narrows, so pairwise checking admits the chain.

**Why it works.** Absence is ⊤. A link that simply says nothing about `settle` is unconstrained on that axis, so `escrow_schema → (omitted) → immediate` narrows at every step and widens overall. `narrows` is **not** pairwise transitive, which is the single least obvious thing about the lattice.

**The check.** Each link is compared against the **accumulated meet** of everything above it, not against its immediate parent. Folding as the walk proceeds makes the relation transitive by construction and rejects the escape at the link that attempts it.

**Where.** [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *blocks the grandchild escape that pairwise checking would allow*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *blocks the same escape on resources*<br>[`test/props.test.ts`](../test/props.test.ts) — *narrows is NOT pairwise transitive — an omitted caveat is ⊤*<br>[`test/props.test.ts`](../test/props.test.ts) — *narrowing against the accumulated meet IS transitive*

---

### Widening by omitting a caveat

<sub>`omitted-caveat-widening` · §6.1, §7 · preventive control</sub>

**The attack.** Drop a caveat in a child mandate and hope the verifier reads absence as "unbounded".

**Why it works.** Absence *is* ⊤ in the wire format — that uniformity is what the algebra rests on. What must not follow is that the effective authority forgets what an ancestor said.

**The check.** The effective authority is the meet of the whole chain, so an omitted caveat is re-applied from above. A post-condition then re-checks that the fold narrows every individual link, turning a bug in `narrows` or `meet` from a silent escalation into a rejected chain.

**Where.** [`src/caveats.ts`](../src/caveats.ts), [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *re-applies a caveat the child omitted*<br>[`test/props.test.ts`](../test/props.test.ts) — *a child cannot escape a parent caveat by omitting it*<br>[`test/props.test.ts`](../test/props.test.ts) — *extending a chain never increases effective authority*

---

### Pattern widening via encoding

<sub>`pattern-widening-via-encoding` · §6.4 · preventive control</sub>

**The attack.** Write a resource pattern or a request URI so that two strings compare as different but resolve to the same resource — percent-encoding, dot segments, case, default ports.

**Why it works.** Comparing raw strings makes the grant depend on spelling. `%2e%2e/` looks like an ordinary path segment until something decodes it, and a verifier that resolves dot segments *before* decoding lets `/a/%2e%2e/b` escape a prefix it was supposed to be inside.

**The check.** Canonicalize before comparing, and in the order that matters: decode first, then resolve dot segments. Patterns use a restricted grammar with no regex, so containment is decidable rather than approximate. An encoded slash stays encoded, because it is not a path separator.

**Where.** [`src/uri.ts`](../src/uri.ts)

**Proven by.** [`test/uri.test.ts`](../test/uri.test.ts) — *decodes percent-escaped dot segments BEFORE resolving them*<br>[`test/uri.test.ts`](../test/uri.test.ts) — *rejects regex-ish and multi-wildcard patterns*<br>[`test/uri.test.ts`](../test/uri.test.ts) — *prefix matching does not leak across sibling paths*<br>[`test/props.test.ts`](../test/props.test.ts) — *canonicalization is idempotent and never yields a traversal*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *rejects a resource outside the grant, including via traversal*

---

### Injecting an unrecognized top-level claim

<sub>`claim-injection` · §5.1 · preventive control</sub>

**The attack.** Add a top-level claim the verifier does not know, hoping it is ignored or acted on.

**Why it works.** Anything a verifier ignores is a place to hide meaning that a *different* verifier might honour, and the two disagree about what the same bytes authorize.

**The check.** Unknown top-level claims reject the chain, exactly as unknown caveats do.

**Where.** [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *rejects unknown top-level claims*

---

### Cross-currency comparison

<sub>`cross-currency-comparison` · §6.2, §15 · preventive control</sub>

**The attack.** Present a request in a currency the mandate does not name and hope a comparison returns a convenient answer.

**Why it works.** Comparing `5.00 USD` against `5.00 EUR` has no correct numeric answer, and a comparator that returns a boolean has already given the wrong one. Returning `false` for "not narrower" reads as a violation; returning `true` grants across currencies at an implied rate of 1.

**The check.** Cross-currency comparison is a typed failure — `currency_mismatch` — not a boolean. No conversion is ever implied.

**Where.** [`src/money.ts`](../src/money.ts), [`src/caveats.ts`](../src/caveats.ts)

**Proven by.** [`test/money.test.ts`](../test/money.test.ts) — *fails closed across currencies rather than returning false*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *rejects a request denominated differently from the mandate*

---

### Algorithm confusion

<sub>`algorithm-confusion` · §4.1 · preventive control</sub>

**The attack.** Present a token whose header names an algorithm that turns a public key into a verification secret, or `alg: none`.

**Why it works.** The whole JWT algorithm-confusion family comes from one mistake: letting `alg` *select* the key or the implementation. If the header can choose, the attacker chooses.

**The check.** A static allowlist of one algorithm. The key comes from the resolver; `alg` only has to agree with it, and never selects anything.

**Where.** [`src/jws.ts`](../src/jws.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *rejects alg:none and unsigned tokens*

---

### Stolen mandate replayed

<sub>`stolen-mandate-replayed` · §5.2, §7 · preventive control</sub>

**The attack.** Copy a mandate chain out of a log, a proxy, or a compromised host, and present it.

**Why it works.** A credential that authorizes on presentation alone is a bearer token, and a leaked one is a blank cheque against the principal.

**The check.** `cnf.jkt` at every link. The holder proves possession by signing the actual HTTP request (RFC 9421), and the verifier matches that key's thumbprint against the leaf's `cnf.jkt`.

**Where.** [`src/verify.ts`](../src/verify.ts), [`src/http/signature.ts`](../src/http/signature.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *binds the presenter key to the leaf cnf.jkt*<br>[`test/spend.test.ts`](../test/spend.test.ts) — *binds proof of possession to the leaf holder*<br>[`test/mandated-fetch.test.ts`](../test/mandated-fetch.test.ts) — *is refused by the ledger when the signing key is not the leaf holder*

---

### Forging or editing a link

<sub>`forged-link` · §7 · preventive control</sub>

**The attack.** Extend a chain with a link the parent holder never signed, or edit a signed one.

**Why it works.** Delegation is only as good as the rule about who may sign what. A verifier that checks each link against *any* trusted key, rather than against its parent's subject, lets any holder mint a sibling of any other.

**The check.** Link *i* must be signed by the key named as link *i−1*'s `sub`, and `iss`/`par` must agree with the parent. The root, and only the root, is checked against the trusted-issuer set.

**Where.** [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *rejects a link signed by anyone but the parent holder*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *rejects a tampered payload*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *rejects an untrusted root issuer*

---

### Key compromise at depth *n*

<sub>`key-compromise-at-depth` · §5.2, §10.1, §10.3 · preventive control</sub>

**The attack.** Compromise a subagent key and spend everything the principal has.

**Why it works.** A delegation format where a leaf key can reach the root's authority has not delegated anything; it has shared a password.

**The check.** Every link is independently PoP-bound to its own holder, and consumption debits the whole path, so a compromised key at depth *n* yields the authority of that subtree and no more. Short `exp` and subtree revocation bound the window.

**Where.** [`src/verify.ts`](../src/verify.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *revoking an ancestor stops every descendant*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *revoking a leaf leaves its sibling alone*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *reports the exhausted ancestor even when the leaf still has room*

---

### Delegating deeper than granted

<sub>`depth-escape` · §6.2, §7 · preventive control</sub>

**The attack.** Delegate deeper than the grant allows, or reset the depth budget by omitting `depth` in a middle link.

**Why it works.** `depth` is a counter, not an order. Treating omission as "unbounded" — the reading every other caveat gets — resets the budget at the first link that stays silent.

**The check.** Each hop consumes one; omission inherits the remaining count rather than resetting it, and a link may only clamp it further. `delegable: false` seals a subtree outright.

**Where.** [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *consumes one depth per hop, and omission inherits rather than resetting*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *rejects delegation from a sealed mandate*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *enforces MAX_DEPTH*

---

### Clock skew abuse

<sub>`clock-skew-abuse` · §4.5, §7 · preventive control</sub>

**The attack.** Present a chain outside its window and rely on the verifier's clock being generous, or on disagreement between two verifiers.

**Why it works.** Unbounded skew tolerance turns `exp` into a suggestion. It matters most in offline mode, where `exp` is the only bound on revocation.

**The check.** ±60s hard tolerance, and in online mode the Ledger's clock is authoritative rather than the merchant's or the agent's. The effective window is the intersection across every link, not the leaf's.

**Where.** [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *rejects an expired chain outside the skew tolerance*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *rejects a not-yet-valid chain*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *narrows the validity window structurally*

---

### Confused deputy

<sub>`confused-deputy` · §8, §6.2 · preventive control</sub>

**The attack.** A subagent reuses authority granted for one task to fund a different one.

**Why it works.** Budget alone cannot tell the difference. A mandate that says "$50" and nothing else funds whatever the holder is currently being persuaded to do, which is the whole shape of a prompt-injection loss.

**The check.** The `purpose` and `task` caveats, plus `task_id` bound into the presentation signature so the agent cannot relabel a request after the fact.

**Where.** [`src/verify.ts`](../src/verify.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/verify.test.ts`](../test/verify.test.ts) — *rejects a missing or ungranted purpose*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *pins the task when the grant does*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *enforces a per-task ceiling across separate mandates*

---

### Spend-token replay

<sub>`spend-token-replay` · §9.1, §9.2 · preventive control</sub>

**The attack.** Capture a spend token in flight and present it again, or at a second merchant.

**Why it works.** A spend token is a bearer instrument for its lifetime. Without a replay cache it pays as many times as it is presented.

**The check.** Single use via a `jti` cache with a TTL of **2×** the token lifetime, `aud`-bound to one host, and an RFC 9421 signature covering the `Payment` header. The doubled TTL closes the skew-width window where a token is still acceptable but no longer remembered.

**Where.** [`src/spend.ts`](../src/spend.ts), [`src/http/merchant.ts`](../src/http/merchant.ts)

**Proven by.** [`test/spend.test.ts`](../test/spend.test.ts) — *rejects a replayed jti*<br>[`test/spend.test.ts`](../test/spend.test.ts) — *rejects a token addressed to another merchant*<br>[`test/http.e2e.test.ts`](../test/http.e2e.test.ts) — *rejects a replayed token*

---

### Replay-cache poisoning

<sub>`replay-cache-poisoning` · §9.2 · preventive control</sub>

**The attack.** Present a forged token — or one addressed elsewhere — carrying a `jti` you expect the real agent to use, so the legitimate presentation bounces as a replay.

**Why it works.** A cache that records `jti` before validating the token lets anyone burn any identifier for free. The agent's real token is then refused, and the money is already debited at the Ledger.

**The check.** **The order is normative.** The replay check runs after signature and audience verification, so a token nobody could have issued never reaches the cache.

**Where.** [`src/spend.ts`](../src/spend.ts), [`src/http/merchant.ts`](../src/http/merchant.ts)

**Proven by.** [`test/spend.test.ts`](../test/spend.test.ts) — *does not let an unsigned or misaddressed token burn a legitimate jti*<br>[`test/http.e2e.test.ts`](../test/http.e2e.test.ts) — *does not let an unsigned request burn the token*

---

### Signature covering nothing useful

<sub>`signature-covering-nothing` · §14.2 · preventive control</sub>

**The attack.** Sign an RFC 9421 covered-component list that omits the parts that matter, then reuse that signature on a different request.

**Why it works.** A signature over `@method` alone verifies perfectly and constrains nothing. The verifier that checks "is there a valid signature" rather than "does it cover what I care about" has bought itself a decoration.

**The check.** The merchant checks the *declared* covered-component list actually contains `@method`, `@target-uri` and `payment`, and rejects the request if not.

**Where.** [`src/http/signature.ts`](../src/http/signature.ts)

**Proven by.** [`test/signature.test.ts`](../test/signature.test.ts) — *rejects a signature that does not cover the payment header*<br>[`test/signature.test.ts`](../test/signature.test.ts) — *rejects a signature lifted onto a different URL*<br>[`test/signature.test.ts`](../test/signature.test.ts) — *rejects a signature lifted onto a different method*<br>[`test/signature.test.ts`](../test/signature.test.ts) — *rejects a swapped payment token*

---

### Token lifted to a pricier endpoint

<sub>`token-lifted-to-pricier-endpoint` · §14.5, §9.2 · preventive control</sub>

**The attack.** Take a token minted for a cheap endpoint and spend it on an expensive one within its 60-second window.

**Why it works.** The token names an amount, and an endpoint that only checks the amount is happy to be underpaid for something dearer.

**The check.** The merchant compares `token.res` against the canonical request URI, and the amount against the *current* price for that resource — not against whatever the token says it is worth.

**Where.** [`src/http/merchant.ts`](../src/http/merchant.ts)

**Proven by.** [`test/http.e2e.test.ts`](../test/http.e2e.test.ts) — *rejects a token minted for another resource*<br>[`test/http.e2e.test.ts`](../test/http.e2e.test.ts) — *rejects a token whose amount does not match the current price*

---

### Merchant learns the delegation tree

<sub>`mandate-disclosure-to-merchant` · §9.1 · preventive control</sub>

**The attack.** A merchant learns the principal's delegation tree, budgets and org structure from the credential it is handed.

**Why it works.** Presenting the chain to the merchant would be the simplest design, and it discloses every ancestor's budget and identity to a counterparty that needs to know only "this is paid for".

**The check.** The merchant never sees the chain. The spend token carries `chain_hash`, which commits to the authority that produced it without disclosing it.

**Where.** [`src/spend.ts`](../src/spend.ts)

**Proven by.** [`test/spend.test.ts`](../test/spend.test.ts) — *never shows the merchant the mandate chain*

---

### `jti` re-issue to reset a budget

<sub>`jti-reissue-budget-reset` · §10.1 · preventive control</sub>

**The attack.** Re-sign a mandate reusing a `jti` that has already been spent against, with a fresh `max_total`. Every signature is valid and every caveat narrows.

**Why it works.** The `jti` is the key for consumption state, so a Ledger that keys a counter by `jti` and trusts whatever content arrives with it has just been told the budget is full again. The signature chain alone does not prevent this — nothing in §7 is violated.

**The check.** The Ledger stores a hash of the link's JWS at materialization and rejects a later presentation of the same `jti` with different content.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *rejects a jti reused with different content*<br>[`test/status.test.ts`](../test/status.test.ts) — *is idempotent, and refuses a jti re-presented with different content*

---

### Overdraw on a mandate's first concurrent spends

<sub>`first-spend-overdraw` · §10.1 · preventive control</sub>

**The attack.** Fire several spends concurrently against a mandate that has never been used.

**Why it works.** The obvious implementation takes `SELECT … FOR UPDATE` on the path's rows. **A row that does not exist locks nothing**, and a mandate's first spend has no row — so every concurrent first spend reads `spent = 0`, and the last write wins instead of adding. Overdraw on the first two calls against any new mandate, not in some rare interleaving.

**The check.** Nodes are locked by *key*, not by row: a transaction-scoped advisory lock exists before the row does, and is taken in the same root-to-leaf order.

**Where.** [`src/ledger/sql/postgres.ts`](../src/ledger/sql/postgres.ts)

**Proven by.** [`test/store-suite.ts`](../test/store-suite.ts) — *debits every one of several concurrent first spends on a fresh mandate*

---

### Deadlock as a denial of service

<sub>`lock-order-deadlock` · §10.1 · preventive control</sub>

**The attack.** Drive ordinary concurrent traffic and rely on mixed lock ordering to wedge the ledger.

**Why it works.** Not adversarial at all, which is the point. Every spend under a principal touches the same root, so paths overlap constantly; two transactions locking overlapping rows in different orders deadlock under normal load.

**The check.** Locks are taken root-to-leaf, always, and the ordering lives in `lockPath` rather than in the direction a caller happens to write a loop. Any consistent global order would do; this one is deadlock-free because every path shares a prefix from the root.

**Where.** [`src/ledger/store.ts`](../src/ledger/store.ts), [`src/ledger/sql/postgres.ts`](../src/ledger/sql/postgres.ts)

**Proven by.** [`test/store-suite.ts`](../test/store-suite.ts) — *holds for interleaved reserves across two siblings*<br>[`test/store-suite.ts`](../test/store-suite.ts) — *conserves funds across interleaved reserve, settle and refund*

---

### Sibling collusion

<sub>`sibling-collusion` · §10.1 · preventive control</sub>

**The attack.** Two subagents under one principal each spend their full allowance, jointly exceeding what the principal granted.

**Why it works.** Enforcing a budget at the leaf alone makes the principal's ceiling the *sum* of its children rather than the number it wrote down.

**The check.** Consumption debits the whole path. Every ancestor must independently afford a spend, so joint spend is bounded by the common ancestor.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *bounds sibling collusion by the common ancestor*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *debits every ancestor, not just the leaf*<br>[`test/store-suite.ts`](../test/store-suite.ts) — *holds the task ceiling across two principals sharing a task*

---

### Spending one mandate at every ledger

<sub>`multi-ledger-budget-multiplication` · §7, §10.1, §13 · preventive control</sub>

**The attack.** Present the same chain to several Ledgers. Each verifies it, each accepts it, each debits its own state — so a `max_total` of 20.00 buys 20.00 at every Ledger that will take it.

**Why it works.** §7 step 3 says "all links agree on `ledger`", which *reads* like it binds a chain to one Ledger and does not. Agreement among the links makes a chain internally coherent; it says nothing about who is reading it. Consumption state is per-Ledger, so a second Ledger that accepts the chain offers a second full budget — and nothing in §7 is violated along the way, because every signature is valid, every caveat narrows, and every link does agree. The natural implementation uses its own URL only as the `iss` of minted spend tokens and never compares it to anything, which is exactly what this one did.

**The check.** The second half of §7 step 3, enforced in `verifyChain` itself so it binds every party that acts on a chain rather than only the one that noticed first. `VerifyOptions.ledger` is **required**, and declining the check is the `ANY_LEDGER` sentinel rather than an omitted field — the failure mode of this rule is that somebody forgets it, so an absent parameter and a deliberate opt-out must not look alike. Three parties are bound: a Ledger at `reserve` and at `register`, and an **offline** merchant, which is the one that settles with no Ledger on the path and is therefore the only party acting on the chain at all. `register` needs it independently — the status list URI is derived as `{ledger}/v1/status/{root}`, so registering a foreign chain mints an index no merchant will ever fetch and records the mandate as revocable when it is not.

**Where.** [`src/verify.ts`](../src/verify.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *refuses a chain addressed to another ledger*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *refuses even when every link agrees — agreement is not address*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *does not let one mandate be spent in full at every ledger that takes it*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *refuses to register one either — a list nobody would fetch is worse than none*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *refuses a conforming chain addressed to another ledger*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *is what stops an offline spend that would debit no ledger at all*

---

### Retry-storm griefing

<sub>`retry-storm-griefing` · §10.2, §10.4 · preventive control</sub>

**The attack.** Loop against a cheap endpoint. A $0.05 call burns $500 overnight while nobody is watching.

**Why it works.** Autonomous spend fails catastrophically rather than gradually. Nothing about a retry loop looks anomalous per-call — only the rate does, and only against a baseline.

**The check.** `rate` enforced at every ancestor independently, plus velocity and burn-rate breakers against a rolling baseline, plus a per-task ceiling.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts), [`src/ledger/breakers.ts`](../src/ledger/breakers.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *enforces an ancestor rate the leaf never declared*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *blocks a velocity anomaly against the rolling baseline*<br>[`test/store-suite.ts`](../test/store-suite.ts) — *never lets a rate caveat be exceeded within its window*

---

### Refunds used to reset a rate limit

<sub>`refund-inflates-rate` · §10.2, §12.3 · preventive control</sub>

**The attack.** Spend, get refunded, repeat — using refunds to reset a rate limit.

**Why it works.** A refund restores money, so the obvious implementation restores the rate counter with it. But `rate` bounds *how often the agent acts*, and an action that was taken and reversed still happened. Crediting the counter turns "5 per hour" into "unlimited, as long as they fail".

**The check.** A refund credits budget and does **not** credit the rate counter. The two are different quantities and only one of them is money.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *credits budget on refund but not the rate counter*

---

### Agent approving its own step-up

<sub>`step-up-self-approval` · §10.5 · preventive control</sub>

**The attack.** Read the `step_up_required` error, take the approval handle out of it, and present it back on the retry.

**Why it works.** The Ledger hands the handle to the agent. Treating possession of it as consent means the party being restrained lifts its own restraint — and `step_up` is the only mechanism in the protocol for keeping a high-value transaction attended. This implementation did exactly this, and the test asserting it called re-presenting the handle "once approved".

**The check.** A handle records that a *question was asked*. The approval is a separate signed answer from the mandate's trusted root issuer, restating `root`, `res` and `amt` so the signature attests to terms rather than to an opaque string. Only `state: approved` admits a spend, exactly once.

**Where.** [`src/stepup.ts`](../src/stepup.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *does not accept its own handle back as approval*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *refuses a decision signed by anyone but the principal*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *refuses a decision whose signed terms do not match the request*<br>[`test/stepup.test.ts`](../test/stepup.test.ts) — *refuses a decision signed by the agent, however it is submitted*

---

### Redirecting a signed step-up decision

<sub>`step-up-decision-redirected` · §10.5 · preventive control</sub>

**The attack.** Take a decision the principal signed for one request and submit it against another.

**Why it works.** A signature over a bare handle attests only that the principal saw an opaque identifier; it cannot distinguish the request they were shown from any other. Routing by URL path rather than by signed content lets the path and the signature disagree.

**The check.** The decision restates the terms and the Ledger re-checks all three against its own record before honouring it. The path/signature mismatch is caught before the decision is applied, not after.

**Where.** [`src/http/approval.ts`](../src/http/approval.ts), [`src/http/console.ts`](../src/http/console.ts)

**Proven by.** [`test/stepup.test.ts`](../test/stepup.test.ts) — *will not let the path redirect a signed decision onto another request*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *honours a denial and does not let the agent retry into a yes*

---

### Replaying a captured `release`

<sub>`control-action-replay` · §10.6 · preventive control</sub>

**The attack.** Capture a signed `release` and replay it at the next incident, un-halting a principal who deliberately halted.

**Why it works.** A control action names no one-shot handle, so nothing else prevents replay. A replayed `kill` is harmless; a replayed `release` is not, and an agent that captured one only has to wait. An in-memory nonce cache is insufficient — a halted principal is precisely the situation likely to involve a restart.

**The check.** Every decision carries a `jti` the Ledger consumes exactly once, **durably**, in the same transaction that applies the action.

**Where.** [`src/control.ts`](../src/control.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/console.test.ts`](../test/console.test.ts) — *consumes a decision exactly once*

---

### One principal halting another

<sub>`cross-principal-control` · §10.6 · preventive control</sub>

**The attack.** On a Ledger serving several principals, sign a kill or revoke naming someone else's root.

**Why it works.** `isTrustedRootIssuer` answers "is this DID *a* principal we trust", not "is this DID *this subtree's* principal". Checking only the trust list lets any tenant halt any other. Making the check possible at all required the Ledger to start recording who issued each mandate.

**The check.** The decision's `iss` is checked against the **root node's recorded issuer**, and a `revoke` target must be in that root's subtree.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts), [`src/ledger/store.ts`](../src/ledger/store.ts)

**Proven by.** [`test/console.test.ts`](../test/console.test.ts) — *will not let one principal halt another principal*<br>[`test/console.test.ts`](../test/console.test.ts) — *revokes a mandate in its own subtree and refuses one outside it*<br>[`test/status.test.ts`](../test/status.test.ts) — *still refuses a revoke naming a target under a different root it has seen*

---

### Using the control endpoint from the agent's network

<sub>`agent-approves-via-unauthenticated-endpoint` · §10.5, §10.6 · preventive control</sub>

**The attack.** Reach the control or approval endpoint from the agent's own network and use it.

**Why it works.** The network the kill switch most needs to be reachable from is the agent's. An endpoint protected by a bearer secret is protected by something the agent may well be holding.

**The check.** Control and step-up decisions carry their own authority as signatures, so the endpoint needs no auth of its own and reaching it is not the same as being allowed to use it. The **read** side has no such excuse and is documented as needing the deployment's own access control.

**Where.** [`src/http/console.ts`](../src/http/console.ts), [`src/http/approval.ts`](../src/http/approval.ts)

**Proven by.** [`test/console.test.ts`](../test/console.test.ts) — *accepts a signed control action over HTTP and refuses an unsigned one*

---

### Spending a mandate revoked before its first use

<sub>`revoke-before-first-spend` · §10.3 · preventive control</sub>

**The attack.** Spend a mandate the principal already revoked, by never having spent it before.

**Why it works.** Consumption state materializes on first presentation, so a Ledger that stores revocation *on that state* has nowhere to put a revocation for a mandate it has not seen. This implementation refused such a revocation as "unknown mandate", and the first spend then created the node unrevoked and went through — a window covering the mandate's entire life up to its first use.

**The check.** Revocation is a record of its own, independent of materialization, and a node created later inherits it. It is keyed by root because an unmaterialized `jti` has no recorded parent to check a subtree claim against.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts), [`src/ledger/store.ts`](../src/ledger/store.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *revokes a jti with no node at all, and the node materializes revoked*<br>[`test/status.test.ts`](../test/status.test.ts) — *does not let one principal pre-revoke a jti under another principal*<br>[`test/store-suite.ts`](../test/store-suite.ts) — *records a revocation for a jti with no node, scoped to its root*

---

### Status-list rollback un-revoking a mandate

<sub>`status-list-rollback` · §10.3.1 · preventive control</sub>

**The attack.** Serve a merchant an older status list that has not yet expired, un-revoking everything revoked since.

**Why it works.** `exp` does not stop this. The older list is a perfectly valid, correctly signed, in-date document — nothing about it is malformed. Freshness bounds how *old* a list may be, not whether it is the *latest*.

**The check.** A consumer refuses any `seq` below one it has already accepted for that `sub`. `seq` counts revocations, so it rises monotonically and a lagging replica is refused too.

**Where.** [`src/status.ts`](../src/status.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *refuses a rollback to a still-valid older list*<br>[`test/status.test.ts`](../test/status.test.ts) — *will not go backwards even if the network serves an older list*<br>[`test/status.test.ts`](../test/status.test.ts) — *numbers a list by what is revoked in it, not by when it was built*

---

### Status list pinned to hide a revocation

<sub>`status-list-pinned` · §10.3.1 · preventive control</sub>

**The attack.** Answer the status fetch — from a cache, a proxy, or the path — with yesterday's list, forever.

**Why it works.** A status list with no expiry is a document, not a mechanism. Whoever answers the fetch decides when revocation stops propagating, and nothing in the list itself contradicts them.

**The check.** `exp` is mandatory, a stale list is refused rather than served, and the served `Cache-Control: max-age` tracks the list's own remaining lifetime so an intermediary cannot hold it longer than the signature commits to.

**Where.** [`src/status.ts`](../src/status.ts), [`src/http/service.ts`](../src/http/service.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *refuses a list that has expired, with no fallback to serving it anyway*<br>[`test/status.test.ts`](../test/status.test.ts) — *keeps serving the cached list when a refresh fails, until it expires*<br>[`test/status.test.ts`](../test/status.test.ts) — *caps how long an intermediary may hold a list to the list's own lifetime*

---

### Status list as a decompression bomb

<sub>`status-list-decompression-bomb` · §10.3.1 · preventive control</sub>

**The attack.** Answer the status fetch with a few kilobytes of gzip that expand to gigabytes.

**Why it works.** The list is compressed and fetched over a network, so `gunzip` runs on attacker-reachable input. A verifier that decompresses in order to see what it has is a memory-exhaustion primitive with a signature check bolted on afterwards.

**The check.** The signature is verified **before** anything is decompressed, so only the Ledger can cause an inflation at all; the signed `bits` then caps that inflation. A payload that decompresses to any other length is refused — short included, because a truncated bitstring reads as "nothing is revoked".

**Where.** [`src/status.ts`](../src/status.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *checks the signature before it decompresses anything*<br>[`test/status.test.ts`](../test/status.test.ts) — *refuses a payload that decompresses past its declared size*<br>[`test/status.test.ts`](../test/status.test.ts) — *refuses a payload that decompresses short of its declared size*

---

### Blocking the status fetch to bypass the check

<sub>`status-fetch-blocked` · §10.3.1, §15 · preventive control</sub>

**The attack.** Break the merchant's status-list fetch, so revocation cannot be checked and every revoked mandate works again.

**Why it works.** If "I could not check" is treated as "not revoked", then causing an outage *is* the bypass — and causing an outage is much easier than forging a list.

**The check.** A chain carrying `st` that cannot be checked is refused with `status_unknown` (503, not 403 — "I could not find out" is not "this is revoked"). A cache whose refresh is failing keeps serving what it has until that list's own `exp`, and then starts refusing.

**Where.** [`src/verify.ts`](../src/verify.ts), [`src/status.ts`](../src/status.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *refuses a listed mandate when the list cannot be consulted at all*<br>[`test/status.test.ts`](../test/status.test.ts) — *keeps serving the cached list when a refresh fails, until it expires*

---

### Pointing a status list at a host the issuer controls

<sub>`status-uri-redirection` · §10.3.1 · preventive control</sub>

**The attack.** Issue a mandate whose status list lives at a host the issuer controls, and answer "not revoked" forever.

**Why it works.** Any credential that names where to check its own revocation has handed that decision to whoever issued it. The natural design — a `status_uri` claim — is exactly this.

**The check.** The URI is **derived**, never declared: `{ledger}/v1/status/{root_jti}`, from the `ledger` claim every link already agrees on plus the head of the path. There is nothing left to point elsewhere.

**Where.** [`src/status.ts`](../src/status.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *derives the list URI from the chain rather than from a claim*<br>[`test/status.test.ts`](../test/status.test.ts) — *asks for the list at the URI derived from the chain*<br>[`test/status.test.ts`](../test/status.test.ts) — *refuses a list for a different root or a different ledger*

---

### Two mandates sharing a status index

<sub>`status-index-collision` · §10.3.1 · preventive control</sub>

**The attack.** Allocate one status index to two mandates, so revoking one does not revoke the mandate that matters.

**Why it works.** Allocation is the issuer's job and issuers have bugs. The dangerous half is the publisher: walking nodes and writing `bit[idx] = node.revoked` lets the unrevoked mandate clear the revoked one's bit, depending on nothing but row order.

**The check.** The list is built as the **union** of revoked indices, which cannot express a clear. A collision then costs an unnecessary refusal instead of a missed one — the direction a revocation mechanism has to fail in.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/status.test.ts`](../test/status.test.ts) — *builds by union, so a shared index never clears a revoked bit*

---

### Idempotency key reused for a different request

<sub>`idempotency-key-substitution` · §9 · preventive control</sub>

**The attack.** Reuse an idempotency key with a different request, to be handed someone else's reservation — or your own earlier one — for a spend you did not make.

**Why it works.** The obliging implementation returns the first response for a repeated key. That silently tells a caller something went through that never did, which is worse than either debiting again or failing.

**The check.** The key is bound to a hash of the chain, the request and the quote. A key reused with a different request is refused, not answered. Refusals are recorded too, including `step_up_required`, so a replay returns the same handle rather than queueing the question twice.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts), [`src/http/service.ts`](../src/http/service.ts)

**Proven by.** [`test/service.test.ts`](../test/service.test.ts) — *refuses a key reused for a different request*<br>[`test/service.test.ts`](../test/service.test.ts) — *replays a refusal rather than re-deciding it*<br>[`test/service.test.ts`](../test/service.test.ts) — *returns the same step-up handle on replay rather than queueing twice*

---

### Idempotency hash collision via encoding

<sub>`idempotency-hash-collision-via-encoding` · §9 · preventive control</sub>

**The attack.** Craft two different requests that hash to one idempotency key, and be handed the other caller's reservation.

**Why it works.** Node's `'ascii'` encoding is latin1-equivalent on encode: it truncates code points above U+00FF modulo 256. `Ł` (U+0141) becomes byte 0x41, which is `A` — so `/Łedger` and `/Aedger` hash identically. The JWS hash beside it may legitimately use `'ascii'`, because base64url is ASCII by construction, which is exactly why the wrong one is easy to copy.

**The check.** The request hash is taken over UTF-8. Only the token hash, whose input is base64url, uses `ascii`.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/service.test.ts`](../test/service.test.ts) — *does not collide two requests that differ only above U+00FF*

---

### Double transfer after a crash

<sub>`double-transfer-after-crash` · §12.2.2 · preventive control</sub>

**The attack.** Crash the Ledger between paying a rail and recording that it paid, then let the retry pay again.

**Why it works.** Paying and recording are two writes to two systems. Any crash between them either double-pays or strands the money, and which one you get depends on the order you chose.

**The check.** The rail idempotency key is derived from the spend `jti`, so a retry of the same reservation is the same transfer to the rail rather than a second one. The nonce comes from the `spendId`, never from randomness.

**Where.** [`src/rail/x402.ts`](../src/rail/x402.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.rail.test.ts`](../test/ledger.rail.test.ts) — *never pays twice for one reservation*<br>[`test/rail.x402.test.ts`](../test/rail.x402.test.ts) — *derives the nonce from the spendId, not from randomness*<br>[`test/rail.x402.test.ts`](../test/rail.x402.test.ts) — *is idempotent for a given spendId*

---

### Refund-on-timeout draining a principal

<sub>`refund-on-timeout-drain` · §12.2.1, §12.2.3 · preventive control</sub>

**The attack.** Make settlement time out repeatedly. If a timeout refunds, the budget is restored while the money may already have moved — spend the same allowance again.

**Why it works.** Settlement has **three** outcomes, not two: success, terminal failure, and *indeterminate*. Collapsing the third into either neighbour costs a double-spend or a stranded balance, depending on which way you guess, and a timeout is the most common indeterminate there is.

**The check.** An indeterminate settlement stays `settling` and stays debited until a reconciler asks the rail what actually happened. Escalation moves no money; it changes only who knows.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts), [`src/ledger/reconciler.ts`](../src/ledger/reconciler.ts)

**Proven by.** [`test/ledger.rail.test.ts`](../test/ledger.rail.test.ts) — *holds an indeterminate settlement rather than guessing*<br>[`test/reconciler.test.ts`](../test/reconciler.test.ts) — *leaves an undecided payment debited and waiting*<br>[`test/reconciler.test.ts`](../test/reconciler.test.ts) — *never sweeps a reservation still in flight with the rail*<br>[`test/rail.x402.test.ts`](../test/rail.x402.test.ts) — *treats a 5xx after payment as INDETERMINATE*

---

### Refunding a failed irreversible call, then retrying it

<sub>`failed-call-refund-retry` · §6.2, §12.2.1 · preventive control</sub>

**The attack.** Call an irreversible tool, have it report an error, collect the refund, and call it again — funding two orders on one allowance.

**Why it works.** A tool that reports failure has not proved it had no effect. Refunding a failed order is exactly how an agent retries a trade it already placed, and the JSON-RPC error looks identical either way.

**The check.** Refund by `effect`, not by outcome: a failed `read` refunds because a failed read did nothing; a failed `write` or `irreversible` **settles**; a transport failure holds the reservation for reconciliation.

**Where.** [`src/mcp/gateway.ts`](../src/mcp/gateway.ts), [`src/harness/hook.ts`](../src/harness/hook.ts)

**Proven by.** [`test/mcp.gateway.test.ts`](../test/mcp.gateway.test.ts) — *consumes the allowance when an irreversible tool fails*<br>[`test/mcp.gateway.test.ts`](../test/mcp.gateway.test.ts) — *holds the reservation when the transport dies mid-call*<br>[`test/harness-hook.test.ts`](../test/harness-hook.test.ts) — *consumes the allowance when an irreversible tool fails*

---

### Free service via precision truncation

<sub>`precision-truncation-free-service` · §12.2.4, §4.3 · preventive control</sub>

**The attack.** Price a call below the rail's smallest representable unit and have it round to zero — free service, at scale.

**Why it works.** Per-call pricing runs below a tenth of a cent, and rails carry a fixed number of atomic units. Rounding is the obliging behaviour and it is the bug: a sub-precision amount is not a small payment, it is no payment.

**The check.** Conversion at the asset's precision is exact. An amount below it is a **terminal** failure, never rounded, and money never touches binary floating point anywhere in the codebase.

**Where.** [`src/money.ts`](../src/money.ts), [`src/rail/rail.ts`](../src/rail/rail.ts)

**Proven by.** [`test/rail.x402.test.ts`](../test/rail.x402.test.ts) — *refuses to round away precision the rail cannot carry*<br>[`test/rail.x402.test.ts`](../test/rail.x402.test.ts) — *treats sub-precision amounts as terminal, not as free*<br>[`test/money.test.ts`](../test/money.test.ts) — *compares exactly where floats would not*<br>[`test/verify.test.ts`](../test/verify.test.ts) — *honours sub-cent precision exactly*

---

### Releasing escrow without a verdict

<sub>`escrow-release-without-verdict` · §12.3 · preventive control</sub>

**The attack.** Settle an `escrow_schema` reservation without ever producing the verdict escrow exists to wait for.

**Why it works.** Escrow that releases on a timer, or on the agent saying so, is not escrow. The verdict is the entire mechanism.

**The check.** A reservation under `escrow_schema` will not settle without a verdict, and refunds when the response fails validation. `escrow_human` holds until a human approves.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *escrow_schema will not settle without a verdict*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *escrow_schema refunds when the response fails validation*<br>[`test/ledger.test.ts`](../test/ledger.test.ts) — *escrow_human holds until approved*

---

### Settling one reservation twice

<sub>`double-settle` · §12.2 · preventive control</sub>

**The attack.** Settle one reservation twice, or settle one a sweeper is concurrently refunding.

**Why it works.** Both are read-then-write on the same row. Without a lock that covers the read, two callers see `reserved` and both pay.

**The check.** Settling claims the reservation by moving it off `reserved` inside the transaction that reads it, and the sweeper takes the same lock before crediting.

**Where.** [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/ledger.test.ts`](../test/ledger.test.ts) — *refuses to settle the same reservation twice*<br>[`test/ledger.rail.test.ts`](../test/ledger.rail.test.ts) — *does not sweep a reservation that is mid-settlement*<br>[`test/reconciler.test.ts`](../test/reconciler.test.ts) — *never sweeps a reservation still in flight with the rail*

---

### Agent redirects a non-custodial payment

<sub>`directive-redirection` · §12.4.3, §12.4.6 · preventive control</sub>

**The attack.** Take a directive the Ledger issued and sign a transfer to a different recipient, amount, or asset.

**Why it works.** In non-custodial mode the agent holds the signing key. If the directive is advice rather than a commitment, the agent decides where the money goes and the Ledger finds out afterwards.

**The check.** The directive pins every field of the transfer and is signed by the Ledger; the agent-side signer verifies that signature, checks the directive is bound to its own key, and computes the digest itself rather than accepting one. `directive_hash` is compared again on report.

**Where.** [`src/rail/noncustodial.ts`](../src/rail/noncustodial.ts), [`src/agent/signer.ts`](../src/agent/signer.ts), [`src/agent/directive.ts`](../src/agent/directive.ts)

**Proven by.** [`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *pins every field of the transfer*<br>[`test/agent-directive.test.ts`](../test/agent-directive.test.ts) — *rejects an intent that does not match its own hash*<br>[`test/agent-directive.test.ts`](../test/agent-directive.test.ts) — *rejects one bound to another agent key*<br>[`test/signer.test.ts`](../test/signer.test.ts) — *computes the digest itself rather than accepting one*<br>[`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *rejects an instruction that does not match its directive*

---

### Agent falsely reports payment

<sub>`false-payment-report` · §12.4.5, §12.4.6 · preventive control</sub>

**The attack.** Report a directive as executed without executing it, or with someone else's signature.

**Why it works.** The report comes from the party with the incentive to lie. Any settlement that trusts it is settling on the agent's say-so.

**The check.** Settlement is confirmed by reading the chain — `authorizationState` — never by the report. A proof signed by the wrong key, or over a different authorization, refunds immediately.

**Where.** [`src/rail/x402-noncustodial.ts`](../src/rail/x402-noncustodial.ts), [`src/ledger/ledger.ts`](../src/ledger/ledger.ts)

**Proven by.** [`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *accepts a proof that matches the directive, and still does not settle*<br>[`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *refunds immediately when the proof was signed by someone else*<br>[`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *settles only once the authorization is actually consumed*<br>[`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *settles a directive the agent executed but never reported*

---

### Nonce reused for a different transfer

<sub>`nonce-reuse-for-a-different-transfer` · §12.2.2, §12.4.3 · preventive control</sub>

**The attack.** Get the signer to reuse an authorization nonce for a different transfer, so one on-chain slot covers two intents.

**Why it works.** EIP-3009 nonces are the replay defence. A signer that derives one from randomness cannot be idempotent; a signer that reuses one across differing intents has broken the defence.

**The check.** The nonce is derived from the `spendId`, so re-requesting an identical transfer is idempotent, and requesting a *different* transfer under the same nonce is refused.

**Where.** [`src/agent/signer.ts`](../src/agent/signer.ts), [`src/rail/x402.ts`](../src/rail/x402.ts)

**Proven by.** [`test/signer.test.ts`](../test/signer.test.ts) — *is idempotent for an identical re-request*<br>[`test/signer.test.ts`](../test/signer.test.ts) — *refuses to re-use a nonce for a different transfer*

---

### Exfiltrating the agent signing key

<sub>`signer-key-exfiltration` · §12.4.4 · preventive control</sub>

**The attack.** Get the signing key out of the agent process through a log line, an error path, a JSON dump, or a debugger repr.

**Why it works.** Keys leak through the mundane: `JSON.stringify` on a config object, an exception carrying its context, `util.inspect` in a crash handler. A key held as an ordinary property is one careless log away from a transcript.

**The check.** The key never leaves the closure — not reachable as a property, redacted in JSON and `inspect` output, and not present in policy-refusal or audit paths.

**Where.** [`src/agent/signer.ts`](../src/agent/signer.ts)

**Proven by.** [`test/signer.test.ts`](../test/signer.test.ts) — *is redacted in JSON and inspect output*<br>[`test/signer.test.ts`](../test/signer.test.ts) — *is not reachable as a property*<br>[`test/signer.test.ts`](../test/signer.test.ts) — *does not leak the key through a policy refusal*<br>[`test/signer.test.ts`](../test/signer.test.ts) — *calls the audit hook on success without exposing the key*

---

### Agent bypasses the Ledger entirely

<sub>`agent-bypasses-the-ledger` · §12.4.7, §18 · detective control</sub>

**The attack.** In non-custodial mode, simply sign a transfer that no directive ever authorized.

**Why it works.** The agent holds the key. Nothing in a protocol can stop a key-holder signing, which is the honest statement the alternative designs avoid making.

**The check.** **Not preventable non-custodially.** Detected by reconciling the payer account against issued directives. The preventive answer requires co-signing or custody, and both have costs the spec declines to hide — see open question 9.

> **Gap.** Detective only, and the reconciliation it depends on is not implemented here — `DelegatedTransferRail` declares the weaker guarantees, but nothing in this repo watches a payer account. Stated rather than engineered around.

**Where.** [`src/rail/noncustodial.ts`](../src/rail/noncustodial.ts)

**Proven by.** [`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *declares its weaker capabilities honestly*

---

### Treating a rail as more decidable than it is

<sub>`rail-guarantee-overclaim` · §12.4.5 · preventive control</sub>

**The attack.** Treat a rail that cannot prove settlement as though it could, and auto-refund on its silence.

**Why it works.** Rails differ in what they can decide. An oracle-backed rail eventually answers; a card-shaped one may never. Applying one policy to both means either refunding payments that landed or holding ones that never will.

**The check.** A rail declares its capabilities, and reconciliation escalates rather than refunding where the rail gives no guarantee that it will ever decide. Expiry deadline and decidability deadline are separate.

**Where.** [`src/rail/delegated-transfer.ts`](../src/rail/delegated-transfer.ts), [`src/ledger/reconciler.ts`](../src/ledger/reconciler.ts)

**Proven by.** [`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *declares its weaker capabilities honestly*<br>[`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *separates the expiry deadline from the decidability deadline*<br>[`test/noncustodial.test.ts`](../test/noncustodial.test.ts) — *ESCALATES instead of refunding, because a late settlement is still possible*<br>[`test/reconciler.test.ts`](../test/reconciler.test.ts) — *reports a rail-raised escalation to the pager*

---

### Cross-merchant parallel spend

<sub>`cross-merchant-parallel-spend` · §13 · preventive control</sub>

**The attack.** Present the same offline mandate to several merchants at once, before any of them reports consumption.

**Why it works.** Offline mode's whole premise is that the merchant settles without contacting the Ledger, so nothing is authoritative at spend time. Parallel presentation is not a flaw in the mechanism; it is the price of it.

**The check.** Online, the Ledger is authoritative and this cannot happen. Offline, loss is **bounded** rather than prevented, and only by all the constraints together: one non-wildcard host in `aud`, `max_total` present and therefore scoped to it, `exp` − `nbf` ≤ 1 hour, `settle: immediate`. `verifyChain({ offline: true })` holds a chain to all four as one check, against the *effective* authority rather than any single link. The fifth — reporting consumption every 60 seconds — is a property of a deployment, not a credential.

> **Gap.** Bounded, never prevented — that is what §13 buys and it is the whole trade. `offlineRiskBudget` computes the figure §13 says MUST be surfaced to the principal, but nothing in this repo *tracks* live offline grants to feed it, and the 60-second reporting requirement is not enforced anywhere either. A deployment has to wire both.

**Where.** [`src/offline.ts`](../src/offline.ts), [`src/verify.ts`](../src/verify.ts)

**Proven by.** [`test/offline.test.ts`](../test/offline.test.ts) — *refuses a wildcard audience, which names a set rather than a merchant*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *refuses a window over an hour, to the second*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *refuses escrow, and refuses leaving settle unconstrained*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *admits a conforming chain and refuses one that is merely valid*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *checks the fold, not any one link*<br>[`test/offline.test.ts`](../test/offline.test.ts) — *sums worst-case exposure per merchant*

---

### Calling a tool the enforcement layer cannot price

<sub>`unpriced-tool-through-the-gateway` · §6.2 · preventive control</sub>

**The attack.** Call a tool the gateway has no price for, and spend nothing against the mandate while doing it.

**Why it works.** A gateway that prices what it knows and forwards the rest is a spending control with a hole shaped like every tool nobody configured.

**The check.** The gateway refuses what it cannot price, and goes further: `tools/list` is the mandate rendered, so unpriced and unpermitted tools are never shown. An agent cannot misuse what it was never offered.

**Where.** [`src/mcp/gateway.ts`](../src/mcp/gateway.ts)

**Proven by.** [`test/mcp.gateway.test.ts`](../test/mcp.gateway.test.ts) — *hides unpriced tools rather than refusing them later*<br>[`test/mcp.gateway.test.ts`](../test/mcp.gateway.test.ts) — *hides what the mandate does not permit*<br>[`test/mcp.stdio.test.ts`](../test/mcp.stdio.test.ts) — *completes the handshake and lists only priced tools*

---

### Reaching the upstream server without the gateway

<sub>`routing-around-the-gateway` · no spec section · none control</sub>

**The attack.** Configure the upstream MCP server directly alongside the gateway, and call it without a mandate.

**Why it works.** The gateway constrains a **channel**, not an agent. Its preventive property holds exactly as long as the client reaches the upstream only through it.

**The check.** None available at this layer. Stated plainly in the module and the README rather than engineered around; the harness hook covers a different surface, and neither is a sandbox.

> **Gap.** Structural, not fixable inside the gateway. A deployment that needs this guarantee needs egress control or a sandbox, which this project does not provide and does not claim to.

**Where.** [`src/mcp/gateway.ts`](../src/mcp/gateway.ts)

**Proven by.** —

---

### Ledger outage as unmetered spending

<sub>`ledger-outage-as-unmetered-spending` · no spec section · preventive control</sub>

**The attack.** Make the ledger unreachable, so the enforcement layer fails open and every priced call runs unmetered.

**Why it works.** An enforcement point in front of a network dependency has to choose. Allowing on error is the one that keeps the demo working and is indistinguishable from having no control at all for the length of the outage.

**The check.** The harness hook denies by default when the ledger cannot be reached. A deployment that would rather take the other risk has to say so explicitly.

**Where.** [`src/harness/hook.ts`](../src/harness/hook.ts)

**Proven by.** [`test/harness-hook.test.ts`](../test/harness-hook.test.ts) — *refuses by default, because unmetered spending is the failure it exists to prevent*<br>[`test/harness-hook.test.ts`](../test/harness-hook.test.ts) — *can be told to allow instead, but only deliberately*

---

### A refusal mistaken for a transport error

<sub>`refusal-mistaken-for-a-transport-error` · §15 · preventive control</sub>

**The attack.** Not an attack — a failure mode with the same effect. An agent wraps its calls in `try/catch`, a spending refusal arrives as an exception, and the retry loop turns a budget control into a hot loop.

**Why it works.** `fetch` throws on network failure, so a drop-in replacement that throws on refusal teaches every existing caller to retry a decision that will never change.

**The check.** A refusal is a `Response` carrying RFC 9457 problem details and an `x-am-refusal` header with the §15 code, so "your principal said no" is distinguishable from "the merchant said no" and from a transport failure. Network failures still throw, because that is what `fetch` does.

**Where.** [`src/http/mandated-fetch.ts`](../src/http/mandated-fetch.ts)

**Proven by.** [`test/mandated-fetch.test.ts`](../test/mandated-fetch.test.ts) — *returns problem details rather than throwing when the budget is gone*<br>[`test/mandated-fetch.test.ts`](../test/mandated-fetch.test.ts) — *marks its own refusals so they are not mistaken for the merchant s*<br>[`test/mandated-fetch.test.ts`](../test/mandated-fetch.test.ts) — *relays a ledger refusal as a refusal, not as a transport error*

---

### Ledger compromise

<sub>`ledger-compromise` · §11, §16 · detective control</sub>

**The attack.** Compromise the Ledger and mint whatever spend tokens you like.

**Why it works.** The Ledger holds the key that merchants verify against and the state that bounds every spend. There is no check downstream of it.

**The check.** **None that prevents it.** Ledger keys MUST be HSM-backed. Receipts are dual-signed, so the transaction history can be reconstructed from merchant records independently of the Ledger — which is detection and reconstruction, not prevention.

> **Gap.** Full compromise of the principal's funds, stated as residual risk in §16 rather than mitigated. Nothing in this repo enforces HSM-backed keys or runs the independent reconciliation that would detect it.

**Where.** [`src/receipt.ts`](../src/receipt.ts)

**Proven by.** [`test/spend.test.ts`](../test/spend.test.ts) — *is signed by the ledger over canonical bytes*<br>[`test/spend.test.ts`](../test/spend.test.ts) — *canonicalizes independent of key order*
