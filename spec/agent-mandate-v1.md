# Agent Mandate Protocol v1 (`am/1`)

**Status:** Draft
**Version:** 1.0.0-draft.1
**Media type prefix:** `application/agent-mandate+jwt`

A wire format and verification model for **delegated, attenuable, auditable spending
authority for autonomous agents**.

---

## 1. Overview

An autonomous agent that spends money raises three questions that existing payment
rails do not answer:

1. **On whose authority?** A card number proves possession, not that a human wanted
   this purchase.
2. **Up to what limit, and along which dimensions?** "Under $120" is one bound.
   Real delegation needs resource, purpose, rate, time, and depth bounds too.
3. **Who eats the loss when it goes wrong?** Chargeback regimes assume a human who
   can recall and dispute. An agent that paid $0.03 for a malformed response cannot
   file one.

This specification defines three artifacts that answer those questions:

| Artifact | Signed by | Lifetime | Answers |
|---|---|---|---|
| **Mandate** | Principal, then each delegating agent | Hours–days | "Who authorized what, and how far can it be sub-delegated?" |
| **Spend Token** | Ledger | ~60 seconds | "Is this one specific charge permitted right now?" |
| **Receipt** | Merchant + Ledger | Permanent | "What actually happened, under which authority?" |

### 1.1 Central design claim

> **Mandates express ceilings. Ceilings are stateless. Budgets are stateful.**

A capability credential cannot track consumption: an agent holding a `$50` mandate
can present it to ten merchants simultaneously and each sees `$50` available.

Therefore, in the default (online) mode, **mandates are never presented to
merchants**. They are presented to the **Ledger**, which holds consumption state,
applies policy and circuit breakers, and mints a single-use, amount-exact **Spend
Token**. The merchant verifies one small, cheap artifact.

This split has three consequences worth stating plainly:

- **Correctness.** Double-spend is structurally impossible in online mode.
- **Privacy.** Merchants learn nothing about the principal's internal delegation
  structure — they see a token, not an org chart.
- **Integration cost.** Merchant-side conformance is five checks (§9.2), which is
  what makes adoption plausible.

### 1.2 Out of scope

Payment rail mechanics (card, ACH, stablecoin), KYC/AML, price discovery and
negotiation beyond a quoted amount, tax, and dispute adjudication policy. This
specification defines *authority and its proof*, not *money movement*.

---

## 2. Terminology

Key words **MUST**, **MUST NOT**, **SHOULD**, **MAY** are to be interpreted as in
RFC 2119.

| Term | Definition |
|---|---|
| **Principal** | The human or organization that owns the funds and issues root mandates. |
| **Agent** | Software holding a mandate and a keypair. May sub-delegate. |
| **Ledger** | The authoritative service holding balances, consumption counters, revocation state, and circuit breakers. Mints Spend Tokens. |
| **Merchant** | Any resource server charging for access — an HTTP API, an MCP server, a content endpoint. |
| **Caveat** | A single named restriction on authority (§6). |
| **Chain** | An ordered list of mandate links from root to leaf. |
| **Link** | One mandate in a chain. |
| **Attenuation** | Producing a child mandate whose authority is provably a subset of its parent's. |

---

## 3. Architecture

### 3.1 Online mode (default, NORMATIVE)

```
  Principal
     │ issues root mandate (offline, signed)
     ▼
  Agent A ──delegates──▶ Agent B ──delegates──▶ Agent C
                                                  │
                          (1) GET resource        │
                              ◀── 402 + quote ────┼──▶ Merchant
                                                  │
                          (2) present chain ──────┤
                              ◀── spend token ────┼──▶ Ledger
                                                  │        │
                          (3) GET + token ────────┼──▶ Merchant
                              ◀── 200 + receipt ──┤        │
                                                  │        ▼
                                                  │   settle + dual-sign receipt
```

The Ledger is in the request path. That is a deliberate cost: it buys exact
consumption accounting, instant revocation, real-time circuit breaking, and a
complete audit trail — none of which are achievable with stateless credentials
alone.

### 3.2 Offline mode (OPTIONAL)

For sub-cent, latency-critical, high-frequency access, an agent MAY present a chain
directly to a merchant, which verifies it offline against the root public key and
settles from a prefunded channel. See §13 for the constraints that bound
double-spend loss. Offline mode is a *priced risk*, not a hole, and implementations
MUST document it as such.

---

## 4. Cryptography and encoding

### 4.1 Signatures

- All credentials are **JWS Compact Serialization**, `alg` = `EdDSA` (Ed25519).
- Implementations **MUST NOT** accept `alg: none`, and **MUST NOT** accept any
  algorithm not on a static allowlist. `alg` is never used to select the key.
- Protected header:

```json
{
  "alg": "EdDSA",
  "typ": "application/agent-mandate+jwt",
  "kid": "did:key:z6MkrJVSY8Fg7L...#z6MkrJVSY8Fg7L..."
}
```

### 4.2 Key identifiers

| Form | Used for | Resolution |
|---|---|---|
| `did:key:z6Mk…` | Agents | Self-certifying; no network fetch |
| `did:web:example.com#k1` | Principals / Ledgers | HTTPS fetch of `/.well-known/did.json`, cached per HTTP caching rules |

Agents **SHOULD** use `did:key`. This matters operationally: chain verification at
depth 4 must not require four network round-trips.

The same Ed25519 key **SHOULD** be used for the agent's RFC 9421 HTTP Message
Signatures, so a single key serves both Web Bot Auth identity and mandate
proof-of-possession.

### 4.3 Money

```json
{ "cur": "USD", "amt": "0.02" }
```

- `cur` — ISO 4217 uppercase, or a registered non-fiat code.
- `amt` — **decimal string**, matching `^(0|[1-9][0-9]*)(\.[0-9]{1,9})?$`.

Implementations **MUST NOT** parse or store monetary amounts as binary floating
point at any point in the pipeline. Up to 9 fractional digits are supported because
per-call pricing routinely goes below one cent.

Comparison and arithmetic are exact decimal. Amounts in different currencies are
**incomparable**: any caveat comparison across differing `cur` **MUST** fail closed.

### 4.4 Identifiers

All `jti` values are ULIDs with a type prefix: `mnd_` (mandate), `spn_` (spend
token), `rcp_` (receipt), `qt_` (quote), `tsk_` (task).

### 4.5 Time

Integer seconds since the Unix epoch. Verifiers **MUST** allow ±60s clock skew and
**MUST NOT** allow more. In online mode the Ledger's clock is authoritative for
consumption decisions.

---

## 5. The Mandate credential

### 5.1 Claims

```json
{
  "v": "am/1",
  "typ": "mandate",
  "jti": "mnd_01J8XQ7K3M4P5R6S7T8V9W0X1Y",
  "iss": "did:web:acme.example#k1",
  "sub": "did:key:z6MkAgentA...",
  "par": null,
  "iat": 1770000000,
  "nbf": 1770000000,
  "exp": 1770086400,
  "cnf": { "jkt": "NzbLsXh8uDCcd7noWXFZAfHkxZsRGC9Xs4wLPBhWkQY" },
  "ledger": "https://ledger.example.com",
  "cav": {
    "max_total":   { "cur": "USD", "amt": "50.00" },
    "max_per_txn": { "cur": "USD", "amt": "2.00" },
    "rate":        { "n": 500, "per": "PT1H" },
    "aud":         ["api.weatherco.com", "*.datavendor.io"],
    "resources":   ["https://api.weatherco.com/v3/forecast/*"],
    "purpose":     ["research.readonly"],
    "depth":       2,
    "delegable":   true,
    "settle":      "escrow_schema",
    "step_up":     { "over": { "cur": "USD", "amt": "5.00" } }
  }
}
```

| Claim | Req | Meaning |
|---|---|---|
| `v` | MUST | Protocol + caveat registry version. Verifiers reject unknown versions. |
| `typ` | MUST | `"mandate"` |
| `jti` | MUST | Unique mandate ID; the key for consumption and revocation state |
| `iss` | MUST | Issuer key ID. Root: the Principal. Child: the parent's `sub`. |
| `sub` | MUST | The holder — the agent this mandate grants authority to |
| `par` | MUST | Parent `jti`, or `null` for a root mandate |
| `iat`/`nbf`/`exp` | MUST | Validity window |
| `cnf.jkt` | MUST | JWK SHA-256 thumbprint (RFC 7638) of the holder's public key |
| `ledger` | MUST | Ledger base URL. All links in a chain **MUST** agree, and a Ledger **MUST** refuse a chain that does not name it (§7 step 3). |
| `cav` | MUST | Caveat object (§6). MAY be empty `{}`, meaning unbounded. |
| `st` | MAY | Non-negative integer index into this root's status list (§10.3.1). Absent means "not revocable offline" and asserts nothing about validity. Not a caveat: it carries no authority, participates in no lattice, and is not inherited. |

Unknown top-level claims reject the chain, so an implementation that predates a
claim refuses a mandate carrying it. That is the safe direction — a mandate
stored before `st` existed verifies exactly as it did, and a verifier too old to
understand one declines rather than ignoring it (§17.3).

### 5.2 Proof of possession

`cnf.jkt` is **not optional**. Without it a mandate is a bearer credential and a
leaked one is a blank check against the principal's balance. The holder proves
possession by signing the actual HTTP request with the corresponding key (RFC 9421),
and the verifier matches the signing key's thumbprint against `cnf.jkt`.

Every link in a chain is independently PoP-bound to its own holder. A compromised
key at depth *n* therefore yields only the authority of the subtree rooted at *n*.

---

## 6. Caveat registry and the attenuation lattice

### 6.1 The single rule

> Every caveat type declares a partial order **oriented by authority granted**.
> Absence of a caveat means **⊤** (maximum authority on that dimension).
> A child link is valid iff `child.cav ⊑ parent.cav` under that order.

One comparator, no per-field special cases. Caveats that look inverted (`settle`,
`step_up`) fall out of the same rule once ordered by authority rather than by
numeric value.

### 6.2 Registry (`am/1`)

| Caveat | Type | ⊤ (absent) | `child ⊑ parent` iff |
|---|---|---|---|
| `max_total` | Money | unbounded | same `cur` ∧ `child.amt ≤ parent.amt` |
| `max_per_txn` | Money | unbounded | same `cur` ∧ `child.amt ≤ parent.amt` |
| `rate` | `{n, per}` | unbounded | `child.n ≤ parent.n` ∧ `child.per ≥ parent.per` |
| `aud` | set of host patterns | any host | `child ⊆ parent` (pattern containment, §6.4) |
| `resources` | set of URI patterns | any resource | `child ⊑ parent` (§6.4) |
| `purpose` | set of strings | any purpose | `child ⊆ parent` |
| `task` | string | any task | `child == parent` ∨ parent absent |
| `payer` | rail account id | any registered account | `child == parent` ∨ parent absent (§12.4.4) |
| `depth` | int ≥ 0 | unbounded | `child.depth ≤ parent.depth` (decrement is structural, §7) |
| `delegable` | bool | `true` | parent `false` ⇒ no child may exist |
| `currency` | ISO 4217 | any | `child == parent` |
| `settle` | enum | `immediate` | `immediate ⊐ escrow_schema ⊐ escrow_human` |
| `step_up` | `{over: Money}` | never | same `cur` ∧ `child.over ≤ parent.over` |
| `effect` | enum | `irreversible` | `irreversible ⊐ write ⊐ read` |

`effect` bounds blast radius rather than cost. Every other caveat above is
money-shaped, and agentic risk is not only money: fetching a quote and placing an
equity order can carry the same price and are not the same act. A request
declares the effect it has; a Ledger **MUST** reject one whose declared effect is
broader than `eff.effect`, with `effect_not_permitted`.

An **undeclared** request effect is ⊤ — it is checked as `irreversible`, so any
mandate that bounds `effect` at all rejects it. A caller unwilling to classify a
call does not get the benefit of the doubt.

Note the consequence of the uniform ⊤ rule: a mandate that omits `effect` grants
`irreversible`. Deciding what an *unclassified tool or endpoint* may do is an
enforcement-layer policy, not a lattice question, and enforcement points **SHOULD**
refuse to price a call they cannot classify.

`per` is an ISO 8601 duration, restricted to fixed-length designators (`PnW`,
`PnD`, `PT[nH][nM][nS]`). Years and months are excluded: they are not
fixed-length, so they cannot be totally ordered independent of a calendar
position, and a comparator that cannot order its inputs cannot decide
attenuation.

**`exp` and `nbf` are not caveats.** They are top-level claims (§5.1). Listing
them in both places would create two sources of truth for the validity window; a
`cav` object containing either **MUST** be rejected as an unregistered key.
Their narrowing (`child.exp ≤ parent.exp`, `child.nbf ≥ parent.nbf`) is enforced
structurally in §7, alongside the other rules that are not lattice relations.

### 6.3 Four properties that carry the security weight

**A child MAY introduce a caveat its parent lacks.** A parent silent on `rate` grants
unbounded rate; a child adding `rate: 500/PT1H` is a narrowing. This is legal,
useful, and falls out of the ⊤-for-absent rule without special handling.

**An unrecognized caveat key MUST cause the entire chain to be rejected.** Fail
closed. If a verifier skips fields it does not understand, attenuation is bypassed
by inventing a field name — the same failure that has repeatedly bitten JWT `crit`
handling. The caveat registry is pinned by `v`; adding a caveat requires a version
bump.

**⊑ is NOT transitive across links, and verifiers MUST NOT compare pairwise.**
Take `a = {settle: escrow_schema}`, `b = {}`, `c = {settle: immediate}`. Then
`b ⊑ a` (b declares nothing) and `c ⊑ b` (b is ⊤ on `settle`), but `c ⋢ a`. An
intermediate link that merely *omits* a caveat is ⊤ on that dimension, so a
grandchild can re-declare what its grandparent forbade and every parent-child
check still passes.

Therefore each link **MUST** be compared against the **accumulated meet of every
link above it**, not against its immediate parent. Folding as you descend makes
the relation transitive by construction and rejects the escape at the link that
attempts it. Comparing against the immediate parent is the natural-looking
implementation and it is wrong.

**The meet of two pinned-but-different discrete values is ⊥, not either operand.**
`task: t1 ∧ task: t2` and `USD ∧ EUR` have no common lower bound inside their own
domain. Returning one of the operands makes `meet` non-commutative, so a chain's
effective authority would depend on fold order. ⊥ ("grants nothing") is a valid
lattice element but **MUST NOT** appear in a mandate on the wire: a fold that
reaches it fails validation and the chain is rejected. Unreachable in a chain
that passed the §7 checks, which reject the mismatch first.

### 6.4 Pattern containment

Resource and audience patterns use a **deliberately restricted grammar**:

```
pattern    = scheme "://" hostpat [ "/" pathprefix [ "*" ] ]
hostpat    = host | "*." host          ; single leading wildcard label only
pathprefix = <path segments, no dot-segments after canonicalization>
```

**Regular expressions are prohibited.** Containment of arbitrary regular expressions
is not decidable in the general case, which would make it impossible to
mechanically prove that a child narrows its parent. A restricted grammar with
decidable containment is the entire point.

Before comparison, verifiers **MUST** canonicalize, **in this order**:

1. lowercase scheme and host; strip the default port for the scheme
2. reject userinfo (`https://evil.test@good.test/`)
3. **percent-decode unreserved characters**
4. **resolve `.` and `..` segments** (RFC 3986 §5.2.4)
5. reject anything still containing `..`

Steps 3 and 4 **MUST NOT** be reordered. Most URL libraries — including the
WHATWG `URL` parser — resolve dot-segments *before* decoding, so `%2E%2E%2F`
survives normalization intact and re-expands to `../` in whatever consumes the
result. Decoding first is what makes
`https://api.test/v3/forecast/%2E%2E/%2E%2E/admin` canonicalize to
`https://api.test/admin` and therefore fall outside a `/v3/forecast/*` grant.

Query strings and fragments are dropped: authority is decided on path prefix
only, so admitting them would create multiple spellings of one grant without
changing what it grants. Merchants that need to price on a parameter must expose
it as a path segment.

Host wildcards match exactly one label: `*.datavendor.io` matches `api.datavendor.io`
but not `datavendor.io` or `a.b.datavendor.io`. Consequently `*.x` does **not**
contain `*.y.x` — the latter matches two extra labels where the former matches
one — so wildcard-to-wildcard containment requires identical suffixes.

Set containment requires each child pattern to be covered by a **single** parent
pattern. This is sound but incomplete: a child covered by the *union* of two
parent patterns is rejected despite granting nothing new. Incompleteness costs an
issuer an awkward error message; unsoundness costs the principal their balance.

### 6.5 Note on `rate`

The comparison rule is deliberately conservative. Parent `500/PT1H` and child
`100/PT10M` are incomparable in reality — the child permits fewer requests per
burst but 600/hour sustained — so the rule rejects it rather than guessing.

This is safe to be conservative about because the Ledger independently enforces
*every* ancestor's rate caveat at spend time (§10.2), exactly as it does for
budgets. The comparator is a sanity gate at issuance, not the enforcement point.

---

## 7. Chain verification (NORMATIVE)

`MAX_DEPTH` = 4 links (a root plus three delegations).

```
verify_chain(chain, request, now) -> effective_caveats | error

  1.  1 ≤ len(chain) ≤ MAX_DEPTH                      else chain_invalid
  2.  all links have v == "am/1" and typ == "mandate"  else chain_invalid
  3.  all links agree on `ledger`                       else chain_invalid
      chain[0].ledger == self, if the verifier IS a       else chain_invalid
        Ledger being asked to spend or register

  4.  root = chain[0]
      root.par == null                                  else chain_invalid
      trusted_root_issuer(root.iss)                     else chain_invalid
      verify_jws(root, resolve_key(root.iss))           else chain_invalid

  5.  acc       = root.cav              # accumulated authority so far
      remaining = root.cav.depth ?? ∞   # remaining delegation hops

      for i in 1 .. len(chain)-1:
        parent, child = chain[i-1], chain[i]
        child.par  == parent.jti                        else chain_invalid
        child.iss  == parent.sub                        else chain_invalid
        verify_jws(child, resolve_key(parent.sub))      else chain_invalid

        acc.delegable != false                          else attenuation_violation
        remaining = min(child.cav.depth ?? ∞, remaining - 1)
        remaining ≥ 0                                   else depth_exceeded

        child.exp ≤ parent.exp                          else attenuation_violation
        child.nbf ≥ parent.nbf                          else attenuation_violation

        narrows(child.cav, acc)                         else attenuation_violation
        acc = meet(acc, child.cav)

  6.  eff       = acc
      eff.depth = remaining
      well_formed(eff)                                  else chain_invalid   # rejects ⊥
      window    = { nbf: max(link.nbf), exp: min(link.exp) }

      for link in chain: narrows(eff, link.cav)         else chain_invalid   # post-condition

  7.  window.nbf - SKEW ≤ now ≤ window.exp + SKEW        else mandate_expired

  8.  request.resource ⊑ eff.resources                  else resource_not_covered
      request.host     ∈ eff.aud                        else audience_mismatch
      request.purpose  ⊆ eff.purpose                    else purpose_not_covered
      request.task     matches eff.task                 else purpose_not_covered
      request.effect   ⊑ eff.effect                     else effect_not_permitted
      request.amount   ≤ eff.max_per_txn                else amount_exceeds_cap
      request.amount.cur == eff.currency                else currency_mismatch

  9.  pop_verify(request.http_signature, chain[-1].cnf.jkt)
                                                        else pop_failed

  10. return eff, window
```

**Step 3 has two halves, and only the first is a property of the chain.** "All
links agree on `ledger`" makes a chain internally consistent. On its own it
bounds nothing: agreement among the links says the delegation is coherent, not
that whoever is reading it is the party the Principal addressed it to. A Ledger
asked to `reserve` or `register` against a chain **MUST** therefore also check
that `chain[0].ledger` names *itself*, and refuse with `chain_invalid` otherwise.

Skipping it costs the budget. Consumption state (§10.1) is per-Ledger, so a
mandate a second Ledger will accept has a second `max_total` — the same grant
spends in full at every Ledger that takes it, with no rule above broken along the
way. This is the mirror of the check a Merchant already makes on a spend token's
`iss` (§14.2): every party refuses a credential naming a counterparty it is not.

Two notes on applying it. Trailing slashes are not significant, because
`{ledger}/v1/status/{root}` (§10.3.1) already treats `{url}` and `{url}/` as one
list and the two notions of Ledger identity must not diverge; nothing else is
normalized, since `ledger` is an identity to compare rather than a URI to
resolve. And the check binds *Ledgers*, not verifiers in general — a stateless
verifier, an offline Merchant, or a CLI holds no Ledger identity to compare
against and is bound only by the first half.

This constrains implementations, not the wire format: the bytes of a mandate and
its verdict at the Ledger it names are unchanged, so §17.3 is satisfied. What
changes is a deployment that was serving chains addressed elsewhere, which now
refuses them — correctly, and visibly rather than silently.

```
narrows(child_cav, parent_cav) -> bool

  for key in child_cav:
      if key ∉ REGISTRY[v]:              return false     # fail closed
      if parent_cav[key] is absent:      continue         # parent is ⊤ here
      if not REGISTRY[v][key].leq(child_cav[key], parent_cav[key]):
                                          return false
  return true
```

Note that `narrows` never materializes a ⊤ value: absence in the parent means
maximum authority, so the comparison is skipped rather than performed against a
sentinel. Four things in step 5 and 6 deserve their own note.

**`narrows(child.cav, acc)`, never `narrows(child.cav, parent.cav)`.** Pairwise
comparison admits a grandchild escape (§6.3) and is the single most likely way to
implement this wrong.

**`eff = acc`, not `chain[-1].cav`.** The fold is load-bearing, not defensive.
`narrows` only inspects keys the child *declares*, so a link that simply omits
`max_total` passes attenuation while declaring itself unbounded on that dimension.
The fold is what re-applies every ancestor's constraint to the leaf. Remove it and
a subagent reaches its grandparent's whole balance.

**`depth` is a counter, not an order.** The mandatory per-hop decrement lives here
rather than in the registry because `child ≤ parent − 1` is not reflexive, and a
non-reflexive relation in the lattice breaks `meet`, the post-condition, and the
algebraic laws a verifier's tests depend on. Omission inherits `remaining − 1`
rather than resetting to unbounded.

**`exp` / `nbf` narrow structurally**, against the immediate parent, because they
are claims rather than caveats (§6.2). The effective window is then the
intersection across all links.

The final `narrows(eff, link.cav)` sweep *is* genuinely redundant given a correct
step 5 — and worth the microseconds anyway. It converts a bug in `narrows` or in
any `meet` implementation from a silent privilege escalation into a rejected chain.

---

## 8. Presentation (Agent → Ledger)

```json
{
  "v": "am/1",
  "typ": "presentation",
  "chain": ["<jws_root>", "<jws_child_1>", "<jws_child_2>"],
  "req": {
    "quote_id": "qt_01J8XP9Q2R3S4T5U6V7W8X9Y0Z",
    "resource": "https://api.weatherco.com/v3/forecast/94110",
    "method": "GET",
    "amount": { "cur": "USD", "amt": "0.02" },
    "purpose": "research.readonly",
    "task_id": "tsk_01J8QQ1A2B3C4D5E6F7G8H9J0K",
    "nonce": "u7Kd9fQ2xR1vN0pL",
    "ts": 1770001234
  }
}
```

Links embed **by value**, not by reference. Self-contained offline verifiability is
the reason the substrate was chosen; at ~600 bytes per link, a depth-4 chain is
about 2.4 KB, which is acceptable.

The presentation **MUST** be signed by the leaf agent's key (RFC 9421 over the HTTP
request to the Ledger), providing proof of possession for the leaf.

`task_id` is bound into the signature. Together with the `purpose` caveat this is
the defence against a confused-deputy attack, where a subagent reuses authority
granted for one task to fund a different one.

---

## 9. Spend Token (Ledger → Agent → Merchant)

### 9.1 Claims

```json
{
  "v": "am/1",
  "typ": "spend",
  "jti": "spn_01J8XR5N6P7Q8R9S0T1U2V3W4X",
  "iss": "https://ledger.example.com",
  "aud": "api.weatherco.com",
  "sub": "did:key:z6MkAgentC...",
  "chain_hash": "sha256:9f2a4c...",
  "amt": { "cur": "USD", "amt": "0.02" },
  "res": "https://api.weatherco.com/v3/forecast/94110",
  "settle": "escrow_schema",
  "schema": "sha256:41bd8e...",
  "quote_id": "qt_01J8XP9Q2R3S4T5U6V7W8X9Y0Z",
  "iat": 1770001234,
  "exp": 1770001294,
  "cnf": { "jkt": "NzbLsXh8uDCcd7noWXFZAfHkxZsRGC9Xs4wLPBhWkQY" }
}
```

Single use. Sixty-second lifetime. Amount-exact. Audience-bound.

`chain_hash` is the SHA-256 of the canonical concatenation of the chain's JWS
strings. It commits the token to the authority that produced it without disclosing
that authority to the merchant.

### 9.2 Merchant verification (the entire integration)

```
1. verify_jws(token, ledger_public_key)     — key from the Ledger's did:web
2. token.aud == my_host
3. now ≤ token.exp + SKEW
4. token.jti not in replay_cache            — cache TTL ≥ 2 × token lifetime
5. pop_verify(http_signature, token.cnf.jkt)
```

Then serve, and settle per `token.settle` (§12).

**The order is normative.** The replay check **MUST** come after signature and
audience verification. A cache that records `jti` before validating the token
lets anyone burn a legitimate spend by presenting a forged token — or a token
addressed elsewhere — carrying that `jti`. The agent's real token then bounces as
a replay, and the money is already debited at the Ledger.

Cache TTL is **2× the token lifetime**, not the token's own `exp`: expiring
entries exactly at `exp` leaves a skew-width window in which a token is
simultaneously still acceptable and no longer remembered.

Five checks, one public key, no network call to the Ledger on the hot path. This is
the number that determines whether merchants adopt the protocol, and it is the
reason mandates are kept out of the merchant's view entirely.

---

## 10. Ledger semantics

### 10.1 Consumption debits the whole path

Caveats bound the *tree*. The Ledger enforces consumption *up the tree*:

```
spend(leaf_jti, amount):
    path = ancestors(leaf_jti) ++ [leaf_jti]        # root → leaf
    BEGIN ATOMIC
      for node in path:
          require not revoked(node)
          require remaining[node] ≥ amount
          require rate_ok(node)
      for node in path:
          remaining[node] -= amount
          rate_record(node)
    COMMIT
```

A $0.02 spend at depth 3 debits the grandchild, the child, **and** the root.

This is what makes sibling delegation safe without any coordination between
siblings: two subagents each granted `$10` under a `$20` parent can jointly spend
`$20`, never `$40`. Neither needs to know the other exists.

**Lock ordering is root-to-leaf and is not cosmetic.** A SQL implementation takes
`SELECT ... FOR UPDATE` on the path's rows in that order. Paths overlap
constantly — every spend under a principal touches the same root row — so two
concurrent spends that lock in different orders deadlock under normal load, not
under contrived conditions.

**Nodes materialize on first presentation.** There is no registration step: the
first time a chain is presented, the Ledger creates a counter per link seeded
from that link's declared `max_total`. A link that declares no `max_total` gets
no counter of its own and is bounded only by its ancestors.

**A `jti` MUST be bound to the exact mandate that introduced it.** The Ledger
stores a hash of the link's JWS at materialization and **MUST** reject a later
presentation of the same `jti` with a different hash. Without this, an issuer can
re-sign a mandate reusing a spent `jti` with a fresh `max_total` — every
signature valid, every caveat narrowing — and the consumption counter resets. The
signature chain alone does not prevent this; only the binding does.

### 10.2 Rate limiting

Every ancestor's `rate` caveat is evaluated independently at spend time, using the
same path walk. A leaf that satisfies its own rate caveat but would breach its
grandparent's is rejected with `rate_exceeded`.

### 10.3 Revocation

Revoking a `jti` kills the entire subtree beneath it on the next spend attempt.
In online mode this is instant and free, because the Ledger is already in the path
— no CRL, no OCSP, no propagation delay.

This is a significant advantage of online mode and implementations **SHOULD** treat
offline mode's weaker revocation story (§13) as the exception requiring
justification.

**A mandate that has never been presented is still revocable.** Consumption
state materializes on first presentation (§10.1), so a Ledger that stores
revocation *on that state* cannot record one for a mandate it has not seen — and
the first spend then creates the node unrevoked and goes through. A Ledger
**MUST** therefore keep revocation independent of materialization, and a node
created later **MUST** inherit it. Because an unmaterialized `jti` has no
recorded parent, the record is scoped to the `root` named in the control action
(§10.6): a principal may pre-revoke anything that turns out to be under their own
root, and nothing else.

#### 10.3.1 Status lists

An offline merchant (§13) is not on the Ledger's spend path and learns nothing
from Ledger-side revocation. A Ledger **MAY** publish a **status list**: one bit
per mandate under a root, gzipped, base64url-encoded, and signed with the same
key that signs Spend Tokens.

```json
{
  "v": "am/1", "typ": "status",
  "iss": "https://ledger.example.com",
  "sub": "mnd_01J8XQ...",
  "seq": 3,
  "iat": 1770001200, "exp": 1770001500,
  "bits": 131072, "enc": "gzip",
  "list": "H4sIAAAAAAAA…"
}
```

A mandate opts in by carrying `st`, a non-negative integer index (§5.1). Absence
means only "not revocable offline"; it is not an assertion of validity.

The list URI is **`{ledger}/v1/status/{root_jti}`** and is **derived, never
declared**. Both parts are already agreed by the chain — every link **MUST** name
the same `ledger` (§7), and the root `jti` heads the path — so an issuer has
nothing left to point at a host it controls that would answer "not revoked"
forever.

Bit *i* is byte `i >> 3`, most significant bit first, matching W3C Bitstring
Status List.

Requirements on a consumer, each of which closes an attack that `exp` alone does
not:

1. **Verify the signature before decompressing.** The payload is compressed and
   attacker-reachable; `gunzip` on unauthenticated input is a memory-exhaustion
   primitive. The declared `bits` then caps the inflated size, and a payload that
   decompresses to any other length **MUST** be refused — short is the dangerous
   direction, because the missing tail reads as "nothing is revoked".
2. **Refuse an expired list.** `exp` is mandatory. Whoever answers the fetch can
   otherwise serve one document forever and revocation silently stops
   propagating.
3. **Never accept a lower `seq` than one already held for that `sub`.** An older
   list that has not yet expired is a perfectly valid document, and serving it
   un-revokes everything revoked since. An *equal* `seq` **MUST** be accepted:
   `seq` counts revocations, so a quiet root republishes the same number, and
   discarding those refreshes would expire the consumer's cache while nothing was
   wrong.
4. **Fail closed.** A chain carrying `st` that cannot be checked is refused with
   `status_unknown` (§15) — a 503, because "I could not find out" is not "this is
   revoked". Failing open would make breaking the fetch the way to bypass the
   check.

A Ledger **MUST** build the list as the **union** of its revoked indices rather
than by writing each mandate's bit from its own state. If two mandates share an
index — an issuer allocation bug — the union costs an unnecessary refusal, while
per-mandate writes let an unrevoked mandate clear a revoked one's bit in whatever
order the rows arrive.

Revocation latency becomes the list's lifetime rather than the mandate's `exp`.
§13 already requires the merchant to contact the Ledger every 60 seconds, so a
list refreshed on that heartbeat costs no connectivity the merchant did not
already owe — but see §13, which is why this does not license a longer `exp`.

### 10.4 Circuit breakers

Autonomous spend fails catastrophically rather than gradually: a retry loop against
a $0.05 endpoint burns $500 overnight while nobody is watching. The Ledger
**SHOULD** implement, independent of any caveat:

| Breaker | Trigger | Action |
|---|---|---|
| Velocity anomaly | Spend rate > *k* × rolling 7-day median for the subtree | Alert; optionally hold |
| Burn-rate projection | `remaining / current_rate` < threshold minutes | Alert with time-to-exhaustion |
| Per-task ceiling | Cumulative spend for a `task_id` exceeds configured cap | Reject `budget_exhausted` |
| Novel-merchant | First-ever spend to a host for this principal | Optional step-up |
| Global kill | Operator action | Reject all spends for principal |

Breakers act on the *subtree*, using the same path walk as §10.1.

### 10.5 Step-up

If `eff.step_up.over` is present and `request.amount` exceeds it, the Ledger
**MUST NOT** mint a token. It returns `step_up_required` with an approval handle;
the agent polls or subscribes; a human approves out of band. This is the escape
hatch that keeps high-value transactions attended while leaving the long tail
autonomous.

**The handle is not the approval.** The Ledger hands it to the agent in the
`step_up_required` response, so an implementation that admits a spend on
presentation of the handle is admitting it on the agent's own say-so. A handle
records *that a question was asked*; the approval is a separate signed answer.

A request is therefore in one of three states — `pending`, `approved`, `denied` —
and a Ledger **MUST** admit a spend only against `approved`, exactly once.

#### Decisions

A decision is a compact JWS with `typ: application/agent-approval+jwt`, signed by
the mandate's **trusted root issuer**. The same key that granted the authority is
the one that may exceed its own threshold, so this needs no new trust root.

```json
{
  "v": "am/1",
  "typ": "approval",
  "handle": "stp_01J8XT...",
  "iss": "did:web:acme.example",
  "verdict": "approve",
  "root": "mnd_01J8XQ...",
  "res": "https://api.weatherco.com/v3/forecast/94110",
  "amt": { "cur": "USD", "amt": "5.00" },
  "iat": 1770000120,
  "exp": 1770001020
}
```

`root`, `res` and `amt` restate the terms, and a Ledger **MUST** check all three
against its own record for `handle` before honouring the decision. A signature
over the handle alone attests only that the principal saw an opaque identifier;
it cannot distinguish the request they were shown from any other. `amt` is
compared as "at least the amount requested", and a decision for less is refused
rather than clamped.

A Ledger **SHOULD** measure the spendable window of an approved request from the
decision rather than the request, so that approving late does not hand the agent
a window of seconds.

An implementation **SHOULD** collapse repeat requests for identical terms onto
one pending handle. §10.5 has the agent polling, and a fresh request per poll
buries the human in duplicates of one question — which is how a step-up queue
stops being read.

---

### 10.6 Control actions

A principal has two levers over a subtree that already exists: halt it, and
revoke a link in it. Both change what an agent may do, so both **MUST** be
authenticated, and for the same reason step-up decisions are (§10.5) — **the
party being restrained must not be able to lift the restraint.**

A control action is a compact JWS with `typ: application/agent-control+jwt`:

```json
{
  "v": "am/1",
  "typ": "control",
  "jti": "ctl_01J8XV...",
  "iss": "did:web:acme.example",
  "action": "kill",
  "root": "mnd_01J8XQ...",
  "iat": 1770000300,
  "exp": 1770000600
}
```

`action` is one of `kill`, `release`, `revoke`. A `revoke` **MUST** carry
`target`, the mandate `jti` to revoke, and that mandate **MUST** be in `root`'s
subtree.

Before applying one, a Ledger **MUST**:

1. **consume `jti` exactly once, durably.** Unlike a step-up decision, a control
   action names no one-shot handle, so nothing else prevents replay. A replayed
   `kill` is harmless; a replayed `release` restarts spending that a principal
   deliberately halted, and an agent that captured one only has to wait for the
   next incident. An in-memory cache is insufficient — a halted principal is
   precisely the situation likely to involve a restart.
2. **check that `iss` issued `root`.** Being *a* trusted root issuer is not the
   same as being *this* subtree's principal, and a deployment serving more than
   one principal would otherwise let either halt or revoke the other's mandates.
   This requires the Ledger to have recorded the issuer of each mandate at the
   time it first debited against it.

Control decisions **SHOULD** be short-lived. The nonce stops the second use; it
does nothing about the first, so a captured decision that has not been used yet
is live until `exp`.

Because a control action carries its own authority, the endpoint that accepts one
needs no authentication of its own. That is what makes it safe to expose to the
network the agent is on — which is the network the kill switch most needs to be
reachable from.

## 11. Receipt

```json
{
  "v": "am/1",
  "typ": "receipt",
  "jti": "rcp_01J8XS7P8Q9R0S1T2U3V4W5X6Y",
  "spend": "spn_01J8XR5N6P7Q8R9S0T1U2V3W4X",
  "chain_hash": "sha256:9f2a4c...",
  "path": ["mnd_root...", "mnd_a...", "mnd_b..."],
  "agent": "did:key:z6MkAgentC...",
  "principal": "did:web:acme.example",
  "task": "tsk_01J8QQ1A2B3C4D5E6F7G8H9J0K",
  "res": "https://api.weatherco.com/v3/forecast/94110",
  "amt": { "cur": "USD", "amt": "0.02" },
  "req_hash": "sha256:c1d4...",
  "resp_hash": "sha256:7a3e...",
  "resp_bytes": 4210,
  "status": "settled",
  "ts": 1770001240,
  "sigs": {
    "merchant": "<jws detached>",
    "ledger": "<jws detached>"
  }
}
```

`status` ∈ `reserved` | `settled` | `refunded` | `disputed` | `expired`.

Receipts are **not deferrable to a later version**. When no human approved the
individual transaction, the signed receipt trail is the only thing that makes the
spend legitimate after the fact, and it is what a finance or compliance function
will actually ask for. Retrofitting a signed audit trail onto a ledger that did not
have one is substantially harder than building it in.

`path` makes rollup by principal, task, or subtree a single indexed query.
`resp_hash` is what makes conditional settlement enforceable (§12).

---

## 12. Settlement modes

| Mode | Behaviour |
|---|---|
| `immediate` | Funds move on response. Simplest; no recourse. |
| `escrow_schema` | Funds held; released when `resp_hash` validates against the `schema` hash declared in the Spend Token. Auto-refund on mismatch or timeout. |
| `escrow_human` | Funds held pending explicit principal approval. |

`escrow_schema` is the machine-speed substitute for a chargeback. An agent cannot
file a dispute over $0.03, and a 30-day human dispute cycle is meaningless at that
scale. Making payment conditional on the response validating against a
merchant-declared schema moves recourse from *after the fact and human* to *at the
moment and automatic*.

Escrow timeout is a Ledger policy parameter; the default **SHOULD** be short
(minutes), and expiry **MUST** result in refund, not capture.

### 12.1 Refund attribution

A refund credits the budget counter on **every node the debit touched**,
symmetrically — the same path walk as §10.1, with the sign inverted.

**Rate counters are NOT credited back.** A refunded call still reached the
merchant and still consumed a request slot. Restoring it would make a
consistently failing endpoint an unlimited-rate endpoint, which is precisely the
shape of the retry storm the `rate` caveat exists to bound.

Nodes revoked or expired between reserve and refund are credited anyway. The
counter is meaningless for a dead mandate, and skipping it would make the
ancestor totals disagree with the sum of their receipts, which is the one thing
reconciliation depends on.

### 12.2 Settlement rails

Nothing in §1–§11 moves money. Authority, budgets, breakers and receipts are all
bookkeeping; a **rail** is what performs the transfer — x402/USDC, Lightning, a
card capture, or a book entry between two accounts on the same Ledger.

Two integration shapes exist, and the easier one is the less obvious one:

| Shape | Merchant implements | Trade |
|---|---|---|
| **A — Ledger pays an existing rail on the agent's behalf** | nothing | Merchant sees an ordinary rail client. No privacy or offline-verification benefit, but adoption cost is zero. |
| **B — Merchant accepts Spend Tokens natively** (§14) | §9.2 + §14.5 + RFC 9421 | Better privacy and audit; needs the merchant to move first. |

Shape A is the wedge. Asking a merchant to implement §14 before a single agent
has paid them anything inverts the order of value. The agent never holds the
rail's wallet in either shape, which is the point: a held wallet is unbounded
authority.

**The Ledger MUST NOT call a rail inside the consumption critical section.** A
transfer is a network call; §10.1's atomic section is not. Settlement is three
phases — decide and claim, pay, finalize — with the claim marking the reservation
`settling` so a concurrent settle cannot pay twice.

#### 12.2.1 Terminal versus indeterminate

A rail failure has three outcomes, not two, and collapsing the third is the
single most expensive mistake available here:

| Outcome | Meaning | Required response |
|---|---|---|
| success | Transfer landed | Mark `settled`, record the rail reference |
| **terminal** failure | Definitively did not transfer — rejected quote, 4xx, unrepresentable amount | Credit the path back, mark `refunded` |
| **indeterminate** | Timeout, reset, 5xx, unparseable response | Leave `settling`. Do **not** refund. |

Refunding on a timeout pays the merchant *and* hands the money back to the agent.
Capturing on a timeout charges for a request that may never have been served.
Neither is acceptable, so the state machine needs somewhere to wait.

Implementations **MUST** provide a reconciliation pass that resolves `settling`
reservations by asking the rail what happened. A deployment without one silently
accumulates funds that are neither spent nor available.

`sweepExpired` (§12) **MUST NOT** touch `settling` reservations — expiry applies
to tokens nobody redeemed, not to payments in flight.

#### 12.2.3 Cadence and escalation

A reconciliation pass **MUST**:

1. ask the rail about every `settling` reservation, and apply the three-outcome
   rule above;
2. **escalate** any reservation the rail could not resolve after a configured
   age, measured from when it entered `settling`;
3. sweep expired-unredeemed reservations, subject to the directive rule below.

Asking before escalating is required in that order: a reservation the rail can
resolve on this pass **MUST NOT** be escalated, so a human is only ever
interrupted for something genuinely undecidable.

**Escalation moves no money.** The reservation stays `settling` and stays
debited. It is in that state precisely because nobody knows whether the payment
landed, and §12.2.1 already establishes that guessing costs either a double-spend
or a stranded balance. What escalation changes is that somebody is told.
Escalation **MUST** be idempotent — a reservation already escalated is not
re-raised on every subsequent pass, or the alert becomes noise and stops being
read.

The age threshold is a deployment policy: it depends on the rail's own settlement
window, and no universal value is defensible. **Having one is not optional.** A
deployment that never escalates has re-created the silence that made the
`settling` state necessary, one layer further out.

A pass **SHOULD** report the count of outstanding `settling` reservations and the
age of the oldest. That count trending upward is the signal that a rail has
stopped answering, and it is the number worth paging on.

A rail that throws **MUST NOT** end the pass. Reconciliation is the component
that runs unattended; one failing dependency degrades it, and must not stop it
from escalating and sweeping what it still can.

**Non-custodial escalation is not a clock.** Under §12.4.5 a rail without
`hardExpiry` can never turn "unconfirmed" into "never happened", so those
reservations escalate on the rail's declared capabilities rather than on elapsed
time — and they escalate from `reserved`, not only from `settling`, because an
agent can execute a directive and never report. A reconciler that only inspects
the `settling` queue will miss them.

#### 12.2.2 Idempotency belongs in the rail's own key

Rails **SHOULD** derive their idempotency key deterministically from the spend
`jti` rather than from randomness. On x402 this means the EIP-3009 authorization
nonce is `H("am/1:x402:" ‖ spendId)`: the token contract rejects a nonce it has
already seen, so a settlement retried after a crash is deduplicated *by the chain
itself*, regardless of what state the Ledger's own records ended up in. That is a
stronger guarantee than any bookkeeping on this side of the wire.

#### 12.2.3 Verify the rail's wire format against a live capture

Rail adapters **SHOULD** be built against a recorded response from the target
deployment, not from protocol documentation. x402 v1 and v2 disagree on the
location of the challenge (response body versus a base64 `PAYMENT-REQUIRED`
header), the payment header name (`X-PAYMENT` versus `PAYMENT-SIGNATURE`), the
price field (`maxAmountRequired` versus `amount`), and the network identifier
(bare nickname versus CAIP-2). An adapter written from the v1 documentation fails
against a v2 merchant at the first parse.

The subtler class of error is a field that is *accepted* but wrong. The EIP-712
domain name for Base USDC is `USD Coin`, not `USDC`; signing over the wrong
domain yields a well-formed signature the token contract rejects, and the failure
surfaces at settlement rather than at build time. Adapters **MUST** take the
domain from the challenge's own metadata rather than hard-coding it.

Where a merchant returns no settlement receipt, the rail's own authorization
identifier stands in — for EIP-3009 that is `(from, nonce)`, which is checkable
on-chain via `authorizationState()`. A receipt that records nothing verifiable is
worse than one that records an identifier the reader can resolve themselves.

#### 12.2.4 Precision is not negotiable downward

Protocol amounts carry nine decimal places (§4.3). Rail assets carry fewer —
USDC carries six. An amount that cannot be expressed exactly in the rail's atomic
units **MUST** be a terminal failure, never a rounding decision.

Truncating `0.0000005` to zero atomic units means the merchant serves the request
for free, forever, and nothing in the system reports a problem. The mandate layer
can express prices this rail cannot settle, and the honest response is to refuse
the settlement rather than quietly approximate it.

### 12.3 Who decides that escrow releases

Unresolved, and worth stating plainly rather than burying: under
`escrow_schema` the party asserting that the response failed validation is the
party that gets its money back. That is a bad incentive on its face.

The partial answer this specification provides is that both sides sign the
receipt, including `resp_hash`, so a dishonest verdict is recorded and
adjudicable after the fact. That converts theft into a disputable claim, which is
weaker than prevention. A merchant unwilling to accept that exposure should quote
`immediate` and price the risk in. Genuinely fixing it needs either a
Ledger-side validator (which means the Ledger reads response bodies — a large
privacy and scaling cost) or a third-party attestation, and neither is specified
here.

### 12.4 Non-custodial settlement

Everything in §12.2 assumes the Ledger holds a funded wallet and pays out of it.
That is the simplest thing to build and the most expensive thing to operate: a
service holding prepaid balances and moving funds on a user's behalf is doing
something regulators have a name for, and the exposure lands on the operating
company rather than on the product.

This section specifies the variant where **the Ledger never holds funds**.

#### 12.4.1 The custody spectrum

| Tier | Ledger's role | Prevents overspend? | Holds funds? | Cost |
|---|---|---|---|---|
| **Custodial** (§12.2) | Holds the wallet, signs and submits | Yes — the agent has no funds to misuse | Yes | Cheap to build, expensive to operate |
| **Directive** (this section) | Authorizes, bounds, records; the agent signs | **No — detective only** | No | Cheap both ways |
| **Co-signed account** (§12.4.7) | Holds a veto key on a smart account | Yes | No — principal can exit unilaterally | Expensive to build, cheap to operate |

The middle tier is the subject of this section. Implementations **SHOULD** ship it
before the custodial tier, and **SHOULD** design for the third.

#### 12.4.2 The honest threat model

> **A non-custodial mandate cannot prevent a spend. It can only account for one.**

If the agent holds the signing key, it can always ignore the Ledger and pay a
merchant directly. No credential, caveat, or breaker changes that. Any
specification claiming otherwise is describing a control it does not have.

What the Ledger provides instead is **detective control**: every authorized
transfer is bound to a directive, every directive is recorded, and any wallet
outflow without a matching directive is a detectable unauthorized spend. This is
the same shape as a corporate card — misuse is possible, and the control is
detection plus consequence rather than physical impossibility.

Deployments **MUST** state which control they are providing. Selling detective
control as preventive is the failure mode that matters here, because a principal
who believes an agent *cannot* overspend will set a budget they are not willing
to actually lose.

#### 12.4.3 The Settlement Directive

Replaces the Spend Token on the payment path. Where a Spend Token tells a
*merchant* that a charge is authorized, a Directive tells an *agent* exactly what
it is permitted to sign — and nothing else.

```json
{
  "v": "am/1",
  "typ": "directive",
  "jti": "spn_01J8XR5N6P7Q8R9S0T1U2V3W4X",
  "iss": "https://ledger.optera.one",
  "sub": "did:key:z6MkAgentC...",
  "chain_hash": "sha256:9f2a4c...",
  "rail": "x402",
  "payer": "0x1111111111111111111111111111111111111111",
  "domain": {
    "name": "USD Coin",
    "version": "2",
    "chainId": 8453,
    "verifyingContract": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
  },
  "authorization": {
    "from": "0x1111111111111111111111111111111111111111",
    "to": "0x65E3E64935eA709bDf1119E1fC991299c04c0154",
    "value": "1000",
    "validAfter": "1770001180",
    "validBefore": "1770001540",
    "nonce": "0x9c1f...e4"
  },
  "directive_hash": "sha256:71ac...",
  "iat": 1770001240,
  "exp": 1770001300,
  "cnf": { "jkt": "NzbLsXh8uDCcd7noWXFZAfHkxZsRGC9Xs4wLPBhWkQY" }
}
```

**Every field of the transfer is pinned.** A directive that leaves `to`, `value`,
or the domain free is not a constraint, it is a suggestion: an agent given
latitude over `to` can redirect the payment and still present a technically
conforming report. `directive_hash` is the SHA-256 of the canonical serialization
(§11) of `domain` ‖ `authorization`, and it is what the Ledger records and later
compares against.

`nonce` is computed by the **Ledger**, deterministically from `jti` per §12.2.2.
The agent does not choose it. This is what makes §12.4.5 work.

#### 12.4.4 The `payer` caveat

Add to the §6.2 registry:

| Caveat | Type | ⊤ (absent) | `child ⊑ parent` iff |
|---|---|---|---|
| `payer` | rail account identifier | any registered account | `child == parent` |

Discrete equality, exactly like `task` and `currency`: a child may pin it, never
widen it, and the meet of two different payers is ⊥ (§6.3). It slots into the
existing lattice with no new machinery.

A principal delegating to a subagent can therefore bind that subagent to a
specific funding wallet — which is how you give one agent a small hot wallet
without exposing the treasury account the parent mandate could otherwise reach.

#### 12.4.5 Reconciliation without observability

The Ledger no longer performs the payment, so it cannot observe the outcome. The
agent's report is not evidence — it is a claim by the party with an incentive.

Resolution is a **chain read against the deterministic nonce**:

```
authorizationState(directive.payer, directive.authorization.nonce)
```

EIP-3009 exposes this on the token contract, and it returns true exactly when
that authorization has been consumed. The Ledger computed the nonce, so it can
ask this question at any time without trusting anyone.

This is the real reason §12.2.2 required deterministic nonces. Idempotency was
the visible benefit; **non-custodial observability is the load-bearing one.**

The state machine gains a property the custodial version lacks:

| Condition | Outcome |
|---|---|
| nonce consumed | `settled` — funds left the payer |
| nonce unconsumed, `validBefore` in the future | genuinely unknown; stay `settling` |
| nonce unconsumed, `validBefore` **passed** | `refunded` — the authorization can never be used |

`validBefore` is a cryptographic deadline, not a timeout heuristic. After it
passes the signature is permanently unusable, so the indeterminate state has a
**guaranteed resolution time**. Custodial settlement has no equivalent: a
transfer submitted into a network partition can land at any point. Non-custodial
reconciliation is strictly more decidable, which is an unusual direction for a
security-motivated change to move.

Implementations **MUST** set `reservationGraceSeconds` to at least
`validBefore − validAfter` so the sweep never runs ahead of decidability.

#### 12.4.6 Verifying the agent's report

```
report(jti, { signature, merchant_status, ref? })
```

The Ledger **MUST**:

1. Recover the signer of `signature` over the EIP-712 typed data reconstructed
   from the stored directive.
2. Require that it equals `directive.payer`.
3. Require that the reconstructed tuple hashes to `directive_hash`.

Steps 1–3 catch an agent that signed *something else* at report time rather than
at reconcile time, which is worth the round trip: the failure is then attributable
to a specific agent and a specific directive rather than surfacing later as an
unexplained budget hole.

A report is never sufficient on its own. Settlement **MUST** be confirmed by
§12.4.5 regardless of what the report says. A report that claims payment against
an unconsumed nonce is a first-class event — refund the budget, and record it
against the agent, because the benign explanations and the malicious one look
identical from here.

Two new seams are required, both verification-only, neither ever touching a
private key:

```ts
interface Eip712Verifier {
  recover(domain: Eip712Domain, authorization: Eip3009Authorization, signature: string): string;
}

interface ChainReader {
  authorizationState(token: string, from: string, nonce: string): Promise<boolean>;
}
```

#### 12.4.7 Bypass detection

The one control the Ledger genuinely has over an agent that ignores it: watch the
payer account.

Implementations **SHOULD** reconcile observed outflows from each registered
`payer` against issued directives, and treat any transfer with no matching
directive as an unauthorized spend — alert, revoke the subtree (§10.3), and trip
the global kill (§10.4). Detection latency is bounded by how often the account is
read, and that latency **SHOULD** be disclosed to the principal, because it is the
real exposure window.

**Prevention without custody** is available at the third tier: hold the funds in
a smart account that releases only against a Ledger co-signature, with a
principal-controlled unilateral withdrawal after a timelock. The Ledger holds a
veto key rather than the funds — it cannot spend them and cannot freeze them.
That is the correct destination for a deployment that needs preventive control
and cannot accept custody, and it is out of scope here only because it requires
on-chain contracts this specification does not define.

---

## 13. Offline mode (OPTIONAL)

Constraints, all of which are **MUST** when the merchant settles without contacting
the Ledger:

1. `aud` resolves to exactly one host — no wildcards.
2. `max_total` is present and scoped to that merchant.
3. `exp` − `nbf` ≤ 1 hour.
4. `settle` is `immediate` (escrow requires Ledger participation).
5. The merchant reports consumption to the Ledger asynchronously, at least every 60
   seconds.

Worst-case loss from parallel presentation is bounded by the sum of per-merchant
offline `max_total` values across all merchants named in live offline mandates.
Implementations **MUST** surface this figure to the principal as a configured risk
budget rather than leaving it implicit.

Revocation in offline mode is bounded only by `exp` unless the merchant consults
a status list (§10.3.1), which replaces that bound with the list's own lifetime.
A merchant doing so **MUST** refresh off the spend path — the point of offline
mode is that settling touches no network — and **SHOULD** refresh on the same
60-second heartbeat requirement 5 already imposes, which costs it no connectivity
it did not already owe.

This does **not** license a longer `exp`. The one-hour cap bounds two different
losses, and a status list addresses only one of them: worst-case parallel
presentation is still the sum of live offline `max_total`s, and nothing about
revocation changes that.

---

## 14. HTTP binding

All three headers are RFC 8941 **Dictionaries**, not parameterized Items. A
parameter value may not be an Inner List, and `settle` has to advertise more than
one mode — so the obvious `agent-mandate;v=1;settle=("immediate" …)` spelling is
not valid Structured Fields at all.

### 14.1 Challenge

```http
HTTP/1.1 402 Payment Required
Content-Type: application/problem+json
Accept-Payment: scheme=agent-mandate, v=1, ledger="https://ledger.example.com",
  quote="qt_01J8XP9Q2R3S4T5U6V7W8X9Y0Z", amount="0.02", currency="USD",
  settle=(immediate escrow_schema), schema="sha256:41bd8e...", exp=1770001294
```

`amount` is a String, never an sf-Decimal: sf-Decimals carry at most three
fractional digits and are floating-point on the wire, and per-call pricing runs
below a tenth of a cent (§4.3).

### 14.2 Payment

```http
GET /v3/forecast/94110 HTTP/1.1
Host: api.weatherco.com
Payment: scheme=agent-mandate, v=1, token="eyJhbGciOiJFZERTQSI..."
Signature-Input: pay=("@method" "@target-uri" "payment");created=1770001240;keyid="did:key:z6Mk...";alg="ed25519"
Signature: pay=:2FZ9k1...:
```

The RFC 9421 signature **MUST** cover `@method`, `@target-uri`, and `payment`,
and the merchant **MUST** verify that the presented covered-component list
actually contains them. A signature over `@method` alone verifies
cryptographically and proves nothing about what is being paid for; treating "a
valid signature exists" as sufficient is the failure mode here.

Clients **MUST** add the `Payment` header *before* signing. Signing first and
appending payment afterwards yields a signature that verifies while covering
nothing about the payment — a token any interceptor can lift onto a different
request.

### 14.3 Success

```http
HTTP/1.1 200 OK
Payment-Receipt: id="rcp_01J8XS7P8Q9R0S1T2U3V4W5X6Y", ledger="https://ledger.example.com"
```

### 14.4 Discovery

`GET /.well-known/agent-payment` returns supported versions, accepted ledgers,
settlement modes, the signature algorithms and required covered components, and a
pricing table or pricing endpoint.

### 14.5 Merchant obligations beyond §9.2

Verifying the spend token is necessary and not sufficient. Before serving, a
merchant **MUST** also check:

| Check | Why |
|---|---|
| `token.iss` is the ledger it trusts | Otherwise any ledger's signature is accepted, including one the agent stood up |
| `token.res` equals the canonicalized request URI | Otherwise a token minted for a cheap endpoint pays for an expensive one inside its 60s window |
| `token.amt` equals the currently quoted price | Otherwise a stale cheap quote is honoured after a reprice (see §18 #3) |

The request signature is verified **before** the spend token, so an unsigned or
badly-signed request never reaches the replay cache (§9.2).

**Note on expiry ordering.** The RFC 9421 `created` tolerance and the spend
token's TTL are both 60 seconds, so a slow agent trips both at once and the
signature check — which runs first — is what reports. The observed error is
`pop_failed`, not `token_expired`. Implementations **SHOULD** say so in their
error detail rather than leaving an agent to conclude its key is wrong.

---

## 15. Error codes

Returned as `application/problem+json` (RFC 9457) with `type`
`https://agentmandate.org/errors/{code}`.

| Code | HTTP | Meaning |
|---|---|---|
| `chain_invalid` | 400 | Structural or signature failure |
| `unknown_caveat` | 400 | Unregistered caveat key — fail closed |
| `attenuation_violation` | 403 | A child widened its parent |
| `depth_exceeded` | 403 | Delegation deeper than permitted |
| `mandate_expired` | 403 | Outside the effective validity window |
| `mandate_revoked` | 403 | A link in the path is revoked |
| `status_unknown` | 503 | A link claims a status list entry that could not be checked (§10.3.1) |
| `pop_failed` | 401 | Request signature does not match `cnf.jkt` |
| `resource_not_covered` | 403 | Resource outside `resources` |
| `audience_mismatch` | 403 | Host outside `aud`, or token `aud` ≠ merchant |
| `purpose_not_covered` | 403 | Purpose or task outside grant |
| `effect_not_permitted` | 403 | Declared blast radius broader than `effect`; absent counts as `irreversible` |
| `currency_mismatch` | 400 | Cross-currency comparison attempted |
| `amount_exceeds_cap` | 403 | Over `max_per_txn` |
| `budget_exhausted` | 402 | Some ancestor has insufficient remaining |
| `rate_exceeded` | 429 | Some ancestor's rate caveat breached |
| `step_up_required` | 403 | Human approval needed; includes approval handle |
| `token_expired` | 401 | Spend token past `exp` |
| `token_replayed` | 409 | `jti` already seen |
| `breaker_tripped` | 403 | Circuit breaker halted the subtree |

---

## 16. Security considerations

| Attack | Mitigation |
|---|---|
| Unknown-caveat bypass | Registry pinned by `v`; unrecognized key rejects the chain (§6.3) |
| Stolen mandate replayed | `cnf` PoP binding at every link (§5.2) |
| Confused deputy | `purpose` caveat + `task_id` bound into the presentation signature (§8) |
| Pattern widening via encoding | Canonicalize before compare; restricted grammar, no regex (§6.4) |
| Algorithm confusion | Static `alg` allowlist; `alg` never selects the key (§4.1) |
| Spend-token replay | `jti` cache, 60s expiry, `aud`-bound, signature covers `Payment` header |
| Replay-cache poisoning | Replay check runs *after* signature and audience (§9.2), so a forged token cannot burn a real `jti` |
| Signature covering nothing useful | Merchant checks the declared covered-component list contains `@method`, `@target-uri`, `payment` (§14.2) |
| Token lifted to a pricier endpoint | Merchant checks `token.res` against the canonical request URI (§14.5) |
| `jti` re-issue to reset a budget | Ledger binds each `jti` to its JWS hash at materialization (§10.1) |
| Deadlock as a denial of service | Path rows locked root-to-leaf, always (§10.1) |
| Free service via precision truncation | Amounts below the rail's asset precision are a terminal failure, never rounded (§12.2.4) |
| Double transfer after a crash | Rail idempotency key derived from the spend `jti` (§12.2.2) |
| Refund-on-timeout draining a principal | Indeterminate settlements wait in `settling` for reconciliation (§12.2.1) |
| Agent redirects a non-custodial payment | Directive pins every transfer field; `directive_hash` is compared on report (§12.4.3, §12.4.6) |
| Agent falsely reports payment | Settlement confirmed by chain read, never by the report (§12.4.5) |
| Agent bypasses the Ledger entirely | **Not preventable non-custodially.** Detected by payer-account reconciliation (§12.4.7) |
| Cross-merchant parallel spend | Online: Ledger is authoritative. Offline: per-merchant caps bound loss (§13) |
| Status-list rollback un-revoking a mandate | Consumer refuses any `seq` below one already held for that `sub` (§10.3.1) |
| Status list pinned to hide a revocation | `exp` is mandatory and a stale list is refused rather than served (§10.3.1) |
| Status list as a decompression bomb | Signature verified before `gunzip`; declared `bits` caps the inflated size (§10.3.1) |
| Blocking the status fetch to bypass the check | A chain carrying `st` that cannot be checked is refused, not admitted (§10.3.1) |
| Spending a mandate revoked before its first use | Revocation is recorded independently of materialization and inherited by the node (§10.3) |
| Key compromise at depth *n* | Blast radius limited to that subtree's caveats; short `exp` + subtree revoke |
| Retry-storm griefing | `rate` caveat enforced at every ancestor + burn-rate breaker (§10.4) |
| Clock skew abuse | ±60s hard tolerance; Ledger clock authoritative online (§4.5) |
| Sibling collusion | Path-walk debit makes joint spend bounded by the common ancestor (§10.1) |
| Ledger compromise | Full compromise of the principal's funds. Ledger keys **MUST** be in an HSM; receipts are dual-signed so merchant records provide independent reconstruction. |

**Residual risk worth stating plainly.** The Ledger is a single point of both
failure and trust. Availability failure blocks all online spending; key compromise
is total. Dual-signed receipts mean the transaction history can be independently
reconstructed from merchant records, but they do not prevent a compromised Ledger
from minting valid tokens. Any production deployment needs HSM-backed keys,
independent reconciliation against merchant receipts, and a documented
degraded-mode posture.

---

## 17. Conformance profiles

### 17.1 `am/1-core` (v0 — build this first)

- Root mandates plus **one** level of attenuation (`MAX_DEPTH` = 2)
- Caveats: `max_total`, `max_per_txn`, `aud`, `resources`, `currency`
  (the validity window is carried by the `exp` / `nbf` claims, always)
- Online mode only
- `settle: immediate` only
- Receipts **required**

Depth 2 covers "my agent hires a subagent," which is essentially all real usage
today. Everything omitted here can be added later without invalidating mandates
already issued — with one exception.

### 17.2 `am/1-full`

Adds `rate`, `purpose`, `task`, `depth`, `delegable`, `settle`, `step_up`; depth up
to 4; offline mode; escrow settlement; circuit breakers.

### 17.3 The one thing that cannot be deferred

**The caveat lattice semantics are a wire-format commitment.** A mandate issued
under `am/1` and stored for 30 days must verify identically on day 30. Changing a
comparator's meaning later silently changes what previously-issued mandates
authorize — which is a security regression that no version bump can retroactively
fix for credentials already in the wild.

So: implement the full comparator table in §6.2 on day one, even for caveats the v0
profile never emits. Reject unregistered keys from the first commit. Everything
else is additive.

---

## 18. Open questions

1. **Cross-ledger delegation.** Can an agent under Ledger A sub-delegate to an agent
   settling on Ledger B? Requires inter-ledger consumption accounting. Currently
   forbidden by *both* halves of §7 step 3 — the links must agree on `ledger`,
   and the serving Ledger must be the one they agree on. The second half is what
   does the work here: without it the question answers itself in the worst way,
   since a chain naming B is simply accepted by A and the "forbidden" case is the
   supported one.
2. **Escrow release incentives.** Under `escrow_schema` the payer decides whether
   it pays. Dual-signed receipts make a dishonest verdict adjudicable but do not
   prevent it. See §12.3 — this is the largest unresolved gap in the design.
3. **Quote binding.** Should `quote_id` be cryptographically bound to the merchant's
   402 response, so an agent cannot present a stale cheap quote against a
   repriced resource?
4. **Delegation to non-agent principals.** Human-to-human sub-delegation of a
   spending mandate is structurally identical; whether to model it is a product
   question with regulatory consequences.
5. **Privacy of `path` in receipts.** It reveals org structure to whoever reads the
   receipt. A salted-hash form would preserve rollup while hiding topology, at the
   cost of making audit harder.
6. **Interop with AP2 / ACP.** Both are plausible rails or peers beneath this
   control plane; x402 is implemented (§12.2). An adapter mapping an AP2 Intent
   Mandate onto a root `am/1` mandate looks tractable and would be worth
   prototyping early.
7. **Escrow across a rail that cannot reverse.** `escrow_schema` assumes funds can
   be held and released. An on-chain transfer clears immediately and
   `SettlementRail.refund` is optional for good reason. Either the Ledger holds
   the float itself (becoming a custodian, with everything that implies) or
   escrow is only offered on rails that support holds. Currently unspecified.
8. ~~**Reconciliation cadence and alerting.**~~ **Answered, in §12.2.3.** The
   duration stays a deployment policy — it depends on the rail's own settlement
   window and no universal value is defensible — but the requirement to have one,
   and to escalate rather than guess when it elapses, does not.
9. **Co-signed spend accounts.** §12.4.7 names the tier that gets prevention
   without custody but does not define the contract, the session-key format, or
   the timelock semantics for unilateral principal withdrawal. This is the main
   piece of unfinished design in the non-custodial direction.
10. **Non-EIP-3009 rails.** §12.4.5 depends on `authorizationState` — a
    pre-authorization the payer signs and someone else submits, observable
    on-chain. Rails without that shape (a card capture, a Lightning payment) have
    no equivalent trustless oracle, and the directive model does not obviously
    transfer to them.

---

## Appendix A — Worked example

Principal grants Agent A a $50/day research budget. A delegates $10 to subagent C
for one task, restricted to one vendor and one hour.

**Root** (`mnd_root`, signed by `did:web:acme.example#k1`):

```json
{ "sub": "did:key:z6MkA...", "par": null, "exp": 1770086400,
  "cav": { "max_total": {"cur":"USD","amt":"50.00"},
           "max_per_txn": {"cur":"USD","amt":"2.00"},
           "aud": ["*.datavendor.io", "api.weatherco.com"],
           "purpose": ["research.readonly"],
           "depth": 2, "delegable": true } }
```

**Child** (`mnd_c`, signed by `did:key:z6MkA...`):

```json
{ "sub": "did:key:z6MkC...", "par": "mnd_root", "exp": 1770004800,
  "cav": { "max_total": {"cur":"USD","amt":"10.00"},
           "max_per_txn": {"cur":"USD","amt":"0.50"},
           "aud": ["api.weatherco.com"],
           "resources": ["https://api.weatherco.com/v3/forecast/*"],
           "purpose": ["research.readonly"],
           "task": "tsk_01J8QQ...",
           "rate": {"n": 200, "per": "PT1H"},
           "depth": 0, "delegable": false } }
```

Checks that pass: `exp` earlier, both amounts lower, `aud` a subset, `purpose`
equal, `depth` ≤ 2−1, and `resources`/`task`/`rate` newly introduced (parent was ⊤
on all three).

Checks that would fail: raising `max_total` to `$60`; adding `blob.datavendor.io`
to `aud`; setting `depth: 1`; setting `delegable: true` after a parent set it false;
`cur: "EUR"` against a `USD` parent.

C now spends $0.02. The Ledger debits `mnd_c` → $9.98 and `mnd_root` → $49.98,
checks both rate caveats, mints a 60-second token scoped to
`api.weatherco.com`, and records a dual-signed receipt with
`path: ["mnd_root", "mnd_c"]`.

C cannot delegate further (`delegable: false`), cannot touch `datavendor.io`
(narrowed out), cannot spend on another task (`task` pinned), and cannot outlive
the hour — while the principal's exposure remains capped at $50 regardless of how
many subagents A creates.
