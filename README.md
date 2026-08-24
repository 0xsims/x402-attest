# x402-attest

[![CI](https://github.com/0xsims/x402-attest/actions/workflows/ci.yml/badge.svg)](https://github.com/0xsims/x402-attest/actions/workflows/ci.yml)

<!--
  The badge renders broken while this repo is private. GitHub's camo proxy fetches
  README images anonymously, and the badge endpoint 404s to unauthenticated
  requests on a private repo — verified 2026-08-23. Nothing is misconfigured; it
  starts working the moment the repo goes public. Deliberately not added to
  packages/x402-attest/README.md, which ships to npm, where it would be
  permanently broken for everyone.
-->

**Tamper-evident receipts for agent-paid HTTP calls.**

An AI agent that pays for HTTP resources over [x402](https://docs.x402.org) gets,
for every paid call, a receipt that a third party can verify without trusting the
agent, the seller, or Rubric.

The buyer carries the compliance obligation, so attestation lives on the buyer's
side. This library never requires a seller's cooperation.

**The value is the receipt, not the data.**

```
packages/
  x402-attest/        the SDK
  clawrouter-attest/  ClawRouter wiring
  verify-cli/         standalone verifier
```

---

## The one-line integration

```diff
+ import { withAttestation } from '@tempus1/x402-attest';
+
+ const fetchAndPay = withAttestation(baseX402Fetch, {
+   subjectId: 'agent-alpha',
+   policy: { maxPricePerCall: '0.05', allowedNetworks: ['eip155:8453'] },
+ });

- const res = await baseX402Fetch(url, init);
+ const res = await fetchAndPay(url, init);
```

`withAttestation` returns a function with the identical signature to the one it
wraps. Nothing else in your code changes.

### Full configuration

```ts
import { createTap, withAttestation } from '@tempus1/x402-attest';

// Optional but strongly recommended: see "What the tap is for" below.
const tap = createTap();
const baseX402Fetch = x402Client(tap.wrapFetch(fetch));

const fetchAndPay = withAttestation(baseX402Fetch, {
  rubricApiKey: process.env.RUBRIC_API_KEY,   // optional; see Anchoring modes
  subjectId: 'agent-alpha',                    // who is acting
  policyId: 'trading-desk-v2',                 // optional governing policy
  sessionId: 'run-2026-08-23-01',              // optional correlation id
  mode: 'batch',                               // 'batch' | 'immediate' | 'off'
  batch: { maxLeaves: 256, maxAgeMs: 60_000 },
  redact: 'hash-only',                         // 'hash-only' | 'metadata' | (rec) => rec
  policy: {
    maxPricePerCall: '0.05',                   // USD string
    allowedNetworks: ['eip155:8453'],
    allowedPayTo: ['0x...'],
    budgetCap: '25.00',                        // per session
  },
  walPath: './.rubric-wal',
  tap,
  onReceipt: (r) => {},
});

// Also available, on the returned function and as module-level exports:
await fetchAndPay.flush();
await fetchAndPay.close();
fetchAndPay.getReceipt(callId);
fetchAndPay.exportReceipts({ format: 'csv' });
```

## Run it

```bash
npm install
npm test          # 208 tests, no live network
npm run example   # full keyless demo against in-process mocks
```

## Installing it

Not published to npm yet. **Installing straight from git does not work** — npm
would fetch the monorepo root rather than the package, and `dist/` is gitignored
with no `prepare` script, so nothing usable lands. Build tarballs instead:

```bash
npm run pack        # -> ./tarballs/*.tgz, self-contained, dist included
```

Then in the consuming project:

```bash
npm i /path/to/tempus1-x402-attest-0.1.0.tgz
```

Install **all three together** if you want the ClawRouter plugin or the verifier —
they depend on `@tempus1/x402-attest@0.1.0`, which cannot resolve from the
registry while it is unpublished:

```bash
npm i ./tarballs/tempus1-x402-attest-0.1.0.tgz \
      ./tarballs/tempus1-clawrouter-attest-0.1.0.tgz \
      ./tarballs/tempus1-x402-verify-cli-0.1.0.tgz
```

Both bins come with them: `x402-attest` and `x402-verify`.

`npm run example` pays for three calls over x402, anchors them under one Merkle
root by paying for the attestation over x402 as well, prints a receipt, verifies
it, tampers with one byte, and verifies again.

---

## What a receipt looks like

Produced by `npm run example`. This one records a **model substitution**: the agent
asked for `claude-sonnet-4.6` and the router served `gemini-2.5-flash`.

```json
{
  "callRecord": {
    "v": 1,
    "callId": "01a02fe5-bc2b-7000-bc45-8726e1d8daeb",
    "subjectId": "agent-alpha",
    "policyId": "trading-desk-v2",
    "sessionId": "run-2026-08-23-01",
    "startedAt": "2026-08-23T18:33:00.203Z",
    "endedAt": "2026-08-23T18:33:00.413Z",
    "durationMs": 210,
    "request": {
      "method": "POST",
      "host": "api.seller.example",
      "path": "/v1/chat/completions",
      "queryHash": "sha256:f81fc2a1bfbc1d6bfa2feeee30dd3eef88fa733f3033ebcd9a29c536fd77cfa0",
      "bodyHash": "2a1f1ce63ebeb0488931405d895f35a493f4e22441134f9c07eb428cb97a6035",
      "bodyBytes": 105,
      "contentType": "application/json"
    },
    "challenge": {
      "scheme": "exact",
      "network": "eip155:8453",
      "maxAmountRequired": "3000",
      "payTo": "0x1111111111111111111111111111111111111111",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "resource": "https://api.seller.example/v1/chat/completions",
      "maxTimeoutSeconds": 60,
      "rawHash": "b1a3...c92f"
    },
    "payment": {
      "scheme": "exact",
      "network": "eip155:8453",
      "amountAuthorized": "3000",
      "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
      "payTo": "0x1111111111111111111111111111111111111111",
      "xPaymentHash": "8f2c...41ab"
    },
    "settlement": {
      "success": true,
      "txHash": "0xabab...abab",
      "network": "eip155:8453",
      "source": "x-payment-response"
    },
    "response": {
      "status": 200,
      "bodyHash": "a9cfc6b653a3e82335c6177b7ba38f78314cd6ad59f80dbe2b5880fe6e95f2ae",
      "bodyBytes": 211,
      "headers": {
        "content-type": "application/json",
        "payment-response": "eyJzdWNjZXNzIjp0cnVlLCJ0cmFu...",
        "x-clawrouter-model": "google/gemini-2.5-flash",
        "x-clawrouter-tier": "SIMPLE"
      }
    },
    "outcome": "policy_violation",
    "assertions": [
      { "id": "price_matches_challenge", "result": "pass", "observed": "3000", "expected": "3000" },
      { "id": "payto_matches_challenge", "result": "pass", "observed": "0x1111...", "expected": "0x1111..." },
      { "id": "network_allowed",         "result": "pass", "observed": "eip155:8453", "expected": "eip155:8453" },
      { "id": "payto_allowed",           "result": "pass", "observed": "0x1111...", "expected": "0x1111..." },
      { "id": "price_within_policy",     "result": "pass", "observed": "0.003000", "expected": "0.05" },
      { "id": "budget_within_cap",       "result": "pass", "observed": "0.003000", "expected": "25.00" },
      { "id": "settled",                 "result": "pass", "observed": "0xabab...", "detail": "source=x-payment-response" },
      { "id": "model_matches_request",   "result": "fail",
        "observed": "sha256:5f2a...", "expected": "sha256:c81d...",
        "detail": "served-model source=x-clawrouter-model" }
    ]
  },
  "leafHash": "ce525cd776357189195d6e76683327e4f475377cbf1139d9ac61ac100cbd5cc0",
  "proof": [
    { "hash": "fb4812918d5322bd1a35e102c4b60c1faad29d5f3bd0792c80e5a92c47e2aa98", "side": "right" },
    { "hash": "a5377685823720f5a520b255cd0a2ce53c36dcd102de3ecaefd653bc3f54f5ab", "side": "right" }
  ],
  "root": "b8a44427b72fce0105bcd2e11c0e8bcad1e3c902df5faedba10816e5355519fb",
  "attestationId": "1645f6ca-da6d-4001-819f-698965e70fb6",
  "verifyUrl": "https://rubric-protocol.com/audit/1645f6ca-da6d-4001-819f-698965e70fb6",
  "verifyApiUrl": "https://rubric-protocol.com/v1/verify/1645f6ca-da6d-4001-819f-698965e70fb6",
  "envelope": {
    "schemaVersion": "rubric.x402-attest/v1",
    "leafType": "DATA_RECORD",
    "root": "b8a44427b72fce0105bcd2e11c0e8bcad1e3c902df5faedba10816e5355519fb",
    "leafCount": 3,
    "firstCallId": "01a02fe5-bc2b-7000-bc45-8726e1d8daeb",
    "lastCallId": "01a02fe5-bc2d-7000-9f11-3c0a4d7e2b90",
    "timeRange": { "from": "2026-08-23T18:33:00.203Z", "to": "2026-08-23T18:33:00.913Z" },
    "subjectId": "agent-alpha",
    "policyId": "trading-desk-v2",
    "merkle": { "hash": "sha256", "leafPrefix": "0x00", "nodePrefix": "0x01", "oddNode": "promote" }
  },
  "payloadCommitment": "1654a32e8ca47dd30c4b23daf60ecf46b6caeed76c00b126be904ac04ddcc188",
  "commitmentSalt": "9d4f1c77b8e0a2536ac41e9f0b73d81552aa6e04c9f3b7182de60c4a5f9b2e33"
}
```

`envelope` is the exact payload submitted to Rubric, carried because Rubric does
not give it back. `commitmentSalt` opens the commitment the node holds. Note what
is *not* here: the `payloadKey` the salt was derived from. That stays in
`{walPath}/payload-keys.jsonl` at mode 0600 — the salt discloses the opening, not
the key.

Note what is *not* in there: no prompt, no completion, no query string, no payment
authorization header, no `set-cookie` the seller sent. Only digests and the checks.

---

## What this does and does not prove

Overclaiming here is the failure mode that discredits the whole idea, so read this
section before you cite a receipt to anyone.

### It proves

- **The record has not been altered since it was written.** Any change to any byte
  of `callRecord` — a price, a payee, an assertion result, a timestamp — breaks
  `leafHash`. The verifier catches it with no network access at all.
- **The record was committed before a known point in time.** The batch root is
  anchored to Hedera Consensus Service. The record existed no later than that
  consensus timestamp; it cannot be back-dated afterwards.
- **The record was in the batch it claims.** The inclusion proof binds this exact
  leaf to that exact root. It cannot be moved between batches.
- **Which checks the buyer performed, and what they returned** — including the ones
  that could not be completed. That is the audit artifact.
- **All of the above without trusting anyone.** Verification needs no API key, no
  Rubric account, no cooperation from the seller, and no trust in the agent that
  produced the receipt.

### It does not prove

- **That the seller was honest.** This library records what the buyer observed. If a
  seller lies in its own `PAYMENT-RESPONSE` header, the receipt faithfully records
  the lie. `settled: pass` means a settlement receipt was observed, not that the
  chain settled — go read the `txHash` on-chain for that.
- **That the recorded content is what was actually sent.** `bodyHash` binds a
  receipt to bytes. It proves nothing on its own; it lets someone *holding* those
  bytes prove they match. Discard the bytes and you have an unforgeable record of a
  hash of something you can no longer produce.
- **That the agent recorded every call it made.** A buyer who wants to hide a call
  can not call the wrapper. This library makes the calls it sees undeniable; it
  cannot make omissions detectable. Batch `leafCount` and `firstCallId`/`lastCallId`
  make *gaps within an anchored batch* visible, and nothing more.
- **Anything, if the receipt was produced without an opening salt.** With the salt
  the whole chain is cryptographically checked. Without one — an older node, or
  the direct `/v1/attest` path — the last link falls back to matching a recorded
  value, which a forger who controlled both the root and the commitment could
  satisfy. `verifyReceipt` always reports which binding it achieved.
- **That the model served was any good, or correctly priced.**
  `model_matches_request` compares a requested string to a served string. It does
  not evaluate the output or the fairness of the price.
- **That the timestamps are true.** `startedAt` comes from the local clock and is
  descriptive. The anchor is the only trustworthy time bound, and it is an upper
  bound.
- **Anything at all when the assertion says `unknown`.** `unknown` is not a soft
  pass. It means the check was attempted and the inputs were not observable —
  usually because no tap was installed, or the policy field was not configured.

---

## Assertions

Eight checks on every call, always all eight, always in this order. `unknown` is a
legitimate result and is recorded rather than omitted.

| id | passes when | `unknown` when |
|---|---|---|
| `price_matches_challenge` | amount authorized equals the advertised amount (`maxAmountRequired` on v1, `amount` on v2) | no challenge or no payment observed |
| `payto_matches_challenge` | payment went to the address the challenge named | either side unobservable |
| `network_allowed` | network is in `policy.allowedNetworks` | policy field unset |
| `payto_allowed` | payee is in `policy.allowedPayTo` | policy field unset |
| `price_within_policy` | call cost ≤ `policy.maxPricePerCall` | policy unset, or amount unpriceable |
| `budget_within_cap` | cumulative session spend ≤ `policy.budgetCap` | policy unset, or this call unpriceable |
| `settled` | a settlement receipt with a transaction hash was observed | no settlement receipt served |
| `model_matches_request` | model requested equals model served | neither discoverable |

Any `fail` sets `outcome: 'policy_violation'`. It never throws and never blocks the
response. The library records; the caller decides.

### Reading the challenge when a seller sends it twice

A seller may serve the requirements in a header, in the 402 body, or — commonly —
in both at once. BlockRun answers a 402 with `PAYMENT-REQUIRED`,
`X-PAYMENT-REQUIRED` **and** `WWW-Authenticate: X402 requirements="<b64>"`, plus a
human-readable JSON error body.

The header always wins. The two say different things: the header carries the
machine-readable requirements (`"amount": "2000"`, atomic units), the body carries
prose for a person (`"price": { "amount": "0.002000", "currency": "USD" }`) and has
no `accepts`, no `payTo`, no `scheme` and no `network`. Reading the body when a
header is present recorded a USD price against an atomic authorization and failed
`price_matches_challenge` on a correct payment — see DEVIATIONS §16.

`WWW-Authenticate` is only read when it carries the `X402` auth-scheme token, so a
`Bearer realm=...` from an unrelated auth layer is never mistaken for payment terms.

### `model_matches_request` is the proof-of-routing check

Routers substitute cheaper models. That is often fine and often the point — it is
what a cost-saving router is *for*. What a buyer cannot otherwise do is prove after
the fact which model actually served a given paid call.

Compared, in order of trustworthiness: the `x-clawrouter-*` routing header, then
the response body's `model`, against the request body's `model`. An alias resolving
to a pinned build (`gpt-4o` → `gpt-4o-2026-05-13`) is a pass. A different family is
a fail. When neither side is discoverable the result is `unknown` — guessing `pass`
here would turn the receipt into an alibi for the exact behaviour it exists to
detect.

### What the tap is for

`withAttestation` wraps an x402 client that handles 402 → pay → retry internally.
From outside that client, only the final 200 is visible — so the challenge the
seller served and the authorization the client signed are invisible, and four of
the eight assertions degrade to `unknown`.

Installing `createTap()` *underneath* the x402 client is what makes them real
checks:

```ts
const tap = createTap();
const baseX402Fetch = x402Client(tap.wrapFetch(fetch));  // tap goes here
const fetchAndPay = withAttestation(baseX402Fetch, { subjectId, tap });
```

It is optional. Without it you still get valid, verifiable receipts — they just
assert less, and they say so.

**Verified against the real client.** `x402-fetch@1.2.0` takes `fetch` as its
first argument and calls it, so the tap installs cleanly underneath. The test
suite runs the full handshake through it with a real viem wallet signing a real
EIP-3009 authorization, and asserts both halves of the claim: with the tap the
four payment-side checks return real verdicts, and without it — same client, same
seller — they degrade to `unknown` with `challenge` and `payment` absent. No
optimistic passes either way.

The two generations put everything in different places, and both are deployed:

| | `x402-fetch@1.2.0` (v1) | `@x402/core` + `@x402/evm` (v2) |
|---|---|---|
| payment header | `X-PAYMENT` | `PAYMENT-SIGNATURE` |
| requirements | 402 body, `accepts[]` | `PAYMENT-REQUIRED` / `X-PAYMENT-REQUIRED` / `WWW-Authenticate` header |
| amount field | `maxAmountRequired` | `amount` |
| network | `base` | CAIP-2 `eip155:8453` |
| scheme / network in the payment payload | top level | under `accepted` |
| `resource` | on each `accepts[]` entry | on the envelope, as `{ url, description, mimeType }` |

docs.x402.org describes only the v2 header names and pins no schema for either —
the OpenAPI document it references is an unmodified template. Both shapes here
were read off the encoders on disk and off a live mainnet 402, not off the docs;
DEVIATIONS §17 records the v2 payload verbatim.

Reading both generations, both amount spellings, both homes for scheme and
network, and normalizing network aliases is what makes this work rather than
silently observing nothing.

---

## Verification

```bash
npx @tempus1/x402-attest verify ./receipt.json   # exit 0 = valid, nonzero = tampered
```

| exit | meaning |
|---|---|
| 0 | valid |
| 1 | hash mismatch — the record does not hash to its claimed leaf |
| 2 | proof mismatch — the proof does not reach the anchored root |
| 3 | not anchored — locally valid, but the node reports a state we cannot place |
| 4 | fetch failed — the public verify endpoint could not be reached |
| 5 | pending anchor — signed and held by the node, HCS flush still in flight |

Note that 3, 4 and 5 are deliberately not "invalid". A batch that has not flushed
yet, and a verifier you cannot reach, are both different from a forged receipt.

**Exit 5 is the common one, and it is not a problem.** HCS anchoring happens at the
next tier-2 flush, typically 60–120s after submission, so a receipt verified
immediately after it is written reports `status: "signed-pending-hcs"` — signed,
held, ledger anchor in flight. Everything checkable has been checked: the record
hashes to its leaf, the proof reaches the submitted root, and the commitment
matches. Verify again after a couple of minutes and it becomes 0. The CLI prints
`PENDING`, not `INVALID`, because in a tamper-evidence tool the second word means
something very specific and this is not it.

Across several receipts the worst result wins, and pending is the least severe
nonzero code: a real problem in any receipt still outranks it. In CI, treat 5 as
"retry shortly" rather than as a gate failure.

Flags: `--offline` (hash and proof only, no network), `--json`, `--quiet`,
`--verify-url <url>`, `--timeout <ms>`. Input may be one receipt, a JSON array, or
JSONL; with several, the exit code is the worst result.

Four checks, and the first three are pure local computation:

1. `sha256(jcs(callRecord))` must equal `leafHash`.
2. Walking `proof` from that leaf must reproduce `root`.
3. That root must be the one named in `envelope` — the exact payload submitted to
   Rubric, which the receipt carries.
4. `GET /v1/verify/{attestationId}` — public, no key — must report `anchored` and
   hold the same `payload_commitment` the receipt recorded.

**Two URLs, and which one to use.** A receipt carries both. `verifyUrl` is the link
to hand a person: Rubric returns `/audit/{id}`, a rendered HTML page.
`verifyApiUrl` is `/v1/verify/{id}`, the JSON API, and it is what `verifyReceipt`
calls. The API path is always built locally rather than taken from the server
response, keeping only the origin the server named — tiered attestations resolve
from the store of the node that issued them, so that origin matters. Receipts
written before 0.1.1 have no `verifyApiUrl`; the API path is derived from
`verifyUrl`'s origin for those. If the endpoint returns something that is not JSON
the verifier says so in those terms rather than surfacing a parser error.

**On step 4, and why it is not a root comparison.** Verified against the live
mainnet node: Rubric never echoes the submitted payload back. Tiered payloads are
encrypted at rest and the endpoint returns only a commitment to them, so there is
no root in the response to compare against. The receipt therefore carries the
envelope plus the commitment's **opening salt**, and the chain runs

```
callRecord → leafHash → proof → root → envelope.root → commitment → anchored
```

Rubric's commitment scheme is

```
salt       = SHA-256(payloadKey + ':rubric-commit-v1')
commitment = SHA-256(salt + RFC8785(payload))
```

The salt is a one-way function of the payload key, which is what makes the last
link verifiable without disclosing anything. A receipt publishes the **salt**, so
anyone can recompute the commitment from the envelope and compare it to what the
node holds — while the AES key that decrypts the payload stored at Rubric never
leaves your machine. `verifyReceipt` reports `binding: 'recomputed'`, and every
link in the chain is checked rather than taken on trust.

Two weaker states exist and are reported honestly rather than smoothed over.
`binding: 'recorded'` means no salt was available, so the commitment was matched
by the value the receipt recorded — that catches a receipt pointed at the wrong
attestation, but not one whose root and commitment were fabricated together.
`'none'`, with `commitment: 'unverifiable'`, means nothing could bind the payload
at all. Neither is ever silently reported as a clean pass.

An altered envelope is caught locally, before any network call, because the
commitment no longer opens.

---

## Anchoring and the economics

An attestation costs about **$0.005**. The median x402 payment is a fraction of a
cent. Anchoring per call would cost an order of magnitude more than the thing it
attests, so per-call anchoring is economically dead.

Batching 256 calls under one Merkle root:

| | per call |
|---|---|
| per-call anchoring | $0.005 |
| batched at 256 | **$0.00002** |

Each leaf still gets an independent inclusion proof, so nothing is lost by
batching. Flush triggers: `batch.maxLeaves` reached, `batch.maxAgeMs` elapsed, an
explicit `flush()`, or SIGINT/SIGTERM with a 5s drain.

### The Merkle tree, and why the odd-node rule matters

Leaves are `sha256(0x00 || leafHash)`, internal nodes `sha256(0x01 || left ||
right)`. The domain-separating prefixes make the two hash spaces disjoint, which is
what stops a 64-byte leaf from being presented as an internal node.

**An unpaired node is promoted unchanged. It is never duplicated.** Duplicating it —
the Bitcoin rule — makes a tree over `[A, B, C]` and a tree over `[A, B, C, C]`
produce the same root (CVE-2012-2459). For an audit artifact that is fatal: it lets
someone claim a leaf was in a batch that never contained it. Promotion keeps the
leaf count bound to exactly one root, and `leafCount` travels in the batch envelope
so a verifier can check proof length against it.

### Anchoring modes

| | behaviour |
|---|---|
| `rubricApiKey` set | anchor via `POST /v1/tiered-attest` (works on every tier, including free Developer) |
| no API key | anchor via `POST /v1/x402/tiered-attest` — **the attestation is paid for over x402, the same way it attests** |
| `mode: 'off'` | WAL only, no network |

The keyless path is the demo, and it works:

```ts
const fetchAndPay = withAttestation(baseX402Fetch, {
  subjectId: 'agent-alpha',
  anchorFetch: x402Client(fetch),   // the RAW client, NOT the attested wrapper
});
```

`anchorFetch` must be the unwrapped client. Wrapping it would attest the
attestation, which would need its own attestation.

Failed anchors retry with jittered exponential backoff (1s → 60s, indefinitely).
**A leaf is never dropped** — not on a 500, not on a 400, not on a bad API key. The
leaves are on disk; the next flush or the next process picks them up.

---

## Privacy

`hash-only` is the default: **no body content leaves the process, ever.**

| mode | behaviour |
|---|---|
| `hash-only` | digests only. Model names appear in assertions as `sha256:...` |
| `metadata` | adds allowlisted non-sensitive fields: model name, token counts, status |
| `(rec) => rec` | your function, run after `bodyHash` is computed over the original bytes |

Hashed, never stored: request and response bodies, query strings, the payment
authorization header. Response headers are **allowlisted** — `x-payment-response`,
`payment-response`, `x-clawrouter-*`, `x-request-id`, `content-type`,
`server-timing`. Everything else is dropped, including `set-cookie` and
`authorization`.

The mandatory no-plaintext test plants sentinels in the request body, the response
body and the model name, runs the full flow, and asserts they appear in no outbound
payload, no receipt, and no WAL line. What actually reaches Rubric is exactly nine
fields — a root, a leaf count, two call ids, a time range, a subject id, a schema
version, a leaf type, and the Merkle parameters — plus `policyId` when you set one.
That list is asserted explicitly, so a future change that starts shipping call
detail upstream fails loudly.

Ordering matters and is fixed: `bodyHash` is computed over the **original** bytes,
then redaction runs, then the leaf hash is taken over the **redacted** record. A
redacted receipt still binds to exactly the bytes that crossed the wire.

---

## Durability

Every leaf is written to an append-only WAL at `{walPath}/leaves.jsonl` and
`fdatasync`ed **before the wrapper returns**. A crash cannot lose evidence for a
call whose response the caller already acted on.

Append-only is deliberate: anchoring results go to `anchors.jsonl` as separate
lines rather than rewriting leaves in place, so a crash can only ever truncate the
tail. On restart the WAL is replayed, every leaf is re-checked against its own
recorded hash, a truncated final line is tolerated, unanchored leaves are re-queued,
and session spend is rebuilt.

The test suite SIGKILLs a child process mid-batch — no handlers, no flush — and
asserts zero leaves lost and all of them anchorable after restart.

```ts
wal: { fsync: 'always' }   // default: survives power loss. ~1-2ms per call.
wal: { fsync: 'interval' } // write(2) per leaf, fdatasync on a 250ms timer.
                           // Survives process crash / SIGKILL, not power loss.
wal: { fsync: 'off' }      // fdatasync on flush and close only.
```

Under `interval` the deferred sync runs on a timer, off the request path. The
obvious implementation — sync inline on whichever call crosses the interval
boundary — was measured and is *worse at p99* than syncing every call: the median
improves but the periodic spike lands squarely in the tail.

## Latency

The wrapper never blocks on anchoring. Measured against an in-process upstream
(virtualized ext4, Node 20.20):

| | p50 | p99 |
|---|---|---|
| compute only (`wal.fsync: 'off'`) | ~0.8–1.3ms | ~1.5–3.9ms |
| `wal.fsync: 'interval'` | ~0.4–1.0ms | ~1.0–4.3ms |
| default (`fdatasync` per leaf) | ~1.7–2.6ms | ~3.4–7.6ms |

Added latency is measured as the shift between two distributions at the same
quantile, `p99(attested) - p99(baseline)`, over 400 samples with warmup.

The `<5ms p99` target is met for compute and for the `interval` policy. With
`fdatasync` per leaf it is hardware-dependent and sits right at the line: a single
durable write costs ~1.9ms at p99 on this disk, which is most of the budget before
this library does anything at all. See
[DEVIATIONS.md](DEVIATIONS.md#11-latency-the-5ms-p99-target-is-met-for-compute-not-for-fdatasync-per-leaf).

Anchoring being completely unreachable does not slow calls down at all: the test
suite runs 20 calls against a Rubric fetch that never resolves, and they complete in
under a second with every leaf durable and queued.

---

## Export

```ts
fetchAndPay.exportReceipts({ format: 'csv', from: '2026-08-01', to: '2026-08-31' });
```

One row per call, one column per assertion result, plus call id, timestamps, host,
path, status, outcome, network, payee, amounts, transaction hash, attestation id and
verify URL. Cells are RFC 4180 quoted, and cells starting with `=`, `+`, `-` or `@`
are prefixed with a quote — `payTo` is attacker-influenced content heading into a
finance spreadsheet.

`format: 'jsonl'` emits the full receipt, one JSON object per line.

---

## ClawRouter

See [packages/clawrouter-attest](packages/clawrouter-attest/README.md).

ClawRouter's pitch is that it saves you money by routing to a cheaper model that is
good enough. That is a claim about substitution, and the honest way to back a
substitution claim is to make the substitutions checkable. This is complementary,
not adversarial.

---

## Non-goals

No ZK proofs. No on-chain contract. No dashboard. No key custody beyond what your
x402 client already needs. No attempt to prove the seller was honest.

This library proves what was observed and what was checked. Nothing more.

---

## Tests

```bash
npm test        # 242 tests
npm run coverage
```

Coverage on `packages/x402-attest`: **95% statements, 89% branches, 97% functions.**

The suite depends on `x402-fetch` and `viem` as devDependencies for the real-client
integration test. The shipped package still has **zero runtime dependencies**.

Ships a mock x402 seller, a mock facilitator/payment client, and a mock Rubric node.
No live network in CI.

`test/fixtures/live-mainnet/` holds captured wire data from the first live mainnet
run — the 402 challenge headers, the 402 body, the settlement header, the
`/v1/verify` response, the audit page, and the receipt itself. The challenge and
request-body captures are pinned by hash against what that receipt recorded, so
they are provably the same bytes and not a paraphrase. The payment headers are the
one thing that could not be captured — the plaintext is hashed and discarded by
design — so they are produced by the shipping `@x402/core` + `@x402/evm` encoder
signing the real challenge with an unfunded throwaway key, and a test re-runs that
encoder to keep the frozen fixture from drifting.

Covered: JCS determinism (shuffled keys, non-ASCII, astral-plane keys, the RFC 8785
worked example); Merkle round-trips at every index for batch sizes 1, 2, 3, 7, 8 and
256; odd-node promotion and the `[A,B,C]` vs `[A,B,C,C]` collision; SIGKILL crash
recovery; every assertion's fail path; the no-plaintext test; latency; Rubric
unreachable with backoff and recovery; and a tampered receipt exiting nonzero from
the real CLI binary in a real subprocess.

## Documents

- [ASSUMPTIONS.md](ASSUMPTIONS.md) — what was left open and what was decided
- [DEVIATIONS.md](DEVIATIONS.md) — where the live docs contradicted the spec

## License

MIT
