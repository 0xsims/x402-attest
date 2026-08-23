# x402-attest

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
+ import { withAttestation } from '@rubric/x402-attest';
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
import { createTap, withAttestation } from '@rubric/x402-attest';

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
npm test          # 198 tests, no network
npm run example   # full keyless demo against in-process mocks
```

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
  "verifyUrl": "https://rubric-protocol.com/v1/verify/1645f6ca-da6d-4001-819f-698965e70fb6"
}
```

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
| `price_matches_challenge` | amount authorized equals the advertised `maxAmountRequired` | no challenge or no payment observed |
| `payto_matches_challenge` | payment went to the address the challenge named | either side unobservable |
| `network_allowed` | network is in `policy.allowedNetworks` | policy field unset |
| `payto_allowed` | payee is in `policy.allowedPayTo` | policy field unset |
| `price_within_policy` | call cost ≤ `policy.maxPricePerCall` | policy unset, or amount unpriceable |
| `budget_within_cap` | cumulative session spend ≤ `policy.budgetCap` | policy unset, or this call unpriceable |
| `settled` | a settlement receipt with a transaction hash was observed | no settlement receipt served |
| `model_matches_request` | model requested equals model served | neither discoverable |

Any `fail` sets `outcome: 'policy_violation'`. It never throws and never blocks the
response. The library records; the caller decides.

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

---

## Verification

```bash
npx @rubric/x402-attest verify ./receipt.json   # exit 0 = valid, nonzero = tampered
```

| exit | meaning |
|---|---|
| 0 | valid |
| 1 | hash mismatch — the record does not hash to its claimed leaf |
| 2 | proof mismatch — the proof does not reach the anchored root |
| 3 | not anchored — locally valid, but not on the ledger yet |
| 4 | fetch failed — the public verify endpoint could not be reached |

Note that 3 and 4 are deliberately not "invalid". A batch that has not flushed yet,
and a verifier you cannot reach, are both different from a forged receipt.

Flags: `--offline` (hash and proof only, no network), `--json`, `--quiet`,
`--verify-url <url>`, `--timeout <ms>`. Input may be one receipt, a JSON array, or
JSONL; with several, the exit code is the worst result.

Three steps, and the first two are pure local computation:

1. `sha256(jcs(callRecord))` must equal `leafHash`.
2. Walking `proof` from that leaf must reproduce `root`.
3. `GET /v1/verify/{attestationId}` — public, no key — must report `anchored` and
   carry the same root.

Programmatically:

```ts
import { verifyReceipt } from '@rubric/x402-attest/verify';
const result = await verifyReceipt(receipt);        // { ok, code, reason, checks }
const local  = await verifyReceipt(receipt, { offline: true });
```

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
npm test        # 198 tests
npm run coverage
```

Coverage on `packages/x402-attest`: **95% statements, 88% branches, 97% functions.**

Ships a mock x402 seller, a mock facilitator/payment client, and a mock Rubric node.
No live network in CI.

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
