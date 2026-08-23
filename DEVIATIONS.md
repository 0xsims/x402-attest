# Deviations from the build spec

Every place the implementation departs from the build spec it was written against,
with the reason. Docs were checked against `https://rubric-protocol.com/docs` and
`https://docs.x402.org` on **2026-08-23**.

---

## 1. The keyed path anchors via `/v1/tiered-attest`, not `/v1/attest`

**Spec:** "API key present → sign locally, anchor via the Rubric SDK." and
"Use `leafType: 'DATA_RECORD'` and `sourceId: subjectId`."

**Live docs:** there are two submission endpoints and they take different bodies.

| | `/v1/attest` | `/v1/tiered-attest` |
|---|---|---|
| Tier | Enterprise only | all tiers, including free Developer |
| Required fields | `agentId`, `sourceId`, `leafType`, `data` | `sourceId`, `data` |
| Accepts `leafType`? | yes | **no** |
| Cost | direct HCS write, bills HBAR per call | buffered, flushed in tiers |

**What we do:** default `anchorEndpoint: 'tiered'`. The `leafType: 'DATA_RECORD'`
value the spec asks for still travels with the attestation — it is carried inside
`data`, where it remains part of the attested payload and is visible to any
verifier. `/v1/attest` is reachable via `anchorEndpoint: 'direct'`, which also
emits a `RubricCostWarning` and sends `leafType` at the top level as that endpoint
requires.

**Why:** `/v1/attest` writes straight to HCS and bills HBAR on every call, and is
Enterprise-tier only. Making it the default would mean a free-tier user's first
call fails with a 403, and an Enterprise user's bill scales with flush count.
Batching already makes anchoring cheap; picking the endpoint that works on every
tier makes it *available*.

## 2. No dependency on the Rubric SDK

**Spec:** "anchor via the Rubric SDK".

**What we do:** plain `fetch` against the documented HTTP endpoints. The package
has zero runtime dependencies.

**Why:** the SDK carries a signing stack this library does not need — we anchor a
root, we never custody a key. A package whose entire product is auditability is
much easier to trust when its dependency tree is empty and its whole network
surface is two POST shapes and one GET.

## 3. `/v1/tiered-attest` returns a `payloadKey`, which the spec does not mention

**Live docs:** the response includes `payloadKey`, "64-char hex AES-256-GCM key
(returned once)".

**What we do:** the key is written to `{walPath}/payload-keys.jsonl` with mode
`0600` and is never placed in a receipt, a leaf, or an export.

**Why:** it is a decryption credential, not evidence. Discarding it would lose the
ability to recover the submitted payload from Rubric's warm store later; putting it
in receipts would ship a credential to whoever receives the audit file. A separate
restricted file is the only option that does neither.

## 4. `/v1/verify` does not return the submitted payload — verification is commitment-based

**Spec:** "fetches `GET /v1/verify/{attestationId}` ... and confirms the anchored
root matches and status is `anchored`."

**Verified against the live mainnet node on 2026-08-23** (public GET, no key,
attestation `e65dc29e-b029-4f27-9c97-d2e2631107d0`):

```json
"attestation": {
  "payload":      { "payload_commitment": "1654a32e…" },
  "payload_hash": "89bc5ff5…",
  "batch_root":   "069d3474…",
  "merkle_proof": ["e810aa20…"], "merkle_proof_directions": ["R"]
},
"status": "anchored", "verified": true, "payloadHashMatch": true,
"sequenceNumber": 291514, "aggregateBinding": "strong"
```

The submitted payload is **never echoed back**. Tiered payloads are encrypted at
rest and the endpoint exposes only a commitment to them; `batch_root` is Rubric's
own tier-1 flush root, unrelated to ours. Confirming "the anchored root matches",
as the spec describes, is not possible against this API.

**What we do:** the receipt now carries the `envelope` — the exact payload
submitted — plus the `payloadCommitment` Rubric issued for it. Verification runs:

```
callRecord → leafHash → proof → root → envelope.root → commitment → anchored
```

Steps 1, 2 and the envelope-root check are pure local computation. The last link
compares the receipt's recorded commitment against the one the node holds.

**The commitment scheme, read from the server source rather than guessed:**

```
salt       = SHA-256(payloadKeyHex + ':rubric-commit-v1')
commitment = SHA-256(salt + RFC8785(payload))
```

The salt is one-way in the payload key. The implementation comment states the
intent directly: *"opening discloses {plaintext, salt} only — decryption key stays
sealed."* So the receipt carries the salt, not the key, and any third party can
recompute the commitment from the envelope and compare it against the public
verify endpoint. `binding: 'recomputed'`; the chain is trustless end to end and no
secret is published.

Where a salt is unavailable — an older node, or the direct `/v1/attest` path —
the verifier falls back to `binding: 'recorded'` and says so; with nothing at all
to bind with it reports `commitment: 'unverifiable'`. Neither is presented as a
clean pass. An altered envelope fails locally, before any network call, because
the commitment stops opening.

Their canonicalizer is RFC 8785, the same as ours, so the recomputation is exact.

**How this was missed until now.** The mock returned `data: <submitted payload>`
in its verify response — it encoded the assumption and was then used to validate
it, so a verifier that could never work against the real API passed every test.
The mock now mirrors the observed live shape and implements the confirmed
commitment scheme — confirmed by reading the server, not inferred from a passing
test.

**Also confirmed, and reassuring:** the on-ledger tier-2 anchor (HCS topic
`0.0.10416909`, seq 291514, read from the Hedera mirror node) declares
`canonicalization: JCS/RFC8785` and a batch level of
`SHA-256 / RFC6962 domainSeparation / merkleOdd: "promote"` — independently the
same construction this library implements.

**One operational consequence:** per the 404 note, tiered attestations "resolve
from the serving node's store" and cannot be found by a mirror-node scan. Verifying
against a different federation node than the issuing one returns `found: false`.
The keyless path already prefers the server-supplied `verifyUrl`; the keyed path
builds it from `rubricBaseUrl` and will point at the wrong node in a multi-region
deployment. Not yet fixed.

## 5. x402 header names: two generations, both supported

**Spec:** `X-PAYMENT`, `x-payment-response`, and a `maxAmountRequired` field.

**Live docs (docs.x402.org, 2026-08-23):** the headers are named
`PAYMENT-REQUIRED`, `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE`, each carrying
base64-encoded JSON. The referenced schema document at
`docs.x402.org/api-reference/openapi.json` is an unmodified template — it defines
`Plant`, `NewPlant` and `Error` — so the live docs do **not** pin the wire schema
at all.

**What we do:** read both header generations, and read the amount from
`maxAmountRequired`, `amount`, `price`, or `price.amount`, whichever is present.
The header allowlist covers both `x-payment-response` and `payment-response`.
Network ids are normalized through a CAIP-2 alias table before policy comparison,
so a challenge saying `base` satisfies a policy written as `eip155:8453`.

**Why:** guessing one generation does not corrupt evidence, but it does silently
degrade half the assertions to `unknown`, which is the difference between a useful
receipt and a decorative one.

**Settled by testing the real client (2026-08-23).** `x402-fetch@1.2.0` — the
shipping reference client — uses the spec's format, not the docs':

| | docs.x402.org | x402-fetch@1.2.0 |
|---|---|---|
| payment header | `PAYMENT-SIGNATURE` | `X-PAYMENT` |
| requirements location | `PAYMENT-REQUIRED` header | 402 response body, `accepts[]` |
| amount field | unspecified | `maxAmountRequired`, required by its zod schema |
| network id | CAIP-2 | `base` (from `ChainIdToNetwork[8453]`) |

So the build spec described the deployed reality and the live documentation
describes something else — possibly a future generation, possibly aspirational.
Supporting both was the right call, and the alias table is what lets a policy
written in CAIP-2 match a challenge that says `base`.

The tap installs underneath it cleanly: `wrapFetchWithPayment(fetch, wallet)`
takes the transport as its first argument and calls it. Covered by
`test/real-client.test.ts`, which also asserts the without-tap degradation.

## 6. `challenge.resource` has its query string stripped

**Spec:** "the 402 as served. NOT sensitive — keep in clear."

**What we do:** everything in the challenge is kept verbatim except the query
string of `resource`.

**Why:** `resource` is the seller echoing back the buyer's own request URL. Keeping
it verbatim reinstates, in clear, the exact query string that `request.queryHash`
exists to keep out of the record. Query strings carry API keys and signed-URL
tokens, and the log is append-only, so the leak would be permanent. This was caught
by a test, not by inspection.

## 7. `settlement` is always present

**Spec:** `settlement?` is optional.

**What we do:** when no settlement is observed we record
`{ success: false, source: 'none' }` rather than omitting the field.

**Why:** "we looked and saw nothing" and "we did not look" are different claims. The
same reasoning the spec applies to `unknown` assertions applies here.

## 8. `Assertion` carries an extra `detail` field

**Spec:** `{ id, result, observed?, expected? }`.

**What we do:** an optional `detail` string, e.g. `policy.allowedPayTo not set`,
`served-model source=x-clawrouter-model`.

**Why:** an `unknown` with no explanation is nearly as unhelpful as an omission. The
field never contains body content. It is inside the hash like everything else.

## 9. `onReceipt` fires twice per call

**Spec:** implies one callback.

**What we do:** once when the leaf is durable (`attestationId: null`), and again
when the batch anchors. `isAnchored(receipt)` distinguishes them.

**Why:** the spec requires that a policy violation surface through `onReceipt`, and
requires batching with a 60-second window. A single callback can satisfy one or the
other. Firing immediately is what makes the violation actionable; firing again is
what delivers the attestation id.

## 10. Under `hash-only`, model names in assertions are digests

**Spec:** does not say how `observed`/`expected` interact with redaction.

**What we do:** `model_matches_request` records `sha256:<hex>` of each model name
under `hash-only`, and the names in clear under `metadata`.

**Why:** the model name is response-body content, and the mandatory no-plaintext
test would otherwise fail on the library's own default. The audit conclusion —
pass, fail, or unknown — is preserved either way, and an auditor holding the model
name can still confirm the digest.

Note that a model name arriving in an allowlisted `x-clawrouter-*` **header** is
kept in clear, because the spec's header allowlist mandates capturing that prefix
and routing headers are the evidence behind the substitution check. Header content
and body content are treated differently, deliberately.

## 11. Latency: the 5ms p99 target is met for compute, not for fdatasync-per-leaf

**Spec:** "Target: <5ms p99 added latency" and "fsync on write ... BEFORE returning
from the wrapper."

**Measured on the development machine (virtualized ext4, Node 20.20):**

Added latency measured as `p99(attested) - p99(baseline)` over 400 samples with
warmup, test files run serially so the measurement is not competing with the rest
of the suite:

| | p50 | p99 |
|---|---|---|
| compute only (`wal.fsync: 'off'`) | ~0.8–1.3ms | ~1.5–3.9ms |
| `wal.fsync: 'interval'` | ~0.4–1.0ms | ~1.0–4.3ms |
| default, fdatasync per leaf | ~1.7–2.6ms | **~3.4–7.6ms** |
| one bare `fdatasync` on this disk | ~1.0ms | ~1.9ms |

The two requirements are in tension on commodity cloud storage: a single durable
write costs about half the entire budget before this library does any work at all.

**What we do:** keep fdatasync-per-leaf as the default, and add
`wal: { fsync: 'always' | 'interval' | 'off' }` so the trade is explicit. Under
`interval`, every leaf is still `write(2)`-ed before the wrapper returns, so it
survives a process crash, an uncaught exception, or SIGKILL — the failure agents
actually hit. Only power loss within the interval can lose it, and the
crash-recovery test covers the `interval` policy too.

The test suite asserts <5ms p99 strictly for compute and for `interval`, and
reports the default configuration's number rather than asserting a figure this
hardware cannot hold reliably.

One finding worth recording, because it inverts the obvious intuition: syncing on a
250ms *interval* was initially implemented inline — "if the interval has elapsed,
fdatasync this call" — and measured **worse at p99** than syncing every single
call. Deferring the cost does not remove it; it concentrates it on whichever
unlucky request crosses the boundary, and that request is the tail. The interval
sync now runs on a timer, off the request path, which is what actually made p99
drop.

## 12. Response bodies are buffered by default

**Spec:** silent on this.

**What we do:** read the response body, hash it, and hand the caller a
reconstructed `Response`. Bodies served as `text/event-stream` are streamed through
a hashing transform instead, and `capture.stream` overrides the choice.

**Why:** "write the leaf before returning from the wrapper" is only achievable if
the response hash is known before returning. Buffering an SSE stream would defeat
the point of streaming, so those are teed instead and their leaf lands when the
stream ends. `close()` finalizes any stream still open, attesting it as incomplete.

Two costs of reconstruction, stated plainly: the returned `Response` loses `url` and
`redirected`, and a very large body is materialized in memory. Cloning instead was
measured and is worse — undici's tee roughly quadruples the p99.

## 13. ClawRouter integration is a wrapper and a reverse proxy

**Spec:** "Wire the SDK in so every proxied call is attested. Add response headers
`x-rubric-attestation-id` and `x-rubric-receipt-url` once anchored."

**Live docs:** ClawRouter exposes `startProxy({ ..., onRouted, onPayment })` and
emits `x-clawrouter-profile|tier|model|confidence|reasoning`. There is no hook that
lets a third party add response headers to its proxy.

**What we do:** two integrations — `withClawRouterAttestation` (wrap the fetch your
agent already points at :8402; one line, no extra hop) and `createAttestingProxy`
(an attesting reverse proxy in front of ClawRouter that can add the headers).

**Added:** `x-rubric-call-id` on every proxied response. Since batches anchor on a
60s/256-leaf schedule and we never block waiting, the two spec'd headers are
usually absent at response time. The call id is the durable handle that makes them
retrievable later, so without it the feature would be almost always unavailable.

## 14. Verify CLI ships from both packages

**Spec:** shows `npx @rubric-protocol/x402-attest verify ./receipt.json`, and also lists
`packages/verify-cli`.

**What we do:** both. `@rubric-protocol/x402-attest` exposes the documented `x402-attest`
bin; `@rubric-protocol/x402-verify-cli` is a read-only package exposing `x402-verify`.

## 15. Exit code for a root that does not match the anchored record

**Spec:** lists 0 valid, 1 hash mismatch, 2 proof mismatch, 3 not anchored,
4 fetch failed — with no code for "the anchored attestation contains a different
root".

**What we do:** exit 2. It is a break in the chain from leaf to anchored root,
which is what code 2 means. Exit 3 is reserved for a receipt that is internally
valid and simply has not reached the ledger yet.
