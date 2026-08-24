# FIX TASK: four defects found by the first live mainnet run

Four bugs, each located precisely, each found by paying a real x402 v2 seller on
Base mainnet and anchoring the result on Hedera. Fix all four, add regression tests
built from the REAL wire data below, and record what you learned in DEVIATIONS.md.

Read this whole file before changing anything. Do not guess at wire formats — every
shape you need is either quoted here or readable from `node_modules`.

---

## The run that found these

- Seller: `POST https://blockrun.ai/api/v1/chat/completions`, x402 **v2**, Base mainnet
- Paid: 2000 atomic USDC ($0.002) to `0xe9030014F5DAe217d0A152f02A043567b16c1aBf`
- Settled: tx `0xe4586d62b584cc796f4a471faf9b51d21ec236cc695db67804ad372fdf4ed23a`
- Anchored: attestation `04264ea8-046a-410d-a77c-4d6a49c28b1d`
- HTTP 200, `model` served `openai/gpt-5.5`

The seller serves the challenge in **three headers** — `WWW-Authenticate: X402
requirements="<b64>"`, `payment-required: <b64>`, `x-payment-required: <b64>` — AND
returns a human-readable JSON error body at the same time. That combination is what
broke things: the code assumed a challenge arrives as *either* a header *or* a body,
never both.

Decoded challenge (authoritative):

```json
{ "x402Version": 2,
  "accepts": [{ "scheme": "exact", "network": "eip155:8453", "amount": "2000",
    "asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "payTo": "0xe9030014F5DAe217d0A152f02A043567b16c1aBf",
    "maxTimeoutSeconds": 300, "extra": { "name": "USD Coin", "version": "2" } }],
  "resource": { "url": "https://blockrun.ai/api/v1/chat/completions",
    "description": "GPT-5.5 API call (~17 input, 8 max output tokens)",
    "mimeType": "application/json" } }
```

402 body served alongside it (NOT authoritative — human error text):

```json
{ "error": "Payment Required", "message": "This endpoint requires x402 payment",
  "price": { "amount": "0.002000", "currency": "USD" },
  "paymentInfo": { "network": "base", ... } }
```

Settlement header actually returned on the 200 (`payment-response`, b64):

```
eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4ZTQ1ODZkNjJiNTg0Y2M3OTZmNGE0NzFmYWY5YjUxZDIxZWMyMzZjYzY5NWRiNjc4MDRhZDM3MmZkZjRlZDIzYSIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1MyIsInBheWVyIjoiMHg2QTc0MkFhNDBjMkEzYTVlYzZlYTczMGMzQzQ3RmNjODNDNDg3NTgzIn0=
```

What the receipt actually recorded (all four bugs visible at once):

```json
"challenge": { "scheme": "unknown", "network": "unknown",
               "maxAmountRequired": "0.002000", "payTo": "unknown", "asset": "unknown" },
"payment":   { "scheme": "unknown", "network": "unknown",
               "amountAuthorized": "2000", "payTo": "0xe903…" }
```

---

## BUG 1 — the header challenge is discarded whenever a body is also present

**Where:** `src/index.ts:519`

```ts
headerValue: obs.challengeRaw && !obs.challengeBody ? obs.challengeRaw : undefined,
```

**Why it's wrong:** BlockRun sends both. `challengeBody` is truthy, so `headerValue`
is passed as `undefined`, so `parseChallenge` falls through to the body — which has
no `accepts`, no `payTo`, no `scheme`, no `network`, and a *USD-formatted* price of
`"0.002000"` where the header says `"2000"` atomic. That single substitution causes
`price_matches_challenge` to **fail** on a completely correct payment, and drops
`payto_matches_challenge` to `unknown`.

A spurious price-mismatch on an honest payment is the worst failure this library
has: it discredits the assertion set, which is the entire product.

**Root cause, one level down:** `TapObservation` (`src/types.ts`) has a single
`challengeRaw` field that `tap.ts` uses for *both* the decoded header value and the
raw 402 body text. The call site cannot distinguish them, which is why it resorts to
that heuristic.

**Fix:**
1. Add `challengeHeader?: string` to `TapObservation`.
2. In `tap.ts`, write the header value to `store.challengeHeader` and only
   `??=` it into `challengeRaw` (which stays the bytes-for-hashing field).
3. At `index.ts:519`, pass `headerValue: obs.challengeHeader` unconditionally.
   `parseChallenge` already prefers a decodable header over the body — that
   precedence is correct for v2 and must not be conditional on the body's absence.
4. Also accept `www-authenticate` in `CHALLENGE_HEADERS` handling: parse
   `X402 requirements="<b64>"` and extract the quoted value. Some v2 servers send
   only that. Keep `payment-required` and `x-payment-required` as-is.

---

## BUG 2 — the v2 payment payload only partly parses

**Where:** `parsePaymentHeader` in `src/x402.ts`

`amountAuthorized` (`2000`) and `payTo` parsed correctly, but `scheme`, `network`
and `asset` came back `unknown`, so `network_allowed` and `payto_allowed` degrade
to `unknown` when they should be real checks.

**Do not guess the v2 envelope shape.** The encoder is on disk. Read
`node_modules/@x402/evm/dist/esm/**` (the `exact` client scheme) and
`node_modules/@x402/core/dist/esm/**` to find exactly how the `PAYMENT-SIGNATURE`
payload is constructed, then extend the parser to read those fields. Record the
observed shape in DEVIATIONS.md, since it is not in the published spec.

Keep the existing v1 field spellings working. The hash-only rule is unchanged: the
header plaintext must never leave `parsePaymentHeader`'s stack frame.

---

## BUG 3 — the verifier fetches the human HTML page instead of the JSON API

**Where:** `src/anchor.ts:326-329` and `src/verify.ts:297`

`anchor.ts` prefers the server-supplied `verifyUrl`, commented as "authoritative".
Rubric returns `https://rubric-protocol.com/audit/{id}` — a **human-facing HTML
page**. `verify.ts` then fetches it and dies on `Unexpected token '<', "<!DOCTYPE"`.

The JSON API is `https://rubric-protocol.com/v1/verify/{id}` and it works. Confirmed
live against attestation `04264ea8-046a-410d-a77c-4d6a49c28b1d`.

**Fix:** keep both, and keep them distinct.
- `receipt.verifyUrl` stays the human page — it is what you hand a person.
- Add `receipt.verifyApiUrl`, always built by `verifyUrlFor(baseUrl, attestationId)`,
  never taken from the server response.
- `verifyReceipt` uses `verifyApiUrl`, falling back to deriving `/v1/verify/{id}`
  from the origin of `verifyUrl` for receipts written before this change.
- If a fetch returns non-JSON, say so plainly — "expected JSON from the verify API,
  got text/html; this looks like the human audit page, not /v1/verify" — rather
  than surfacing a raw JSON parse error.

---

## BUG 4 — a pending anchor is reported as a failure

**Where:** `src/verify.ts:402`

```ts
if (remote.status !== 'anchored') { checks.anchored = 'fail'; … }
```

The live attestation returned:

```json
{ "status": "signed-pending-hcs", "verified": true, "payloadHashMatch": true,
  "sequenceNumber": null, "aggregateBinding": null, "hcsExplorerUrl": null }
```

HCS anchoring happens at the next tier-2 flush, typically 60–120s after submission.
So every receipt verified inside that window currently reports `fail` — which, in a
tamper-evidence tool, reads as "this record was altered". Crying wolf here is worse
than saying nothing.

**Fix:** add `'pending'` to the `anchored` check states. `signed-pending-hcs` (and
any other non-terminal state the API reports) maps to `pending`, with a reason that
says the signature verified and the ledger anchor is still in flight. `ok` stays
false — pending is not verified — but the exit code and the message must
distinguish "not yet anchored" from "does not match". Give it its own
`VERIFY_EXIT` code and document it in the README's exit-code table.

---

## Tests — build them from the real bytes above

Add a fixtures module holding the verbatim wire data from this run: the challenge
b64, the 402 body, the settlement header b64, and the observed `/v1/verify`
response for both `signed-pending-hcs` and `anchored` states.

Required cases:

- Header **and** body present together → challenge parses from the header;
  `maxAmountRequired === '2000'`, `payTo`, `scheme`, `network`, `asset` all populated
- The same fixture end to end → `price_matches_challenge` is `pass`, not `fail`
- `www-authenticate: X402 requirements="…"` alone → parses identically
- Body only, no header → v1 path still works, unchanged
- v2 payment header → `scheme`, `network`, `asset` populated; v1 header still parses
- `verifyReceipt` against an HTML response → clear diagnostic, not a JSON parse error
- `verifyReceipt` against `signed-pending-hcs` → `pending`, not `fail`
- A receipt lacking `verifyApiUrl` → derives it from `verifyUrl`'s origin

**The trap to avoid, again.** DEVIATIONS.md §4 already records one instance of a
mock that encoded an assumption and was then used to validate it. Every fixture here
must be the bytes actually observed on the wire, pasted verbatim — not a mock shaped
the way the code expects. If a fixture and the code disagree, the fixture is right.

---

## Definition of done

- All four fixed, `npm test` green, coverage thresholds held
- New fixtures are verbatim wire captures
- DEVIATIONS.md gains entries for: the both-header-and-body case, the observed v2
  `PAYMENT-SIGNATURE` shape, Rubric's `verifyUrl` being a human page, and the
  `signed-pending-hcs` state with its 60–120s window
- README: exit-code table updated for the pending state; assertion docs updated
  where behaviour changed
- Version bumped to 0.1.1 in all three packages
