# @rubric/clawrouter-attest

Attest every call your agent makes through [ClawRouter](https://github.com/BlockRunAI/ClawRouter),
so its routing decisions become independently checkable.

## Why

ClawRouter is MIT-licensed, runs a local OpenAI-compatible x402 proxy on port 8402,
and already emits `x-clawrouter-*` headers describing which model it picked and why.
That is most of the evidence an auditor needs. What is missing is a tamper-evident
record binding those routing decisions to the payments made for them.

ClawRouter's pitch is that it saves you money by routing to a cheaper model that is
good enough. That is a claim about substitution, and the honest way to back a
substitution claim is to make the substitutions verifiable by the party paying the
bill. Attaching receipts turns "we saved you 92%" from a dashboard number into
something a buyer's auditor can check without asking BlockRun or Rubric to vouch for
it.

**This is complementary, not adversarial.** A router with nothing to hide gets a
stronger claim out of it than anyone else.

## Two wirings

### 1. Wrap the fetch (one line, no extra hop)

```ts
import { withClawRouterAttestation } from '@rubric/clawrouter-attest';

const fetchAndPay = withClawRouterAttestation(myX402Fetch, {
  subjectId: 'agent-alpha',
  rubricApiKey: process.env.RUBRIC_API_KEY, // omit for the keyless x402 path
  policy: { maxPricePerCall: '0.05', allowedNetworks: ['eip155:8453'] },
});

await fetchAndPay('http://localhost:8402/v1/chat/completions', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ model: 'anthropic/claude-sonnet-4.6', messages }),
});
```

A tap is installed for you, so the 402 handshake is observed and the price and payee
assertions are real checks rather than `unknown`.

### 2. Attesting reverse proxy (when the client cannot change)

```ts
import { createAttestingProxy } from '@rubric/clawrouter-attest';

const proxy = createAttestingProxy({
  listenPort: 8403,
  upstream: 'http://127.0.0.1:8402',
  subjectId: 'clawrouter-proxy',
});
```

Point clients at `:8403`. Every response carries:

| header | when |
|---|---|
| `x-rubric-call-id` | always |
| `x-rubric-attestation-id` | only once the call's batch is anchored |
| `x-rubric-receipt-url` | only once the call's batch is anchored |

The last two are **omitted while anchoring is pending, never waited for**. Batches
anchor on a 60s / 256-leaf schedule, and holding an LLM response for up to a minute
to decorate it with a header would be an absurd trade. `x-rubric-call-id` is the
durable handle: pass it to `getReceipt(callId)` once the batch lands.

## What you get

Every proxied call produces a receipt recording, among the eight standard checks:

```json
{ "id": "model_matches_request", "result": "fail",
  "observed": "sha256:5f2a...", "expected": "sha256:c81d...",
  "detail": "served-model source=x-clawrouter-model" }
```

A `fail` here means the model served differed from the model requested. That is
often entirely legitimate — it is what a cost-saving router does. The point is that
it is now a matter of record rather than a matter of trust.

Under the default `hash-only` redaction the model names are digests, so the receipt
proves the comparison without disclosing the content. Use `redact: 'metadata'` to
keep names and token counts in clear.

Routing headers captured by prefix: `x-clawrouter-profile`, `-tier`, `-model`,
`-confidence`, `-reasoning`.

## Notes

- ClawRouter suppresses its debug headers when `CLAWROUTER_DEBUG_HEADERS=off`, and
  does not emit them on streaming responses. Without them the served model falls
  back to the response body, and if that is absent too the check reports `unknown`
  rather than guessing.
- `createRoutingObserver()` adapts ClawRouter's `startProxy({ onRouted, onPayment })`
  callbacks. They carry no request identity, so the events are kept as context and
  deliberately **not** folded into call records — inventing a correlation would put
  a guess into an audit artifact.

See the [root README](../../README.md) for the full model, and
[what this does and does not prove](../../README.md#what-this-does-and-does-not-prove).
