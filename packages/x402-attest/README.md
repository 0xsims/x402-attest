# @0xsims/x402-attest

Drop-in attestation wrapper for x402 payment clients. Every paid call produces a
tamper-evident receipt that a third party can verify without trusting the agent, the
seller, or Rubric.

```diff
+ import { withAttestation } from '@0xsims/x402-attest';
+ const fetchAndPay = withAttestation(baseX402Fetch, { subjectId: 'agent-alpha' });

- const res = await baseX402Fetch(url, init);
+ const res = await fetchAndPay(url, init);
```

- Never blocks the request path; anchoring is async and best-effort-durable.
- Never transmits plaintext request or response bodies.
- Batched Merkle anchoring: ~$0.00002 per call at a batch size of 256.
- Failures are attested, not swallowed.
- Verification needs no API key and no cooperation from us.

Zero runtime dependencies. Node >= 20.11.

```bash
npx @0xsims/x402-attest verify ./receipt.json   # exit 0 = valid
```

Full documentation, a worked receipt, and an honest account of what a receipt does
and does not prove: **[root README](../../README.md)**.

- [ASSUMPTIONS.md](../../ASSUMPTIONS.md)
- [DEVIATIONS.md](../../DEVIATIONS.md)
