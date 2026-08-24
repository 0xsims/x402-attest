# @tempus1/x402-verify-cli

Standalone verifier for x402 attestation receipts.

```bash
npx @tempus1/x402-verify-cli verify ./receipt.json
echo $?   # 0 = valid
```

## Why a separate package

The point of a receipt is that a third party can check it without trusting the
agent that produced it. Someone handing a receipt to an auditor should be able to
say: this package only reads. It cannot write files, cannot pay for anything, cannot
sign anything, and its entire network surface is one unauthenticated GET.

No API key. No Rubric account. No cooperation from the seller or the buyer.

## Exit codes

| exit | meaning |
|---|---|
| 0 | valid |
| 1 | hash mismatch — the record does not hash to its claimed leaf |
| 2 | proof mismatch — the proof does not reach the anchored root |
| 3 | not anchored — locally valid, but not on the ledger yet |
| 4 | fetch failed — the public verify endpoint could not be reached |

3 and 4 are deliberately distinct from 1 and 2. A batch that has not flushed, and a
verifier you cannot reach, are not the same thing as a forged receipt.

## Options

```
--offline          hash and inclusion proof only; no network
--verify-url <url> override the endpoint recorded in the receipt
--timeout <ms>     anchor fetch timeout (default 15000)
--json             machine-readable output
--quiet            suppress human-readable output
```

Input may be a single receipt, a JSON array, or JSONL. With several, the exit code
is the worst result across all of them.

## What it checks

1. `sha256(jcs(callRecord))` equals the claimed `leafHash`. Pure local computation;
   catches any mutation of any byte of the record.
2. Walking `proof` from that leaf reproduces `root`. Also purely local.
3. `GET /v1/verify/{attestationId}` reports `anchored` and carries the same root.

Steps 1 and 2 run with `--offline` and need nothing but the file.

## Library use

```ts
import { verifyReceipt, VERIFY_EXIT } from '@tempus1/x402-verify-cli';

const result = await verifyReceipt(receipt);
if (!result.ok) console.error(result.code, result.reason);
```

Also re-exports the primitives, so a verifier can be reimplemented against them in
another language and checked for agreement: `jcs`, `sha256Jcs`, `buildMerkleTree`,
`computeRootFromProof`, `hashLeaf`, `hashNode`, `MERKLE_PARAMS`.
