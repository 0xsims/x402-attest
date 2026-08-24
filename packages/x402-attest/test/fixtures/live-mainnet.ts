import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import type { Receipt } from '../../src/types.js';

/**
 * Wire data from the first live mainnet run, and how each piece was obtained.
 *
 * DEVIATIONS.md §4 records what happens when a mock encodes an assumption and is
 * then used to validate it: a verifier that could never work against the real API
 * passed every test. Every value here is therefore traceable to something
 * observed, and each one says which. Where the code and a fixture disagree, the
 * fixture wins.
 *
 * The run:
 *   seller       POST https://blockrun.ai/api/v1/chat/completions (x402 v2)
 *   paid         2000 atomic USDC ($0.002) to 0xe9030014F5DAe217d0A152f02A043567b16c1aBf
 *   settled      tx 0xe4586d62b584cc796f4a471faf9b51d21ec236cc695db67804ad372fdf4ed23a
 *   anchored     attestation 04264ea8-046a-410d-a77c-4d6a49c28b1d
 *   served       openai/gpt-5.5, HTTP 200
 */

const DIR = join(__dirname, 'live-mainnet');
const read = (name: string): string => readFileSync(join(DIR, name), 'utf8');

/* ------------------------------------------------------------------ *
 * The 402 challenge.
 *
 * Captured verbatim by re-probing BlockRun with the same request body. That
 * this is byte-identical to the challenge the live run saw is not an assumption:
 * the receipt recorded `challenge.rawHash`, and
 *
 *   sha256(CHALLENGE_HEADER_B64) === LIVE_RECEIPT.callRecord.challenge.rawHash
 *
 * which `live-wire.test.ts` asserts. The request body is pinned the same way,
 * against `request.bodyHash`.
 * ------------------------------------------------------------------ */

const CHALLENGE_HEADERS = JSON.parse(read('challenge-headers.json')) as Record<string, string>;

/** `payment-required`, `x-payment-required` and the `www-authenticate` quoted value are identical. */
export const CHALLENGE_HEADER_B64 = CHALLENGE_HEADERS['payment-required']!;
export const CHALLENGE_HEADER_X_B64 = CHALLENGE_HEADERS['x-payment-required']!;

/** `WWW-Authenticate: X402 requirements="<b64>"`, verbatim including the scheme token. */
export const CHALLENGE_WWW_AUTHENTICATE = CHALLENGE_HEADERS['www-authenticate']!;

/**
 * The 402 body served alongside all three headers. Human error text, not
 * requirements: no `accepts`, no `payTo`, no `scheme`, no `network`, and a price
 * of `"0.002000"` in USD where the header says `"2000"` atomic.
 */
export const CHALLENGE_BODY_402: unknown = JSON.parse(read('challenge-402.json'));
export const CHALLENGE_BODY_402_TEXT = read('challenge-402.json');

/** The request that drew the 402, reconstructed and confirmed against `request.bodyHash`. */
export const REQUEST_BODY = JSON.stringify({
  model: 'openai/gpt-5.5',
  messages: [{ role: 'user', content: 'Reply with exactly one word: attested' }],
  max_tokens: 16,
});

/* ------------------------------------------------------------------ *
 * The settlement receipt, lifted verbatim from the 200's `payment-response`
 * header as recorded in the receipt.
 * ------------------------------------------------------------------ */

export const SETTLEMENT_HEADER_B64 =
  'eyJzdWNjZXNzIjp0cnVlLCJ0cmFuc2FjdGlvbiI6IjB4ZTQ1ODZkNjJiNTg0Y2M3OTZmNGE0NzFmYWY5' +
  'YjUxZDIxZWMyMzZjYzY5NWRiNjc4MDRhZDM3MmZkZjRlZDIzYSIsIm5ldHdvcmsiOiJlaXAxNTU6ODQ1' +
  'MyIsInBheWVyIjoiMHg2QTc0MkFhNDBjMkEzYTVlYzZlYTczMGMzQzQ3RmNjODNDNDg3NTgzIn0=';

/* ------------------------------------------------------------------ *
 * The payment headers.
 *
 * These are the one thing that could NOT be captured from the live run, and the
 * reason is by design: the payment header is a signed bearer instrument, so
 * `parsePaymentHeader` hashes it and the plaintext never leaves that stack
 * frame. The receipt kept `xPaymentHash`, nothing more.
 *
 * So instead of writing one by hand — which would be exactly the §4 mistake —
 * these were produced by the shipping encoder on disk, `@x402/core` +
 * `@x402/evm`, signing the real challenge above with a throwaway key that has
 * never been funded. `live-wire.test.ts` re-runs that encoder and asserts the
 * frozen fixtures still match the shape it emits, so the fixtures cannot drift
 * away from the library that produces the real thing.
 * ------------------------------------------------------------------ */

/** v2 `PAYMENT-SIGNATURE`: `{ x402Version, payload, extensions, resource, accepted }`. */
export const PAYMENT_HEADER_V2_B64 = read('payment-signature-v2.b64').trim();

/** v1 `X-PAYMENT`: `{ x402Version, scheme, network, payload }`. */
export const PAYMENT_HEADER_V1_B64 = read('payment-signature-v1.b64').trim();

/** The throwaway payer. Never funded, never used anywhere else. */
export const FIXTURE_PAYER = '0x19E7E376E7C213B7E7e7e46cc70A5dD086DAff2A';

/* ------------------------------------------------------------------ *
 * Rubric's two URLs for one attestation, and what each returns.
 * ------------------------------------------------------------------ */

export const ATTESTATION_ID = '04264ea8-046a-410d-a77c-4d6a49c28b1d';

/** What the keyless anchor returned as `verifyUrl`. A rendered HTML page. */
export const AUDIT_PAGE_URL = `https://rubric-protocol.com/audit/${ATTESTATION_ID}`;
/** The JSON API for the same record. */
export const VERIFY_API_URL = `https://rubric-protocol.com/v1/verify/${ATTESTATION_ID}`;

/** `GET /audit/{id}` verbatim: HTTP 200, `text/html`, 32KB — even with `accept: application/json`. */
export const AUDIT_PAGE_HTML = read('audit-page.html');

/** `GET /v1/verify/{id}` verbatim, once the batch had reached HCS. */
export const VERIFY_ANCHORED: Record<string, unknown> = JSON.parse(read('verify-anchored.json'));
export const VERIFY_ANCHORED_TEXT = read('verify-anchored.json');

/**
 * The same record during the 60-120s window before the tier-2 flush.
 *
 * The live run observed `status: "signed-pending-hcs"` with `verified: true`,
 * `payloadHashMatch: true`, and `sequenceNumber`, `aggregateBinding` and
 * `hcsExplorerUrl` all null — the record is signed and held, the ledger anchor
 * has not landed. Those five fields are the observation; every other field is
 * the anchored capture above, unchanged. Built here rather than pasted so the
 * delta between the two states is visible instead of buried in 35KB of JSON.
 */
export const VERIFY_PENDING: Record<string, unknown> = {
  ...VERIFY_ANCHORED,
  status: 'signed-pending-hcs',
  verified: true,
  payloadHashMatch: true,
  sequenceNumber: null,
  hcsSequence: null,
  aggregateBinding: null,
  hcsExplorerUrl: null,
};

/**
 * The receipt the live run wrote, verbatim.
 *
 * Predates `verifyApiUrl`, so it is also the regression fixture for a receipt
 * that has only the human `verifyUrl` and must have the API path derived.
 */
export const LIVE_RECEIPT = JSON.parse(read('receipt.json')) as Receipt;
