import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { rmSync } from 'node:fs';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { privateKeyToAccount } from 'viem/accounts';
import {
  parseChallenge,
  parsePaymentHeader,
  parseSettlementHeader,
  pickChallengeHeader,
  unwrapChallengeHeader,
} from '../src/x402.js';
import { computeAssertions } from '../src/assertions.js';
import { ZERO } from '../src/decimal.js';
import { deriveVerifyApiUrl, VERIFY_EXIT, verifyReceipt } from '../src/verify.js';
import { verifyApiUrlFrom } from '../src/anchor.js';
import { createTap, withAttestation } from '../src/index.js';
import type { AnyReceipt, CallRecord, FetchLike, Receipt } from '../src/types.js';
import { tmpWal } from './mocks/rubric.js';
import * as fx from './fixtures/live-mainnet.js';

/**
 * Regressions from the first live mainnet run.
 *
 * Every input here is wire data — see `fixtures/live-mainnet.ts` for how each
 * piece was obtained and which parts are captures rather than reconstructions.
 * Four defects showed up on that single call, and all four produced the same
 * class of damage: a correct payment described as incorrect, or a valid receipt
 * described as failed. In a tamper-evidence tool a false alarm is worse than
 * silence, so these are the tests that matter most.
 */

const jsonResponse = (body: unknown): FetchLike => async () =>
  new Response(JSON.stringify(body), {
    status: 200,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  });

/** BlockRun's real 402: three challenge headers AND a human-readable body. */
function liveChallengeHeaders(): Headers {
  return new Headers({
    'content-type': 'application/json',
    'payment-required': fx.CHALLENGE_HEADER_B64,
    'x-payment-required': fx.CHALLENGE_HEADER_X_B64,
    'www-authenticate': fx.CHALLENGE_WWW_AUTHENTICATE,
  });
}

describe('the fixtures are the bytes that were actually on the wire', () => {
  it('pins the challenge header against the hash the live receipt recorded', () => {
    // The receipt hashes the challenge bytes precisely so this is checkable
    // later. If the capture were a paraphrase, this would not match.
    const hash = createHash('sha256').update(fx.CHALLENGE_HEADER_B64).digest('hex');
    expect(hash).toBe(fx.LIVE_RECEIPT.callRecord.challenge?.rawHash);
  });

  it('pins the request body against the hash the live receipt recorded', () => {
    const hash = createHash('sha256').update(fx.REQUEST_BODY).digest('hex');
    expect(hash).toBe(fx.LIVE_RECEIPT.callRecord.request.bodyHash);
  });

  it('serves the same base64 in all three challenge headers', () => {
    expect(fx.CHALLENGE_HEADER_X_B64).toBe(fx.CHALLENGE_HEADER_B64);
    expect(fx.CHALLENGE_WWW_AUTHENTICATE).toBe(
      `X402 requirements="${fx.CHALLENGE_HEADER_B64}"`,
    );
  });

  it('keeps the frozen v2 payment fixture in step with the shipping encoder', async () => {
    // The payment header could not be captured from the live run — it is hashed
    // and discarded by design. Re-running the real encoder here is what stops
    // the frozen fixture from drifting into a shape nothing produces.
    const account = privateKeyToAccount(`0x${'11'.repeat(32)}`);
    const client = new x402Client();
    client.register('eip155:*', new ExactEvmScheme(account));
    const fresh = (await client.createPaymentPayload(
      JSON.parse(Buffer.from(fx.CHALLENGE_HEADER_B64, 'base64').toString('utf8')),
    )) as Record<string, unknown>;

    const frozen = JSON.parse(
      Buffer.from(fx.PAYMENT_HEADER_V2_B64, 'base64').toString('utf8'),
    ) as Record<string, unknown>;

    expect(Object.keys(fresh).sort()).toEqual(Object.keys(frozen).sort());
    expect(fresh['accepted']).toEqual(frozen['accepted']);
    expect(fresh['resource']).toEqual(frozen['resource']);
    // `nonce` and `validBefore` are fresh per payload; the rest is stable.
    expect(Object.keys(fresh['payload'] as object).sort()).toEqual(
      Object.keys(frozen['payload'] as object).sort(),
    );
  });
});

describe('BUG 1 — a challenge served as both header and body', () => {
  it('parses from the header when a body is present too', () => {
    const parsed = parseChallenge({
      body: fx.CHALLENGE_BODY_402,
      headerValue: pickChallengeHeader(liveChallengeHeaders()),
      rawBytes: fx.CHALLENGE_HEADER_B64,
    });

    expect(parsed?.record).toMatchObject({
      scheme: 'exact',
      network: 'eip155:8453',
      maxAmountRequired: '2000',
      payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    });
    expect(parsed?.record.maxTimeoutSeconds).toBe(300);
    expect(parsed?.record.resource).toBe('https://blockrun.ai/api/v1/chat/completions');
  });

  it('does not substitute the body’s USD price for the header’s atomic amount', () => {
    // This is the whole bug in one assertion. The body says "0.002000" USD; the
    // header says "2000" atomic. Recording the former against a payment that
    // authorized the latter fails price_matches_challenge on an honest payment.
    const parsed = parseChallenge({
      body: fx.CHALLENGE_BODY_402,
      headerValue: fx.CHALLENGE_HEADER_B64,
      rawBytes: fx.CHALLENGE_HEADER_B64,
    });
    expect(parsed?.record.maxAmountRequired).not.toBe('0.002000');
    expect(parsed?.record.maxAmountRequired).toBe('2000');
  });

  it('parses identically from www-authenticate alone', () => {
    const headerOnly = new Headers({ 'www-authenticate': fx.CHALLENGE_WWW_AUTHENTICATE });
    const viaWww = parseChallenge({
      headerValue: pickChallengeHeader(headerOnly),
      rawBytes: fx.CHALLENGE_HEADER_B64,
    });
    const viaDedicated = parseChallenge({
      headerValue: fx.CHALLENGE_HEADER_B64,
      rawBytes: fx.CHALLENGE_HEADER_B64,
    });
    expect(viaWww?.record).toEqual(viaDedicated?.record);
  });

  it('ignores a www-authenticate that belongs to another auth scheme', () => {
    // A 401 from an unrelated auth layer must not be read as payment terms.
    expect(unwrapChallengeHeader('www-authenticate', 'Bearer realm="api"')).toBeUndefined();
    expect(unwrapChallengeHeader('www-authenticate', 'Basic realm="x", Digest qop="auth"'))
      .toBeUndefined();
    expect(pickChallengeHeader(new Headers({ 'www-authenticate': 'Bearer realm="api"' })))
      .toBeUndefined();
  });

  it('finds the x402 challenge alongside another scheme in one header', () => {
    const combined = `Bearer realm="api", X402 requirements="${fx.CHALLENGE_HEADER_B64}"`;
    expect(unwrapChallengeHeader('www-authenticate', combined)).toBe(fx.CHALLENGE_HEADER_B64);
  });

  it('still reads a v1 challenge from the body when no header is served', () => {
    const v1Body = {
      x402Version: 1,
      accepts: [
        {
          scheme: 'exact',
          network: 'base',
          maxAmountRequired: '2000',
          payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          resource: 'https://blockrun.ai/api/v1/chat/completions',
          maxTimeoutSeconds: 300,
        },
      ],
    };
    const parsed = parseChallenge({ body: v1Body, rawBytes: JSON.stringify(v1Body) });
    expect(parsed?.record).toMatchObject({
      scheme: 'exact',
      network: 'base',
      maxAmountRequired: '2000',
      payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
    });
  });
});

describe('BUG 2 — the v2 payment envelope', () => {
  it('reads scheme, network and asset out of `accepted`', () => {
    const payment = parsePaymentHeader(fx.PAYMENT_HEADER_V2_B64);
    expect(payment).toMatchObject({
      scheme: 'exact',
      network: 'eip155:8453',
      amountAuthorized: '2000',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
    });
    expect(payment?.scheme).not.toBe('unknown');
    expect(payment?.network).not.toBe('unknown');
    expect(payment?.asset).not.toBe('unknown');
  });

  it('still parses the v1 envelope, where those fields are top-level', () => {
    const payment = parsePaymentHeader(fx.PAYMENT_HEADER_V1_B64);
    expect(payment).toMatchObject({
      scheme: 'exact',
      network: 'base',
      amountAuthorized: '2000',
      asset: 'unknown', // v1 payloads carry no asset; saying so beats guessing
      payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
    });
  });

  it('records the payee, not the token collector, for an escrow-style v2 payload', () => {
    // The `upto` and auth-capture schemes sign `authorization.to` as a fixed
    // collector contract and route to the payee from there. Reading `to` would
    // name the collector as the payee and fail payto_matches_challenge on a
    // correct payment — the same false-alarm class as BUG 1.
    const COLLECTOR = '0x0E3dF9510de65469C4518D7843919c0b8C7A7757';
    const envelope = {
      x402Version: 2,
      accepted: {
        scheme: 'upto',
        network: 'eip155:8453',
        amount: '2000',
        asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
        payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
        maxTimeoutSeconds: 300,
      },
      payload: {
        authorization: { from: fx.FIXTURE_PAYER, to: COLLECTOR, value: '2000' },
        signature: '0xdead',
      },
    };
    const payment = parsePaymentHeader(
      Buffer.from(JSON.stringify(envelope), 'utf8').toString('base64'),
    );
    expect(payment?.payTo).toBe('0xe9030014F5DAe217d0A152f02A043567b16c1aBf');
    expect(payment?.payTo).not.toBe(COLLECTOR);
    expect(payment?.scheme).toBe('upto');
  });

  it('never lets the header plaintext into the record', () => {
    const payment = parsePaymentHeader(fx.PAYMENT_HEADER_V2_B64);
    const serialized = JSON.stringify(payment);
    expect(serialized).not.toContain(fx.PAYMENT_HEADER_V2_B64);
    // The signature is the bearer half; it must not appear in any form.
    const decoded = JSON.parse(
      Buffer.from(fx.PAYMENT_HEADER_V2_B64, 'base64').toString('utf8'),
    ) as { payload: { signature: string } };
    expect(serialized).not.toContain(decoded.payload.signature);
    expect(payment?.xPaymentHash).toMatch(/^[0-9a-f]{64}$/);
  });
});

describe('BUG 1 + BUG 2 together — the assertions the live run got wrong', () => {
  function assertionsFromLiveWire() {
    const payment = parsePaymentHeader(fx.PAYMENT_HEADER_V2_B64);
    const challenge = parseChallenge(
      {
        body: fx.CHALLENGE_BODY_402,
        headerValue: pickChallengeHeader(liveChallengeHeaders()),
        rawBytes: fx.CHALLENGE_HEADER_B64,
      },
      payment ? { scheme: payment.scheme, network: payment.network } : undefined,
    );
    const settlement = parseSettlementHeader(fx.SETTLEMENT_HEADER_B64);

    const result = computeAssertions({
      policy: { maxPricePerCall: '0.10', allowedNetworks: ['eip155:8453'], budgetCap: '1.00' },
      ...(challenge ? { challenge: challenge.record } : {}),
      ...(payment ? { payment } : {}),
      ...(settlement ? { settlement } : {}),
      sessionSpendBefore: ZERO,
      assetDecimals: {},
      defaultAssetDecimals: 6, // USDC, as the library defaults
      redact: 'hash-only',
    });
    return new Map(result.assertions.map((a) => [a.id, a]));
  }

  it('passes price_matches_challenge on the payment that was reported as a violation', () => {
    const a = assertionsFromLiveWire().get('price_matches_challenge');
    expect(a?.result).toBe('pass');
    expect(a?.observed).toBe('2000');
    expect(a?.expected).toBe('2000');
  });

  it('turns payto, network and payto_allowed from unknown into real verdicts', () => {
    const byId = assertionsFromLiveWire();
    expect(byId.get('payto_matches_challenge')?.result).toBe('pass');
    expect(byId.get('network_allowed')?.result).toBe('pass');
    // No allowedPayTo in this policy, so this one stays unknown for the right
    // reason — an unset policy, not an unobservable payee.
    expect(byId.get('payto_allowed')?.detail).toMatch(/allowedPayTo not set/);
  });

  it('leaves settlement and the price cap where they already were', () => {
    const byId = assertionsFromLiveWire();
    expect(byId.get('settled')?.result).toBe('pass');
    expect(byId.get('settled')?.observed).toBe(
      '0xe4586d62b584cc796f4a471faf9b51d21ec236cc695db67804ad372fdf4ed23a',
    );
    expect(byId.get('price_within_policy')?.result).toBe('pass');
  });
});

describe('end to end, through the tap, on the bytes that broke it', () => {
  /** Replays the captured 402 and the captured 200, byte for byte. */
  const blockRunUpstream: FetchLike = async (_input, init) => {
    const sent = new Headers(init?.headers as ConstructorParameters<typeof Headers>[0]);
    if (!sent.get('payment-signature') && !sent.get('x-payment')) {
      // Three challenge headers AND a human-readable body, which is the
      // combination the code could not handle.
      return new Response(fx.CHALLENGE_BODY_402_TEXT, {
        status: 402,
        headers: liveChallengeHeaders(),
      });
    }
    return new Response(
      JSON.stringify({
        id: 'chatcmpl-live',
        model: 'openai/gpt-5.5',
        choices: [{ index: 0, message: { role: 'assistant', content: 'attested' } }],
      }),
      {
        status: 200,
        headers: {
          'content-type': 'application/json',
          'payment-response': fx.SETTLEMENT_HEADER_B64,
        },
      },
    );
  };

  /** Reads the header challenge, pays with the frozen v2 envelope, retries. */
  const payWith = (inner: FetchLike): FetchLike => async (input, init) => {
    const first = await inner(input, init);
    if (first.status !== 402) return first;
    const headers = new Headers(init?.headers as ConstructorParameters<typeof Headers>[0]);
    headers.set('PAYMENT-SIGNATURE', fx.PAYMENT_HEADER_V2_B64);
    return inner(input, { ...init, headers });
  };

  async function runOnce(): Promise<CallRecord> {
    const walPath = tmpWal('live-wire');
    const tap = createTap();
    const receipts: AnyReceipt[] = [];
    const fetchAndPay = withAttestation(payWith(tap.wrapFetch(blockRunUpstream)), {
      subjectId: 'live-demo',
      walPath,
      mode: 'off',
      installSignalHandlers: false,
      tap,
      policy: {
        maxPricePerCall: '0.10',
        allowedNetworks: ['eip155:8453'],
        allowedPayTo: ['0xe9030014F5DAe217d0A152f02A043567b16c1aBf'],
        budgetCap: '1.00',
      },
      onReceipt: (r) => receipts.push(r),
    });

    try {
      const res = await fetchAndPay('https://blockrun.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: fx.REQUEST_BODY,
      });
      expect(res.status).toBe(200);
      await res.arrayBuffer();
      return receipts.at(-1)!.callRecord;
    } finally {
      await fetchAndPay.close();
      rmSync(walPath, { recursive: true, force: true });
    }
  }

  it('records the challenge from the header, not the error body', async () => {
    const record = await runOnce();
    // What the live run recorded here was scheme/network/payTo/asset all
    // "unknown" and a maxAmountRequired of "0.002000".
    expect(record.challenge).toMatchObject({
      scheme: 'exact',
      network: 'eip155:8453',
      maxAmountRequired: '2000',
      payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
    });
    // Still hashing the bytes the seller served, unchanged.
    expect(record.challenge?.rawHash).toBe(fx.LIVE_RECEIPT.callRecord.challenge?.rawHash);
  });

  it('records the payment with its scheme, network and asset', async () => {
    const record = await runOnce();
    expect(record.payment).toMatchObject({
      scheme: 'exact',
      network: 'eip155:8453',
      amountAuthorized: '2000',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      payTo: '0xe9030014F5DAe217d0A152f02A043567b16c1aBf',
    });
  });

  it('does not report a policy violation on a correct payment', async () => {
    const record = await runOnce();
    const byId = new Map(record.assertions.map((a) => [a.id, a.result]));

    expect(byId.get('price_matches_challenge')).toBe('pass');
    expect(byId.get('payto_matches_challenge')).toBe('pass');
    expect(byId.get('network_allowed')).toBe('pass');
    expect(byId.get('payto_allowed')).toBe('pass');
    expect(byId.get('settled')).toBe('pass');
    // The headline: this call was recorded as `policy_violation` on mainnet.
    expect(record.outcome).toBe('ok');
    expect(record.assertions.filter((a) => a.result === 'fail')).toEqual([]);
    expect(record.assertions.filter((a) => a.result === 'unknown')).toEqual([]);
  });
});

describe('BUG 3 — the verifier must call the JSON API, not the audit page', () => {
  it('derives the API URL from a receipt that predates verifyApiUrl', () => {
    expect(fx.LIVE_RECEIPT.verifyApiUrl).toBeUndefined();
    expect(fx.LIVE_RECEIPT.verifyUrl).toBe(fx.AUDIT_PAGE_URL);
    expect(deriveVerifyApiUrl(fx.LIVE_RECEIPT.verifyUrl, fx.ATTESTATION_ID)).toBe(
      fx.VERIFY_API_URL,
    );
  });

  it('leaves an API URL alone and gives up on a non-URL', () => {
    expect(deriveVerifyApiUrl(fx.VERIFY_API_URL, fx.ATTESTATION_ID)).toBe(fx.VERIFY_API_URL);
    expect(deriveVerifyApiUrl('not a url', fx.ATTESTATION_ID)).toBeUndefined();
    expect(deriveVerifyApiUrl(undefined, fx.ATTESTATION_ID)).toBeUndefined();
  });

  it('keeps the issuing node’s origin when building the API URL at anchor time', () => {
    // Tiered attestations resolve from the store of the node that issued them,
    // so the origin the server named has to survive.
    expect(
      verifyApiUrlFrom('https://rubric-protocol.com', fx.AUDIT_PAGE_URL, fx.ATTESTATION_ID),
    ).toBe(fx.VERIFY_API_URL);
    expect(
      verifyApiUrlFrom('https://default.example', 'https://eu.example/audit/x', 'abc'),
    ).toBe('https://eu.example/v1/verify/abc');
    expect(verifyApiUrlFrom('https://default.example', undefined, 'abc')).toBe(
      'https://default.example/v1/verify/abc',
    );
  });

  it('fetches the derived API URL rather than the audit page', async () => {
    const seen: string[] = [];
    const fetchImpl: FetchLike = async (input) => {
      seen.push(String(input));
      return new Response(fx.VERIFY_ANCHORED_TEXT, {
        status: 200,
        headers: { 'content-type': 'application/json; charset=utf-8' },
      });
    };
    const r = await verifyReceipt(fx.LIVE_RECEIPT, { fetchImpl });
    expect(seen).toEqual([fx.VERIFY_API_URL]);
    expect(seen[0]).not.toContain('/audit/');
    expect(r.checks.anchored).toBe('pass');
    expect(r.ok).toBe(true);
  });

  it('explains an HTML response instead of surfacing a JSON parse error', async () => {
    // What the audit page actually returns: 200, text/html, 32KB of document.
    const fetchImpl: FetchLike = async () =>
      new Response(fx.AUDIT_PAGE_HTML, {
        status: 200,
        headers: { 'content-type': 'text/html' },
      });
    const r = await verifyReceipt(fx.LIVE_RECEIPT, { fetchImpl });

    expect(r.code).toBe(VERIFY_EXIT.FETCH_FAILED);
    expect(r.reason).toContain('expected JSON from the verify API');
    expect(r.reason).toContain('text/html');
    expect(r.reason).toContain('human audit page');
    // The diagnostic replaces the parser error, it does not accompany it.
    expect(r.reason).not.toContain('Unexpected token');
    // And it is emphatically not a tampering verdict.
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
  });

  it('reports non-JSON that is not HTML without inventing a page', async () => {
    const fetchImpl: FetchLike = async () =>
      new Response('service unavailable', { status: 200, headers: { 'content-type': 'text/plain' } });
    const r = await verifyReceipt(fx.LIVE_RECEIPT, { fetchImpl });
    expect(r.code).toBe(VERIFY_EXIT.FETCH_FAILED);
    expect(r.reason).toContain('text/plain');
    expect(r.reason).not.toContain('human audit page');
  });
});

describe('BUG 4 — a pending anchor is not a failure', () => {
  it('reports signed-pending-hcs as pending, with its own exit code', async () => {
    const r = await verifyReceipt(fx.LIVE_RECEIPT, {
      fetchImpl: jsonResponse(fx.VERIFY_PENDING),
    });

    expect(r.checks.anchored).toBe('pending');
    expect(r.code).toBe(VERIFY_EXIT.PENDING_ANCHOR);
    expect(r.code).not.toBe(VERIFY_EXIT.NOT_ANCHORED);
    // Pending is not verified, so `ok` stays false.
    expect(r.ok).toBe(false);
    // Everything checkable checked out, and the message leads with that.
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
    expect(r.checks.envelopeRoot).toBe('pass');
    expect(r.reason).toMatch(/still in flight/);
    expect(r.reason).toMatch(/60-120s/);
    expect(r.reason).not.toMatch(/altered|tamper|mismatch/i);
    // This receipt carries no commitment, so the message must not claim one was
    // checked. Reassurance that overstates is the same fault as a false alarm.
    expect(r.checks.commitment).toBe('unverifiable');
    expect(r.reason).toContain('the commitment is unverifiable');
    expect(r.reason).not.toContain('the commitment all check out');
  });

  it('passes the same receipt once the flush has happened', async () => {
    const r = await verifyReceipt(fx.LIVE_RECEIPT, {
      fetchImpl: jsonResponse(fx.VERIFY_ANCHORED),
    });
    expect(r.ok).toBe(true);
    expect(r.code).toBe(VERIFY_EXIT.VALID);
    expect(r.checks.anchored).toBe('pass');
    expect(r.remote?.status).toBe('anchored');
    expect(r.remote?.sequenceNumber).toBe(291848);
  });

  it('tolerates the nulls the pending response carries', async () => {
    const r = await verifyReceipt(fx.LIVE_RECEIPT, {
      fetchImpl: jsonResponse(fx.VERIFY_PENDING),
    });
    // `sequenceNumber: null` and `hcsExplorerUrl: null` must read as absent, not
    // as values, or the receipt would claim a sequence number it does not have.
    expect(r.remote?.sequenceNumber).toBeUndefined();
    expect(r.remote?.verified).toBe(true);
    expect(r.remote?.payloadHashMatch).toBe(true);
  });

  it('does not confuse a missing attestation with a pending one', async () => {
    const r = await verifyReceipt(fx.LIVE_RECEIPT, {
      fetchImpl: jsonResponse({ found: false, id: fx.ATTESTATION_ID }),
    });
    expect(r.code).toBe(VERIFY_EXIT.NOT_ANCHORED);
    expect(r.checks.anchored).toBe('fail');
    expect(r.reason).toMatch(/not known to the verifier/);
  });

  it('still fails a receipt bound to a different payload, pending or not', async () => {
    // The commitment check runs first for exactly this reason: a record still
    // buffering but bound to the wrong payload is tampering, not impatience.
    const bound: Receipt = { ...fx.LIVE_RECEIPT, payloadCommitment: 'a'.repeat(64) };
    const r = await verifyReceipt(bound, { fetchImpl: jsonResponse(fx.VERIFY_PENDING) });
    expect(r.checks.commitment).toBe('fail');
    expect(r.code).toBe(VERIFY_EXIT.PROOF_MISMATCH);
  });
});
