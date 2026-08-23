import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import { createTap, withAttestation } from '../src/index.js';
import { verifyReceipt } from '../src/verify.js';
import { replayWal } from '../src/wal.js';
import { isAnchored, type AnyReceipt, type Receipt } from '../src/types.js';
import { startMockSeller, type MockSeller } from './mocks/seller.js';
import { startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';
import { createMockX402Fetch } from './mocks/x402client.js';

const PAYEE = '0x1111111111111111111111111111111111111111';

/**
 * Poll until a condition holds.
 *
 * Anchoring is deliberately detached from the request path, so tests that assert
 * on it are asserting about work with no handle to await. A fixed sleep either
 * flakes under load or wastes time; polling does neither.
 */
async function waitFor(
  predicate: () => boolean,
  label: string,
  timeoutMs = 5000,
): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise((r) => setTimeout(r, 5));
  }
  throw new Error(`timed out after ${timeoutMs}ms waiting for: ${label}`);
}

describe('end-to-end: paid call to verified receipt', () => {
  let seller: MockSeller;
  let rubric: MockRubric;
  let walPath: string;
  const cleanup: (() => Promise<void>)[] = [];

  beforeEach(async () => {
    seller = await startMockSeller();
    rubric = await startMockRubric();
    walPath = tmpWal('e2e');
  });

  afterEach(async () => {
    for (const fn of cleanup.splice(0)) await fn();
    await seller.close();
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  function build(over: Record<string, unknown> = {}, sellerOpts = {}) {
    const tap = createTap();
    const receipts: AnyReceipt[] = [];
    const x402 = createMockX402Fetch(tap.wrapFetch(fetch), sellerOpts);
    const fetchAndPay = withAttestation(x402, {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      policyId: 'trading-desk-v2',
      sessionId: 'run-2026-08-23-01',
      mode: 'batch',
      batch: { maxLeaves: 256, maxAgeMs: 60_000 },
      policy: {
        maxPricePerCall: '0.05',
        allowedNetworks: ['eip155:8453'],
        allowedPayTo: [PAYEE],
        budgetCap: '25.00',
      },
      walPath,
      rubricBaseUrl: rubric.url,
      tap,
      installSignalHandlers: false,
      onReceipt: (r) => receipts.push(r),
      ...over,
    });
    cleanup.push(() => fetchAndPay.close().then(() => undefined));
    return { fetchAndPay, receipts, tap };
  }

  it('observes the full 402 handshake and records every field', async () => {
    const { fetchAndPay, receipts } = build();

    const res = await fetchAndPay(`${seller.url}/paid?token=secret-query-value`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      // No `model` field: this test is about the payment handshake. Model
      // substitution has its own test, and asking for one model while the mock
      // serves another would correctly trip a policy violation here.
      body: JSON.stringify({ prompt: 'hello' }),
    });

    // The caller's response is intact — body readable, status and headers preserved.
    expect(res.status).toBe(200);
    const body = (await res.json()) as { model: string };
    expect(body.model).toBe('mock-model');

    expect(receipts).toHaveLength(1);
    const rec = receipts[0]!.callRecord;

    expect(rec.v).toBe(1);
    expect(rec.callId).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-/);
    expect(rec.subjectId).toBe('agent-alpha');
    expect(rec.policyId).toBe('trading-desk-v2');
    expect(rec.sessionId).toBe('run-2026-08-23-01');
    expect(rec.durationMs).toBeGreaterThanOrEqual(0);

    expect(rec.request.method).toBe('POST');
    expect(rec.request.path).toBe('/paid');
    // The query string is hashed, never stored: it can carry credentials.
    expect(rec.request.queryHash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(JSON.stringify(rec)).not.toContain('secret-query-value');

    expect(rec.challenge).toBeDefined();
    expect(rec.challenge!.maxAmountRequired).toBe('1000');
    expect(rec.challenge!.payTo).toBe(PAYEE);
    expect(rec.challenge!.network).toBe('eip155:8453');
    expect(rec.challenge!.rawHash).toMatch(/^[0-9a-f]{64}$/);

    expect(rec.payment).toBeDefined();
    expect(rec.payment!.amountAuthorized).toBe('1000');
    expect(rec.payment!.payTo).toBe(PAYEE);
    // Only the hash of the authorization header, never the header.
    expect(rec.payment!.xPaymentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rec)).not.toContain(seller.received[0]!);

    expect(rec.settlement!.success).toBe(true);
    expect(rec.settlement!.source).toBe('x-payment-response');
    expect(rec.settlement!.txHash).toMatch(/^0x[0-9a-f]+$/);

    expect(rec.outcome).toBe('ok');
    // The seller echoed a model but none was requested: unknown, never pass.
    expect(rec.assertions.find((a) => a.id === 'model_matches_request')!.result).toBe(
      'unknown',
    );
  });

  it('applies the response header allowlist and drops everything else', async () => {
    const { fetchAndPay, receipts } = build();
    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });

    const headers = receipts[0]!.callRecord.response.headers;
    expect(Object.keys(headers).sort()).toEqual([
      'content-type',
      'payment-response',
      'x-request-id',
    ]);
    // The seller deliberately sends these; capturing them would put a session
    // cookie and a bearer token into an append-only audit log forever.
    expect(headers['set-cookie']).toBeUndefined();
    expect(headers['authorization']).toBeUndefined();
    expect(JSON.stringify(receipts[0])).not.toContain('super-secret-cookie');
    expect(JSON.stringify(receipts[0])).not.toContain('leaked-token');
  });

  it('captures x-clawrouter-* routing headers, which the allowlist covers by prefix', async () => {
    await seller.close();
    seller = await startMockSeller({ servedModel: 'google/gemini-2.5-flash' });
    const { fetchAndPay, receipts } = build();

    await fetchAndPay(`${seller.url}/v1/chat/completions`, {
      method: 'POST',
      body: JSON.stringify({ model: 'anthropic/claude-sonnet-4.6' }),
    });

    const rec = receipts[0]!.callRecord;
    expect(rec.response.headers['x-clawrouter-model']).toBe('google/gemini-2.5-flash');

    // Proof of routing: the router served something other than what was asked for.
    const model = rec.assertions.find((a) => a.id === 'model_matches_request')!;
    expect(model.result).toBe('fail');
    expect(rec.outcome).toBe('policy_violation');
  });

  it('anchors a batch and produces a receipt that verifies end to end', async () => {
    const { fetchAndPay, receipts } = build();

    for (let i = 0; i < 3; i++) {
      await fetchAndPay(`${seller.url}/paid/${i}`, { method: 'POST', body: '{}' });
    }
    const results = await fetchAndPay.flush();

    expect(results[0]!.status).toBe('anchored');
    expect(results[0]!.leafCount).toBe(3);

    const anchored = receipts.filter(isAnchored);
    expect(anchored).toHaveLength(3);

    for (const receipt of anchored) {
      expect(receipt.attestationId).toBeTruthy();
      expect(receipt.root).toMatch(/^[0-9a-f]{64}$/);
      expect(receipt.verifyUrl).toContain('/v1/verify/');

      const result = await verifyReceipt(receipt, { fetchImpl: fetch });
      expect(result.ok).toBe(true);
      expect(result.code).toBe(0);
      expect(result.checks).toEqual({
        leafHash: 'pass',
        proof: 'pass',
        envelopeRoot: 'pass',
        commitment: 'pass',
        anchored: 'pass',
      });
      // Rubric never echoes the payload back, so the envelope-to-anchor link is
      // matched by the commitment the receipt recorded, not recomputed here.
      expect(result.binding).toBe('recorded');
      expect(result.remote?.commitment).toBe(receipt.payloadCommitment);

      // The receipt carries the payload that was actually submitted.
      expect(receipt.envelope.root).toBe(receipt.root);
      expect(receipt.envelope.leafCount).toBe(3);
    }

    // One attestation for three calls. That is the economics of the whole design.
    const attestCalls = rubric.requests.filter((r) => r.path === '/v1/tiered-attest');
    expect(attestCalls).toHaveLength(1);
  });

  it('sends one attestation per batch containing the root and batch metadata only', async () => {
    const { fetchAndPay } = build();
    await fetchAndPay(`${seller.url}/a`, { method: 'POST', body: '{}' });
    await fetchAndPay(`${seller.url}/b`, { method: 'POST', body: '{}' });
    await fetchAndPay.flush();

    const req = rubric.requests.find((r) => r.path === '/v1/tiered-attest')!;
    expect(req.headers['x-api-key']).toBe('test-key');

    const sent = JSON.parse(req.body) as { sourceId: string; data: Record<string, unknown> };
    expect(sent.sourceId).toBe('agent-alpha');
    expect(sent.data['schemaVersion']).toBe('rubric.x402-attest/v1');
    expect(sent.data['leafType']).toBe('DATA_RECORD');
    expect(sent.data['leafCount']).toBe(2);
    expect(sent.data['subjectId']).toBe('agent-alpha');
    expect(sent.data['policyId']).toBe('trading-desk-v2');
    expect(sent.data['root']).toMatch(/^[0-9a-f]{64}$/);
    expect(sent.data['firstCallId']).toBeTruthy();
    expect(sent.data['lastCallId']).toBeTruthy();
    expect(sent.data['timeRange']).toHaveProperty('from');
    // The Merkle construction travels with the root so a verifier never has to
    // guess how the tree was built.
    expect(sent.data['merkle']).toEqual({
      hash: 'sha256',
      leafPrefix: '0x00',
      nodePrefix: '0x01',
      oddNode: 'promote',
    });
  });

  it('keeps the tiered payload key out of receipts and in a separate file', async () => {
    const { fetchAndPay, receipts } = build();
    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });
    await fetchAndPay.flush();

    // The key is an AES decryption credential, not evidence.
    expect(JSON.stringify(receipts)).not.toContain('a'.repeat(64));
    const keyFile = replayWal(walPath);
    expect(keyFile.leaves).toHaveLength(1);
    expect(JSON.stringify(keyFile.leaves)).not.toContain('a'.repeat(64));
  });

  it('anchors over x402 itself when no API key is present — the keyless path', async () => {
    // The attestation is bought exactly the way the calls it attests were bought.
    // anchorFetch is the RAW x402 client, never the attested wrapper: wrapping it
    // would attest the attestation, which would need its own attestation.
    const anchorFetch = createMockX402Fetch(fetch);
    const { fetchAndPay, receipts } = build({
      rubricApiKey: undefined,
      anchorFetch,
    });

    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });
    const results = await fetchAndPay.flush();

    expect(results[0]!.status).toBe('anchored');

    const paid = rubric.requests.filter((r) => r.path === '/v1/x402/tiered-attest');
    // Two requests: the 402 challenge, then the paid retry.
    expect(paid).toHaveLength(2);
    expect(paid[0]!.headers['payment-signature']).toBeUndefined();
    expect(paid[1]!.headers['payment-signature']).toBeTruthy();
    expect(paid[1]!.headers['x-api-key']).toBeUndefined();

    const receipt = receipts.filter(isAnchored)[0]!;
    const result = await verifyReceipt(receipt, { fetchImpl: fetch });
    expect(result.ok).toBe(true);
  });

  it('mode "off" writes the WAL and never touches the network', async () => {
    const { fetchAndPay, receipts } = build({ mode: 'off' });
    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });
    const results = await fetchAndPay.flush();

    expect(results[0]!.status).toBe('skipped');
    expect(rubric.requests).toHaveLength(0);
    expect(receipts[0]!.attestationId).toBeNull();
    expect(replayWal(walPath).leaves).toHaveLength(1);
  });

  it('mode "immediate" anchors each call on its own', async () => {
    const { fetchAndPay } = build({ mode: 'immediate' });
    await fetchAndPay(`${seller.url}/a`, { method: 'POST', body: '{}' });
    await fetchAndPay(`${seller.url}/b`, { method: 'POST', body: '{}' });
    await fetchAndPay.flush();
    expect(rubric.requests.filter((r) => r.path === '/v1/tiered-attest')).toHaveLength(2);
  });

  it('flushes automatically once maxLeaves is reached', async () => {
    const { fetchAndPay } = build({ batch: { maxLeaves: 3, maxAgeMs: 60_000 } });
    for (let i = 0; i < 3; i++) {
      await fetchAndPay(`${seller.url}/${i}`, { method: 'POST', body: '{}' });
    }
    await waitFor(
      () => rubric.requests.some((r) => r.path === '/v1/tiered-attest'),
      'the leaf-count trigger to fire a flush',
    );
    expect(rubric.requests.filter((r) => r.path === '/v1/tiered-attest')).toHaveLength(1);
  });

  it('flushes automatically once maxAgeMs elapses', async () => {
    const { fetchAndPay } = build({ batch: { maxLeaves: 999, maxAgeMs: 60 } });
    await fetchAndPay(`${seller.url}/a`, { method: 'POST', body: '{}' });
    // Nothing yet: the leaf count is far below the threshold.
    expect(rubric.requests.filter((r) => r.path === '/v1/tiered-attest')).toHaveLength(0);
    await waitFor(
      () => rubric.requests.some((r) => r.path === '/v1/tiered-attest'),
      'the age trigger to fire a flush',
    );
    expect(rubric.requests.filter((r) => r.path === '/v1/tiered-attest')).toHaveLength(1);
  });

  describe('failures are attested, not swallowed', () => {
    it('records a refused payment as payment_failed and still returns the 402', async () => {
      await seller.close();
      seller = await startMockSeller({ maxAmountRequired: '9999999' });
      // The client refuses to authorize above its ceiling, so the 402 stands.
      const { fetchAndPay, receipts } = build({}, { maxAtomic: 5000n });

      const res = await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });
      expect(res.status).toBe(402);

      const rec = receipts[0]!.callRecord;
      expect(rec.outcome).toBe('policy_violation');
      expect(rec.challenge).toBeDefined();
      expect(rec.payment).toBeUndefined();
      // The most valuable record: we saw the price, we declined, and here is proof.
      expect(rec.assertions.find((a) => a.id === 'price_within_policy')!.result).toBe('fail');
      expect(rec.assertions.find((a) => a.id === 'settled')!.result).toBe('unknown');
    });

    it('records a transport failure and rethrows to the caller unchanged', async () => {
      const boom = new Error('ECONNREFUSED');
      const { fetchAndPay, receipts } = build({
        tap: undefined,
      });
      const failing = withAttestation(
        async () => {
          throw boom;
        },
        {
          subjectId: 'agent-alpha',
          walPath,
          mode: 'off',
          installSignalHandlers: false,
          onReceipt: (r) => receipts.push(r),
        },
      );
      cleanup.push(() => failing.close().then(() => undefined));

      await expect(failing('http://127.0.0.1:1/x')).rejects.toBe(boom);
      const rec = receipts.at(-1)!.callRecord;
      expect(rec.outcome).toBe('http_error');
      expect(rec.response.status).toBe(0);
      void fetchAndPay;
    });

    it('records a settlement that the facilitator reported as failed', async () => {
      await seller.close();
      seller = await startMockSeller({ settlementFails: true });
      const { fetchAndPay, receipts } = build();
      await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });

      const rec = receipts[0]!.callRecord;
      expect(rec.settlement!.success).toBe(false);
      expect(rec.assertions.find((a) => a.id === 'settled')!.result).toBe('fail');
      expect(rec.outcome).toBe('policy_violation');
    });

    it('never throws for attestation reasons — a policy violation still returns 200', async () => {
      await seller.close();
      seller = await startMockSeller({ payTo: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' });
      const { fetchAndPay, receipts } = build();

      const res = await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });
      expect(res.status).toBe(200);
      expect(await res.json()).toHaveProperty('model');

      expect(receipts[0]!.callRecord.outcome).toBe('policy_violation');
      expect(receipts[0]!.callRecord.assertions.find((a) => a.id === 'payto_allowed')!.result).toBe(
        'fail',
      );
    });
  });

  it('degrades to unknown assertions, not wrong ones, without a tap', async () => {
    const { fetchAndPay, receipts } = build({ tap: undefined });
    const plain = withAttestation(createMockX402Fetch(fetch), {
      subjectId: 'agent-alpha',
      walPath,
      mode: 'off',
      installSignalHandlers: false,
      policy: { allowedNetworks: ['eip155:8453'] },
      onReceipt: (r) => receipts.push(r),
    });
    cleanup.push(() => plain.close().then(() => undefined));

    await plain(`${seller.url}/paid`, { method: 'POST', body: '{}' });
    const rec = receipts.at(-1)!.callRecord;

    // Without the tap the handshake happened inside the x402 client, so the
    // challenge and payment were never visible. Those checks report unknown.
    expect(rec.payment).toBeUndefined();
    expect(rec.assertions.find((a) => a.id === 'price_matches_challenge')!.result).toBe('unknown');
    expect(rec.assertions.find((a) => a.id === 'payto_matches_challenge')!.result).toBe('unknown');
    // The settlement header is on the final response, so this one still works.
    expect(rec.assertions.find((a) => a.id === 'settled')!.result).toBe('pass');
    void fetchAndPay;
  });

  it('tracks cumulative session spend across calls', async () => {
    const { fetchAndPay } = build();
    for (let i = 0; i < 4; i++) {
      await fetchAndPay(`${seller.url}/${i}`, { method: 'POST', body: '{}' });
    }
    // 4 calls at 1000 atomic USDC each.
    expect(fetchAndPay.attestor.spendUsd).toBe('0.004000');
  });

  it('exposes receipts by call id and exports them for audit', async () => {
    const { fetchAndPay, receipts } = build();
    await fetchAndPay(`${seller.url}/a`, { method: 'POST', body: '{}' });
    await fetchAndPay(`${seller.url}/b`, { method: 'POST', body: '{}' });
    await fetchAndPay.flush();

    const callId = receipts[0]!.callRecord.callId;
    const fetched = fetchAndPay.getReceipt(callId) as Receipt;
    expect(fetched.callRecord.callId).toBe(callId);
    expect(isAnchored(fetched)).toBe(true);

    const jsonl = fetchAndPay.exportReceipts({ format: 'jsonl' });
    expect(jsonl.trim().split('\n')).toHaveLength(2);

    const csv = fetchAndPay.exportReceipts({ format: 'csv' });
    const [header, ...rows] = csv.trim().split('\n');
    expect(header).toContain('assert.price_matches_challenge');
    expect(header).toContain('assert.model_matches_request');
    expect(header).toContain('attestationId');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toContain('anchored');
  });

  it('buffers and reconstructs the response without altering it', async () => {
    const payload = { data: 'x'.repeat(50_000), nested: { arr: [1, 2, 3] } };
    await seller.close();
    seller = await startMockSeller({ responseBody: payload });
    const { fetchAndPay, receipts } = build();

    const res = await fetchAndPay(`${seller.url}/big`, { method: 'POST', body: '{}' });
    expect(await res.json()).toEqual(payload);
    expect(receipts[0]!.callRecord.response.bodyBytes).toBe(
      Buffer.byteLength(JSON.stringify(payload)),
    );
  });

  it('streams SSE straight through and attests when the stream ends', async () => {
    await seller.close();
    seller = await startMockSeller({ stream: true, servedModel: 'mock-model' });
    const { fetchAndPay, receipts } = build();

    const res = await fetchAndPay(`${seller.url}/stream`, { method: 'POST', body: '{}' });
    expect(res.headers.get('content-type')).toBe('text/event-stream');

    const text = await res.text();
    expect(text).toContain('[DONE]');

    // The leaf is written when the stream completes, not before.
    await waitFor(() => receipts.length > 0, 'the stream leaf to be committed');
    expect(receipts).toHaveLength(1);
    expect(receipts[0]!.callRecord.response.bodyBytes).toBe(Buffer.byteLength(text));
  });
});
