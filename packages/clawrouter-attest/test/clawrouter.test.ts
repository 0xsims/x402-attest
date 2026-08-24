import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import { createAttestingProxy, withClawRouterAttestation, CLAWROUTER_HEADERS, createRoutingObserver } from '../src/index.js';
import { isAnchored, type AnyReceipt } from '@tempus1/x402-attest';
import { startMockSeller, type MockSeller } from '../../x402-attest/test/mocks/seller.js';
import { startMockRubric, tmpWal, type MockRubric } from '../../x402-attest/test/mocks/rubric.js';
import { createMockX402Fetch } from '../../x402-attest/test/mocks/x402client.js';

/**
 * ClawRouter wiring.
 *
 * The claim being tested is narrow and worth stating plainly: attaching this makes
 * ClawRouter's routing decisions checkable by the buyer. It does not make
 * ClawRouter more or less trustworthy — it removes the need to decide.
 */
describe('ClawRouter attestation', () => {
  let router: MockSeller;
  let rubric: MockRubric;
  let walPath: string;
  const cleanup: (() => Promise<void>)[] = [];

  beforeEach(async () => {
    // Stands in for ClawRouter: an x402 seller that emits x-clawrouter-* headers.
    router = await startMockSeller({ servedModel: 'google/gemini-2.5-flash' });
    rubric = await startMockRubric();
    walPath = tmpWal('clawrouter');
  });

  afterEach(async () => {
    for (const fn of cleanup.splice(0)) await fn();
    await router.close();
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  it('makes a model substitution provable from the buyer side', async () => {
    const receipts: AnyReceipt[] = [];
    const attested = withClawRouterAttestation(createMockX402Fetch(fetch), {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
      onReceipt: (r) => receipts.push(r),
    });
    cleanup.push(() => attested.close().then(() => undefined));

    // Ask for the expensive model; ClawRouter routes to the cheap one.
    await attested(`${router.url}/v1/chat/completions`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model: 'anthropic/claude-sonnet-4.6', messages: [] }),
    });

    const rec = receipts[0]!.callRecord;
    expect(rec.response.headers['x-clawrouter-model']).toBe('google/gemini-2.5-flash');

    const routing = rec.assertions.find((a) => a.id === 'model_matches_request')!;
    expect(routing.result).toBe('fail');
    expect(routing.detail).toContain('x-clawrouter-model');
    expect(rec.outcome).toBe('policy_violation');

    // The substitution is recorded, the call still succeeded, nothing threw. The
    // library records; the buyer decides whether a cheaper model was acceptable.
    expect(rec.response.status).toBe(200);
  });

  it('confirms a match just as verifiably as a mismatch', async () => {
    await router.close();
    router = await startMockSeller({ servedModel: 'anthropic/claude-sonnet-4.6' });

    const receipts: AnyReceipt[] = [];
    const attested = withClawRouterAttestation(createMockX402Fetch(fetch), {
      subjectId: 'agent-alpha',
      walPath,
      mode: 'off',
      installSignalHandlers: false,
      onReceipt: (r) => receipts.push(r),
    });
    cleanup.push(() => attested.close().then(() => undefined));

    await attested(`${router.url}/v1/chat/completions`, {
      method: 'POST',
      body: JSON.stringify({ model: 'anthropic/claude-sonnet-4.6' }),
    });

    expect(
      receipts[0]!.callRecord.assertions.find((a) => a.id === 'model_matches_request')!.result,
    ).toBe('pass');
  });

  it('captures the full routing header set the SDK allowlists by prefix', () => {
    // Documented for the record: all five are covered by the x-clawrouter-* rule.
    expect(CLAWROUTER_HEADERS.every((h) => h.startsWith('x-clawrouter-'))).toBe(true);
  });

  describe('attesting reverse proxy', () => {
    it('forwards faithfully and tags every response with a call id', async () => {
      const proxy = createAttestingProxy({
        listenPort: 0,
        upstream: router.url,
        rubricApiKey: 'test-key',
        rubricBaseUrl: rubric.url,
        walPath,
        subjectId: 'clawrouter-proxy',
        installSignalHandlers: false,
        fetchImpl: createMockX402Fetch(fetch),
      });
      cleanup.push(proxy.close);
      const addr = proxy.server.address();
      const port = typeof addr === 'object' && addr ? addr.port : proxy.port;

      const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ model: 'anthropic/claude-sonnet-4.6', messages: [] }),
      });

      expect(res.status).toBe(200);
      const body = (await res.json()) as { model: string };
      expect(body.model).toBe('google/gemini-2.5-flash');

      // Upstream routing headers survive the extra hop.
      expect(res.headers.get('x-clawrouter-model')).toBe('google/gemini-2.5-flash');

      // The call id is always present: it is the durable handle to the receipt.
      const callId = res.headers.get('x-rubric-call-id');
      expect(callId).toMatch(/^[0-9a-f]{8}-/);

      // Batches anchor on a 60s / 256-leaf schedule, so at response time the
      // receipt is pending and the attestation headers are correctly omitted
      // rather than waited for.
      expect(res.headers.get('x-rubric-attestation-id')).toBeNull();
      expect(res.headers.get('x-rubric-receipt-url')).toBeNull();

      // Once the batch anchors, that same call id resolves to a full receipt.
      await proxy.attestedFetch.flush();
      const receipt = proxy.attestedFetch.getReceipt(callId!);
      expect(receipt).toBeDefined();
      expect(isAnchored(receipt!)).toBe(true);
      expect((receipt as { attestationId: string }).attestationId).toBeTruthy();
    });

    it('answers 502 rather than hanging when the upstream is gone', async () => {
      const proxy = createAttestingProxy({
        listenPort: 0,
        upstream: 'http://127.0.0.1:1',
        walPath,
        mode: 'off',
        subjectId: 'clawrouter-proxy',
        installSignalHandlers: false,
      });
      cleanup.push(proxy.close);
      const addr = proxy.server.address();
      const port = typeof addr === 'object' && addr ? addr.port : proxy.port;

      const res = await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, {
        method: 'POST',
        body: '{}',
      });
      expect(res.status).toBe(502);

      // The failed call is still attested: an outage the buyer paid for is
      // exactly the kind of thing an audit trail should contain.
      const leaves = proxy.attestedFetch.attestor.batcher.allReceipts();
      expect(leaves).toHaveLength(1);
      expect(leaves[0]!.callRecord.outcome).toBe('http_error');
    });
  });

  it('collects routing callbacks as context without inventing correlations', () => {
    const obs = createRoutingObserver();
    obs.onRouted({ tier: 'SIMPLE', model: 'gemini' });
    obs.onPayment({ amount: '1000' });
    expect(obs.events.map((e) => e.kind)).toEqual(['routed', 'payment']);
    expect(obs.events[0]!.at).toMatch(/^\d{4}-/);
  });
});
