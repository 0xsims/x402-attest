import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { rmSync } from 'node:fs';
import { resolve } from 'node:path';
import { AnchorClient } from '../src/anchor.js';
import { jcs } from '../src/jcs.js';
import { withAttestation } from '../src/index.js';
import { replayWal } from '../src/wal.js';
import { VERIFY_EXIT, verifyReceipt } from '../src/verify.js';
import {
  BATCH_SCHEMA_VERSION,
  isAnchored,
  type BatchEnvelope,
  type FetchLike,
  type Receipt,
} from '../src/types.js';
import { createMockX402Fetch } from './mocks/x402client.js';
import { startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';

/**
 * The keyless anchor commits to more than it was sent.
 *
 * `POST /v1/x402/tiered-attest` does not commit to the client's payload. It wraps
 * it — `data: { ...(req.body.data || {}), x402Payment: {...} }` — and commits to
 * the result. The client cannot reconstruct that member: it never learns the
 * payer address, the atomic amount or the network the server stamped in. So 0.1.3
 * shipped a verifier that recomputed the commitment correctly and got the wrong
 * answer on every keyless receipt, which is exactly what it reported:
 *
 *   commitment  FAIL  (recomputed)
 *   the envelope does not open its commitment: recomputes to 31774630e2…,
 *   receipt records 84728a45a5…
 *
 * The server now returns the injected member alongside the salt, and the receipt
 * records the payload as committed. These tests hold that line at both ends: the
 * recorded envelope must open the commitment, and it must never be the object the
 * root was proven against. See DEVIATIONS §21.
 */
describe('keyless envelope reconstruction', () => {
  let rubric: MockRubric;
  let walPath: string;

  beforeEach(async () => {
    rubric = await startMockRubric();
    walPath = tmpWal('keyless-envelope');
  });

  afterEach(async () => {
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  /**
   * A genuine receipt through the real pipeline, paid for over x402.
   *
   * `anchorFetch` is the raw mock client, never the attested wrapper — wrapping it
   * would attest the attestation.
   */
  async function keylessReceipts(count = 1, path = walPath): Promise<Receipt[]> {
    const upstream: FetchLike = async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const wrapped = withAttestation(upstream, {
      subjectId: 'agent-alpha',
      sessionId: 'keyless-session',
      walPath: path,
      rubricBaseUrl: rubric.url,
      anchorFetch: createMockX402Fetch(fetch),
      installSignalHandlers: false,
    });
    for (let i = 0; i < count; i++) {
      const r = await wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' });
      await r.arrayBuffer();
    }
    await wrapped.flush();
    const out = wrapped.attestor.batcher.allReceipts().filter(isAnchored);
    await wrapped.close();
    return out;
  }

  /** The same receipt over the keyed path, where nothing is injected. */
  async function keyedReceipts(count = 1): Promise<Receipt[]> {
    const upstream: FetchLike = async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const wrapped = withAttestation(upstream, {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });
    for (let i = 0; i < count; i++) {
      const r = await wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' });
      await r.arrayBuffer();
    }
    await wrapped.flush();
    const out = wrapped.attestor.batcher.allReceipts().filter(isAnchored);
    await wrapped.close();
    return out;
  }

  it('records the payload as committed, and it opens the commitment', async () => {
    const [receipt] = await keylessReceipts(3);

    // The member came back and was folded in.
    expect(receipt!.envelope.x402Payment).toEqual({
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amountAtomic: '5000',
      payer: '0x2222222222222222222222222222222222222222',
    });

    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.ok).toBe(true);
    expect(r.code).toBe(VERIFY_EXIT.VALID);
    expect(r.binding).toBe('recomputed');
    expect(r.checks.commitment).toBe('pass');
    // The whole chain, not just the new link.
    expect(r.checks).toEqual({
      leafHash: 'pass',
      proof: 'pass',
      envelopeRoot: 'pass',
      commitment: 'pass',
      anchored: 'pass',
    });
    expect(r.computed.commitment).toBe(receipt!.payloadCommitment);
  });

  it('fails locally when one byte of the injected member is altered', async () => {
    const [receipt] = await keylessReceipts(1);
    const tampered: Receipt = structuredClone(receipt!);
    const payment = tampered.envelope.x402Payment as Record<string, unknown>;
    // Re-point the payment at a different payer. Everything else — leaf, proof,
    // root, recorded commitment — is untouched and still internally consistent.
    payment['payer'] = '0x3333333333333333333333333333333333333333';

    // `offline: true` proves the catch needs no network at all: the receipt no
    // longer opens the commitment it carries, and that is decidable on a laptop.
    const r = await verifyReceipt(tampered, { offline: true });
    expect(r.ok).toBe(false);
    expect(r.code).toBe(VERIFY_EXIT.PROOF_MISMATCH);
    expect(r.checks.commitment).toBe('fail');
    expect(r.reason).toMatch(/does not open its commitment/);
    // The forgery is in the envelope, not the record — the earlier links still hold,
    // which is what makes the commitment check the one that has to catch it.
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
    expect(r.checks.envelopeRoot).toBe('pass');
  });

  it('leaves the keyed path exactly as it was', async () => {
    const [receipt] = await keyedReceipts(1);
    // Nothing is injected on `/v1/tiered-attest`: the commitment covers the bytes
    // that were sent, so folding anything in here would break a working path.
    expect(receipt!.envelope.x402Payment).toBeUndefined();

    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.ok).toBe(true);
    expect(r.binding).toBe('recomputed');
    expect(r.checks.commitment).toBe('pass');
  });

  it('keeps saying FAIL for a real receipt anchored before the member came back', async () => {
    // Live wire data: attestation 43396a10…, anchored over x402 on 2026-08-27 by
    // 0.1.3. The server injected `x402Payment` and committed to it, as it always
    // had, but did not return it — so the receipt carries a salt and a commitment
    // it cannot open. These receipts are genuinely unbindable. The verifier must
    // keep saying so rather than quietly dropping the check when the member is
    // absent, which would turn every one of them into a false pass.
    const receipt = JSON.parse(
      readFileSync(
        resolve(__dirname, 'fixtures', 'live-mainnet', 'keyless-preinjection-receipt.json'),
        'utf8',
      ),
    ) as Receipt;
    expect(receipt.attestationId).toBe('43396a10-548b-43e5-8a87-e2ad8dee1568');
    expect(receipt.envelope.x402Payment).toBeUndefined();
    expect(receipt.commitmentSalt).toBe(
      'd5b041939ea691090938ad6aeca3e5c8c97cb9b7201579b3c7c9eb3ca4b101e6',
    );

    const r = await verifyReceipt(receipt, { offline: true });
    expect(r.ok).toBe(false);
    expect(r.checks.commitment).toBe('fail');
    expect(r.binding).toBe('recomputed');
    // The exact digests from the report that opened this fix.
    expect(r.reason).toMatch(/recomputes to 31774630e2/);
    expect(r.reason).toMatch(/receipt records 84728a45a5/);
    // Everything local still checks out. It is bound to nothing, not forged.
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
    expect(r.checks.envelopeRoot).toBe('pass');
  });

  it('opens the commitment on a real live-mainnet keyless receipt', async () => {
    // The other half of the pair above: a real anchor against the patched server,
    // attestation 61322499…, HCS sequence 292711. Recomputed here from the bytes
    // in the file, offline — a mock cannot manufacture this agreement, because the
    // commitment was issued by the live node before this fixture existed.
    const receipt = JSON.parse(
      readFileSync(
        resolve(__dirname, 'fixtures', 'live-mainnet', 'keyless-bound-receipt.json'),
        'utf8',
      ),
    ) as Receipt;
    expect(receipt.attestationId).toBe('61322499-b5cf-460e-a048-52504ccf2a5e');

    const recomputed = createHash('sha256')
      .update(receipt.commitmentSalt! + jcs(receipt.envelope))
      .digest('hex');
    expect(recomputed).toBe(receipt.payloadCommitment);

    // Offline: pinning a test to a live mainnet GET would fail on a network blip.
    const r = await verifyReceipt(receipt, { offline: true });
    expect(r.ok).toBe(true);
    expect(r.binding).toBe('recomputed');
    expect(r.checks.envelopeRoot).toBe('pass');
  });

  it('leaves the submitted envelope untouched, so a retry re-sends the same bytes', async () => {
    // The recorded envelope is a copy. If the extension were a mutation, the
    // envelope held for retry would carry a member the server injects itself —
    // the batch would be re-submitted as different bytes, and `envelope.root`
    // would be travelling inside a payload that was never the one proven.
    const [receipt] = await keylessReceipts(1);

    const posted = rubric.requests.filter(
      (r) => r.path === '/v1/x402/tiered-attest' && r.body.length > 0,
    );
    for (const req of posted) {
      const sent = (JSON.parse(req.body) as { data: Record<string, unknown> }).data;
      // What went over the wire never contained the member.
      expect(sent['x402Payment']).toBeUndefined();
      expect(sent['root']).toBe(receipt!.root);
    }

    // And the root the proof reaches is still the root the envelope names.
    expect(receipt!.envelope.root).toBe(receipt!.root);
    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.checks.envelopeRoot).toBe('pass');
    expect(r.computed.root).toBe(receipt!.envelope.root);
  });

  it('rebuilds the committed envelope after a restart', async () => {
    const path = tmpWal('keyless-replay');
    try {
      const [original] = await keylessReceipts(2, path);

      // The WAL keeps the two apart: `envelope` is what was submitted, and the
      // injected member sits beside it. A replay that dropped either would rebuild
      // a receipt that cannot open its own commitment.
      const replayed = replayWal(path);
      expect(replayed.anchors).toHaveLength(1);
      const anchor = replayed.anchors[0]!;
      expect((anchor.envelope as Record<string, unknown>)['x402Payment']).toBeUndefined();
      expect(anchor.x402Payment).toEqual(original!.envelope.x402Payment);

      // Recombined, they are the preimage the commitment opens.
      const committed = { ...anchor.envelope, x402Payment: anchor.x402Payment };
      const recomputed = createHash('sha256')
        .update(anchor.commitmentSalt! + jcs(committed))
        .digest('hex');
      expect(recomputed).toBe(anchor.payloadCommitment);

      // Which is what a restarted process actually reconstructs.
      const wrapped = withAttestation(async () => new Response('{}'), {
        subjectId: 'agent-alpha',
        walPath: path,
        rubricBaseUrl: rubric.url,
        anchorFetch: createMockX402Fetch(fetch),
        installSignalHandlers: false,
      });
      const rebuilt = wrapped.attestor.batcher
        .getReceipt(original!.callRecord.callId) as Receipt;
      await wrapped.close();

      expect(rebuilt.envelope.x402Payment).toEqual(original!.envelope.x402Payment);
      expect(rebuilt.envelope.root).toBe(original!.envelope.root);
      expect(jcs(rebuilt.envelope)).toBe(jcs(original!.envelope));

      const r = await verifyReceipt(rebuilt, { fetchImpl: fetch });
      expect(r.ok).toBe(true);
      expect(r.binding).toBe('recomputed');
      expect(r.checks.commitment).toBe('pass');
    } finally {
      rmSync(path, { recursive: true, force: true });
    }
  });
});

describe('AnchorClient — the injected payment member', () => {
  const ENVELOPE: BatchEnvelope = {
    schemaVersion: BATCH_SCHEMA_VERSION,
    leafType: 'DATA_RECORD',
    root: 'a'.repeat(64),
    leafCount: 1,
    firstCallId: 'c1',
    lastCallId: 'c1',
    timeRange: { from: '2026-01-01T00:00:00.000Z', to: '2026-01-01T00:00:01.000Z' },
    subjectId: 's',
    merkle: { hash: 'sha256', leafPrefix: '0x00', nodePrefix: '0x01', oddNode: 'promote' },
  };

  const json = (status: number, body: unknown): Response =>
    new Response(JSON.stringify(body), {
      status,
      headers: { 'content-type': 'application/json' },
    });

  const client = (anchorFetch: FetchLike): AnchorClient =>
    new AnchorClient({
      baseUrl: 'https://rubric-protocol.com',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch,
    });

  it('returns the member verbatim, unknown fields and all', async () => {
    // Passed through untouched because it is part of the canonicalised preimage.
    // Dropping a field this client does not recognise would change what the
    // envelope canonicalises to and break the commitment it exists to open.
    const member = {
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
      amountAtomic: '5000',
      payer: null,
      somethingAddedLater: { nested: [1, 2, 3] },
    };
    const result = await client(async () =>
      json(200, { attestationId: 'att-1', commitmentSalt: 'c'.repeat(64), x402Payment: member }),
    ).anchor(ENVELOPE);

    expect(result.x402Payment).toEqual(member);
  });

  it('accepts the snake_case spelling too', async () => {
    const result = await client(async () =>
      json(200, { attestationId: 'att-2', x402_payment: { payer: '0xabc' } }),
    ).anchor(ENVELOPE);
    expect(result.x402Payment).toEqual({ payer: '0xabc' });
  });

  it('ignores anything that is not an object', async () => {
    // A scalar or an array cannot be a payload member. Folding one in would
    // produce an envelope that opens nothing — a server quirk turned into a
    // tampering accusation, which is the one thing this library must not do.
    for (const bad of ['a string', 42, ['an', 'array'], null]) {
      const result = await client(async () =>
        json(200, { attestationId: 'att-3', x402Payment: bad }),
      ).anchor(ENVELOPE);
      expect(result.x402Payment).toBeUndefined();
    }
  });

  it('is absent when the server sends none', async () => {
    const result = await client(async () => json(200, { attestationId: 'att-4' })).anchor(ENVELOPE);
    expect(result.x402Payment).toBeUndefined();
  });
});
