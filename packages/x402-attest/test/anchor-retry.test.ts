import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import { withAttestation } from '../src/index.js';
import { backoffDelay, AnchorError } from '../src/anchor.js';
import { replayWal } from '../src/wal.js';
import { isAnchored } from '../src/types.js';
import type { AnyReceipt, FetchLike } from '../src/types.js';
import { startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';

/**
 * Rubric being unreachable must never cost a leaf and must never cost a call.
 *
 * This is the failure mode that decides whether the library is safe to put in
 * front of production traffic: an attestation backend having a bad day cannot be
 * allowed to become the buyer's outage.
 */

const upstream: FetchLike = async () =>
  new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: { 'content-type': 'application/json' },
  });

describe('anchoring under failure', () => {
  let rubric: MockRubric;
  let walPath: string;

  beforeEach(async () => {
    rubric = await startMockRubric();
    walPath = tmpWal('retry');
  });

  afterEach(async () => {
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  function build(over: Record<string, unknown> = {}) {
    const receipts: AnyReceipt[] = [];
    const errors: { message: string; attempt: number }[] = [];
    const wrapped = withAttestation(upstream, {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      walPath,
      rubricBaseUrl: rubric.url,
      mode: 'batch',
      installSignalHandlers: false,
      retry: { minDelayMs: 20, maxDelayMs: 80 },
      onReceipt: (r) => receipts.push(r),
      onAnchorError: (e, attempt) => errors.push({ message: e.message, attempt }),
      ...over,
    });
    return { wrapped, receipts, errors };
  }

  it('keeps serving calls and queues leaves while Rubric is down', async () => {
    rubric.options.down = true;
    const { wrapped, receipts, errors } = build();

    for (let i = 0; i < 5; i++) {
      const res = await wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' });
      // The call succeeded. That is the non-negotiable part.
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ ok: true });
    }

    const results = await wrapped.flush();
    expect(results[0]!.status).toBe('retrying');
    expect(results[0]!.leafCount).toBe(5);
    expect(errors.length).toBeGreaterThan(0);
    expect(errors[0]!.message).toMatch(/HTTP 503/);

    // Every leaf is durable and every receipt exists, just not yet anchored.
    expect(receipts).toHaveLength(5);
    expect(receipts.every((r) => !isAnchored(r))).toBe(true);
    expect(replayWal(walPath).leaves).toHaveLength(5);
    expect(replayWal(walPath).unanchored).toHaveLength(5);

    await wrapped.close();
  });

  it('engages backoff and anchors on recovery, losing nothing', async () => {
    // Fail the first two attempts, then start working.
    rubric.options.failFirst = 2;
    const { wrapped, receipts, errors } = build();

    for (let i = 0; i < 3; i++) {
      await wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' });
    }

    const first = await wrapped.flush();
    expect(first[0]!.status).toBe('retrying');
    expect(errors).toHaveLength(1);

    // Poll rather than sleep: the backoff is jittered by design, so any fixed
    // wait is either flaky or wasteful.
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && receipts.filter(isAnchored).length < 3) {
      await new Promise((r) => setTimeout(r, 5));
    }

    const anchored = receipts.filter(isAnchored);
    expect(anchored).toHaveLength(3);
    // One root for all three, and every leaf carries a proof against it.
    expect(new Set(anchored.map((r) => r.root)).size).toBe(1);
    for (const r of anchored) expect(r.attestationId).toBeTruthy();

    // The WAL now records the anchor, so a restart will not re-anchor them.
    const replay = replayWal(walPath);
    expect(replay.anchors).toHaveLength(1);
    expect(replay.unanchored).toHaveLength(0);

    await wrapped.close();
  });

  it('retries indefinitely rather than dropping a leaf on a permanent error', async () => {
    // 401 will never succeed on retry, but the leaves still must not be lost.
    const { wrapped } = build({ rubricApiKey: undefined, anchorFetch: undefined });

    await wrapped('https://seller.example/x', { method: 'POST', body: '{}' });
    const results = await wrapped.flush();

    expect(results[0]!.status).toBe('retrying');
    expect(results[0]!.error).toMatch(/keyless anchoring needs/);
    expect(wrapped.attestor.batcher.pendingAnchorCount).toBe(1);
    expect(replayWal(walPath).unanchored).toHaveLength(1);

    await wrapped.close();
  });

  it('recovers unanchored leaves from the WAL when a new process starts', async () => {
    rubric.options.down = true;
    const first = build();
    for (let i = 0; i < 4; i++) {
      await first.wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' });
    }
    await first.wrapped.flush();
    await first.wrapped.close();
    expect(replayWal(walPath).unanchored).toHaveLength(4);

    // A new attestor over the same WAL directory: the outage is over.
    rubric.options.down = false;
    const second = build();
    expect(second.wrapped.attestor.recovered.leaves).toBe(4);

    const results = await second.wrapped.flush();
    expect(results[0]!.status).toBe('anchored');
    expect(results[0]!.leafCount).toBe(4);
    expect(replayWal(walPath).unanchored).toHaveLength(0);

    await second.wrapped.close();
  });

  it('does not let a throwing onReceipt callback break anchoring', async () => {
    const { wrapped } = build({
      onReceipt: () => {
        throw new Error('caller bug');
      },
    });
    await wrapped('https://seller.example/x', { method: 'POST', body: '{}' });
    const results = await wrapped.flush();
    expect(results[0]!.status).toBe('anchored');
    await wrapped.close();
  });

  it('surfaces a Rubric response with no attestationId as an error, not a fake receipt', async () => {
    const lying: FetchLike = async () =>
      new Response(JSON.stringify({ status: 'buffered' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const { wrapped, errors, receipts } = build({ httpFetch: lying });

    await wrapped('https://seller.example/x', { method: 'POST', body: '{}' });
    const results = await wrapped.flush();

    expect(results[0]!.status).toBe('retrying');
    expect(errors[0]!.message).toMatch(/no attestationId/);
    // Better a pending receipt than one claiming an anchor that does not exist.
    expect(receipts.every((r) => !isAnchored(r))).toBe(true);
    await wrapped.close();
  });
});

describe('backoff', () => {
  it('grows exponentially from the floor to the ceiling', () => {
    const noJitter = () => 1;
    expect(backoffDelay(1, 1000, 60_000, noJitter)).toBe(1000);
    expect(backoffDelay(2, 1000, 60_000, noJitter)).toBe(2000);
    expect(backoffDelay(3, 1000, 60_000, noJitter)).toBe(4000);
    expect(backoffDelay(7, 1000, 60_000, noJitter)).toBe(60_000);
    expect(backoffDelay(50, 1000, 60_000, noJitter)).toBe(60_000);
  });

  it('applies full jitter so a fleet does not retry in lockstep', () => {
    // Without jitter, every agent that saw the same outage retries at the same
    // instant and re-creates the thundering herd that took Rubric down.
    const low = backoffDelay(4, 1000, 60_000, () => 0);
    const high = backoffDelay(4, 1000, 60_000, () => 0.999);
    expect(low).toBe(4000);
    expect(high).toBeGreaterThan(7900);
    expect(high).toBeLessThanOrEqual(8000);

    const samples = new Set(
      Array.from({ length: 50 }, () => backoffDelay(5, 1000, 60_000)),
    );
    expect(samples.size).toBeGreaterThan(10);
  });
});

describe('AnchorError', () => {
  it('defaults to retryable, because dropping evidence is worse than a wasted call', () => {
    expect(new AnchorError('x').retryable).toBe(true);
    expect(new AnchorError('x', { retryable: false }).retryable).toBe(false);
  });
});
