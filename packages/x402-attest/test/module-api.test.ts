import { afterEach, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import {
  close,
  exportReceipts,
  flush,
  getReceipt,
  withAttestation,
  DEFAULT_RUBRIC_BASE_URL,
} from '../src/index.js';
import type { FetchLike } from '../src/types.js';
import { startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';

/**
 * The module-level helpers act across every attestor in the process.
 *
 * They exist for shutdown hooks and instrumentation that do not hold a reference
 * to the wrapper — a `process.on('beforeExit')` in an entrypoint that never saw
 * the object the SDK returned.
 */
describe('module-level API', () => {
  const wals: string[] = [];
  let rubric: MockRubric | undefined;

  afterEach(async () => {
    await close();
    await rubric?.close();
    rubric = undefined;
    for (const w of wals.splice(0)) rmSync(w, { recursive: true, force: true });
  });

  const upstream: FetchLike = async () =>
    new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });

  it('flushes, reads and exports across every live attestor', async () => {
    rubric = await startMockRubric();
    const walA = tmpWal('mod-a');
    const walB = tmpWal('mod-b');
    wals.push(walA, walB);

    const a = withAttestation(upstream, {
      rubricApiKey: 'k',
      subjectId: 'agent-a',
      walPath: walA,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });
    const b = withAttestation(upstream, {
      rubricApiKey: 'k',
      subjectId: 'agent-b',
      walPath: walB,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });

    await (await a('https://s.example/a', { method: 'POST', body: '{}' })).arrayBuffer();
    await (await b('https://s.example/b', { method: 'POST', body: '{}' })).arrayBuffer();

    // One flush call drains both.
    const results = await flush();
    expect(results.filter((r) => r.status === 'anchored')).toHaveLength(2);

    const idA = a.attestor.batcher.allReceipts()[0]!.callRecord.callId;
    expect(getReceipt(idA)?.callRecord.subjectId).toBe('agent-a');
    expect(getReceipt('no-such-call')).toBeUndefined();

    const jsonl = exportReceipts();
    expect(jsonl.trim().split('\n')).toHaveLength(2);

    const csv = exportReceipts({ format: 'csv' });
    expect(csv.split('\n')[0]).toContain('assert.settled');
    expect(csv).toContain('agent-a');
    expect(csv).toContain('agent-b');

    // close() is idempotent and deregisters, so a second call is a no-op.
    expect((await close()).length).toBeGreaterThanOrEqual(0);
    expect(await close()).toEqual([]);
    expect(exportReceipts()).toBe('');
  });

  it('requires a subjectId, because an audit record needs a subject', () => {
    expect(() => withAttestation(upstream, {} as never)).toThrow(/subjectId/);
  });

  it('defaults to the public Rubric base URL', () => {
    expect(DEFAULT_RUBRIC_BASE_URL).toBe('https://rubric-protocol.com');
  });

  it('attaches the instance API to the returned function without changing its shape', async () => {
    const wal = tmpWal('mod-shape');
    wals.push(wal);
    const wrapped = withAttestation(upstream, {
      subjectId: 'agent-shape',
      walPath: wal,
      mode: 'off',
      installSignalHandlers: false,
    });

    expect(typeof wrapped).toBe('function');
    // Same call signature as fetch: (input, init).
    expect(wrapped.length).toBe(2);
    for (const k of ['flush', 'close', 'getReceipt', 'exportReceipts', 'attestor']) {
      expect(k in wrapped).toBe(true);
      // Non-enumerable, so the wrapper still looks like a plain fetch to anything
      // that iterates its own properties.
      expect(Object.keys(wrapped)).not.toContain(k);
    }
    await wrapped.close();
  });
});

describe('signal handling', () => {
  const wals: string[] = [];
  afterEach(async () => {
    await close();
    for (const w of wals.splice(0)) rmSync(w, { recursive: true, force: true });
  });

  const upstream: FetchLike = async () => new Response('{}', { status: 200 });

  it('installs one drain handler per process, not one per attestor', async () => {
    const before = {
      SIGINT: process.listenerCount('SIGINT'),
      SIGTERM: process.listenerCount('SIGTERM'),
    };

    const made = ['s1', 's2', 's3'].map((id) => {
      const wal = tmpWal(`sig-${id}`);
      wals.push(wal);
      return withAttestation(upstream, {
        subjectId: id,
        walPath: wal,
        mode: 'off',
        installSignalHandlers: true,
      });
    });

    // Three attestors, still one handler each: per-attestor handlers would each
    // re-raise the signal, delivering it to the process three times.
    expect(process.listenerCount('SIGINT')).toBe(before.SIGINT + 1);
    expect(process.listenerCount('SIGTERM')).toBe(before.SIGTERM + 1);

    for (const m of made) await m.close();

    // Removed once the last attestor closes: no listener leak.
    expect(process.listenerCount('SIGINT')).toBe(before.SIGINT);
    expect(process.listenerCount('SIGTERM')).toBe(before.SIGTERM);
  });

  it('installs nothing when asked not to', async () => {
    const before = process.listenerCount('SIGTERM');
    const wal = tmpWal('sig-off');
    wals.push(wal);
    const w = withAttestation(upstream, {
      subjectId: 'no-signals',
      walPath: wal,
      mode: 'off',
      installSignalHandlers: false,
    });
    expect(process.listenerCount('SIGTERM')).toBe(before);
    await w.close();
  });
});

describe('capture policy', () => {
  const wals: string[] = [];
  afterEach(async () => {
    await close();
    for (const w of wals.splice(0)) rmSync(w, { recursive: true, force: true });
  });

  it('honours an explicit passthrough override on a non-SSE response', async () => {
    const wal = tmpWal('capture');
    wals.push(wal);
    const receipts: { bodyBytes: number }[] = [];
    const w = withAttestation(
      async () =>
        new Response('plain body bytes', {
          status: 200,
          headers: { 'content-type': 'text/plain' },
        }),
      {
        subjectId: 'capture-agent',
        walPath: wal,
        mode: 'off',
        installSignalHandlers: false,
        capture: { stream: 'passthrough' },
        onReceipt: (r) => receipts.push({ bodyBytes: r.callRecord.response.bodyBytes }),
      },
    );

    const res = await w('https://s.example/x');
    expect(await res.text()).toBe('plain body bytes');
    const deadline = Date.now() + 5000;
    while (Date.now() < deadline && receipts.length === 0) {
      await new Promise((r) => setTimeout(r, 5));
    }
    expect(receipts[0]!.bodyBytes).toBe('plain body bytes'.length);
    await w.close();
  });
});
