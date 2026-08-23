import { afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { appendFileSync, existsSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { spawn } from 'node:child_process';
import { join, resolve } from 'node:path';
import { Wal, replayWal } from '../src/wal.js';
import { withAttestation } from '../src/index.js';
import { sha256Jcs } from '../src/hash.js';
import { isAnchored } from '../src/types.js';
import type { AnyReceipt, FetchLike } from '../src/types.js';
import { startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';

const PKG = resolve(__dirname, '..');
const DIST = join(PKG, 'dist', 'index.js');
const CHILD = join(PKG, 'test', 'fixtures', 'crash-child.mjs');

/**
 * A crash must not lose evidence.
 *
 * The strong form of the claim: SIGKILL the process mid-batch — no unwinding, no
 * handlers, no flush — restart, and every call that returned to its caller is
 * still on disk and still anchorable.
 */
function crashAfter(count: number, walPath: string, fsync = 'always'): Promise<number> {
  return new Promise((resolveP, rejectP) => {
    const child = spawn(process.execPath, [CHILD, DIST, walPath, String(count), fsync], {
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += String(d)));
    child.stderr.on('data', (d) => (err += String(d)));
    child.on('error', rejectP);
    child.on('close', (code, signal) => {
      if (!out.includes('WROTE')) {
        rejectP(new Error(`child never finished writing (code=${code} signal=${signal}): ${err}`));
        return;
      }
      // Killed by signal, not a clean exit: nothing ran on the way out.
      expect(signal).toBe('SIGKILL');
      resolveP(count);
    });
  });
}

describe('crash recovery', () => {
  let walPath: string;
  let rubric: MockRubric;

  beforeAll(() => {
    // The child runs the built output, so make sure it exists even when this file
    // is run on its own rather than via `npm test`.
    if (!existsSync(DIST)) {
      execFileSync('npx', ['tsc', '-b', 'packages/x402-attest'], {
        cwd: resolve(PKG, '..', '..'),
        stdio: 'inherit',
      });
    }
  });

  beforeEach(async () => {
    walPath = tmpWal('crash');
    rubric = await startMockRubric();
  });

  afterEach(async () => {
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  it('loses zero leaves when SIGKILLed mid-batch, and anchors them after restart', async () => {
    const N = 25;
    await crashAfter(N, walPath);

    // Nothing was flushed and nothing was closed, yet every leaf is on disk.
    const replay = replayWal(walPath);
    expect(replay.leaves).toHaveLength(N);
    expect(replay.unanchored).toHaveLength(N);
    expect(replay.anchors).toHaveLength(0);
    expect(replay.corrupt).toHaveLength(0);
    expect(replay.truncatedTail).toBe(false);

    // Every leaf still hashes to its recorded value, so none was half-written.
    for (const leaf of replay.leaves) {
      expect(sha256Jcs(leaf.record)).toBe(leaf.leafHash);
      expect(leaf.record.subjectId).toBe('crash-agent');
    }
    // Call ids are UUIDv7, so lexical order is call order — the batch is intact
    // and correctly ordered without a separate index.
    const ids = replay.leaves.map((l) => l.callId);
    expect([...ids].sort()).toEqual(ids);

    // Restart over the same directory and anchor the recovered work.
    const receipts: AnyReceipt[] = [];
    const upstream: FetchLike = async () => new Response('{}', { status: 200 });
    const restarted = withAttestation(upstream, {
      rubricApiKey: 'test-key',
      subjectId: 'crash-agent',
      sessionId: 'crash-session',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
      onReceipt: (r) => receipts.push(r),
    });

    expect(restarted.attestor.recovered.leaves).toBe(N);

    const results = await restarted.flush();
    expect(results[0]!.status).toBe('anchored');
    expect(results[0]!.leafCount).toBe(N);
    expect(receipts.filter(isAnchored)).toHaveLength(N);
    expect(replayWal(walPath).unanchored).toHaveLength(0);

    await restarted.close();
  });

  it('recovers a leaf written under the page-cache policy too', async () => {
    // `interval` only guarantees write(2) before return. A process crash cannot
    // lose those bytes; only a machine crash could.
    const N = 10;
    await crashAfter(N, walPath, 'interval');
    expect(replayWal(walPath).leaves).toHaveLength(N);
  });

  it('restores cumulative session spend after a restart', async () => {
    // A budget cap that silently resets on crash is not a cap.
    const wal = new Wal(walPath);
    const record = {
      v: 1 as const,
      callId: '018f0000-0000-7000-8000-000000000001',
      subjectId: 'agent-alpha',
      sessionId: 'budget-session',
      startedAt: '2026-08-23T00:00:00.000Z',
      endedAt: '2026-08-23T00:00:00.100Z',
      durationMs: 100,
      request: { method: 'POST', host: 'h', path: '/p', bodyHash: 'a'.repeat(64), bodyBytes: 2 },
      response: { status: 200, bodyHash: 'b'.repeat(64), bodyBytes: 2, headers: {} },
      payment: {
        scheme: 'exact',
        network: 'eip155:8453',
        amountAuthorized: '7000000',
        asset: 'usdc',
        payTo: '0x1',
        xPaymentHash: 'c'.repeat(64),
      },
      outcome: 'ok' as const,
      assertions: [],
    };
    wal.appendLeaf({
      type: 'leaf',
      callId: record.callId,
      leafHash: sha256Jcs(record),
      at: Date.now(),
      record,
    });
    wal.close();

    const restarted = withAttestation(async () => new Response('{}'), {
      subjectId: 'agent-alpha',
      sessionId: 'budget-session',
      walPath,
      mode: 'off',
      installSignalHandlers: false,
    });
    // 7000000 atomic USDC == $7.
    expect(restarted.attestor.spendUsd).toBe('7.000000');
    await restarted.close();
  });

  it('tolerates a truncated final line without losing earlier leaves', async () => {
    await crashAfter(5, walPath);
    const path = join(walPath, 'leaves.jsonl');

    // Exactly what a crash between write() and the next newline leaves behind.
    appendFileSync(path, '{"type":"leaf","callId":"partial","leafHa');

    const replay = replayWal(walPath);
    expect(replay.leaves).toHaveLength(5);
    expect(replay.truncatedTail).toBe(true);
    expect(replay.corrupt).toHaveLength(1);
    expect(replay.corrupt[0]!.reason).toMatch(/partial line/);
  });

  it('flags a hand-edited leaf as corrupt instead of trusting it', async () => {
    await crashAfter(3, walPath);
    const path = join(walPath, 'leaves.jsonl');
    const lines = readFileSync(path, 'utf8').trim().split('\n');

    const tampered = JSON.parse(lines[1]!);
    tampered.record.request.path = '/somewhere-else';
    lines[1] = JSON.stringify(tampered);
    writeFileSync(path, lines.join('\n') + '\n');

    const replay = replayWal(walPath);
    // The edited leaf no longer hashes to its recorded leafHash.
    expect(replay.leaves).toHaveLength(2);
    expect(replay.corrupt).toHaveLength(1);
    expect(replay.corrupt[0]!.reason).toMatch(/leaf hash mismatch/);
  });

  it('does not re-anchor leaves that a previous process already anchored', async () => {
    await crashAfter(4, walPath);

    const first = withAttestation(async () => new Response('{}'), {
      rubricApiKey: 'test-key',
      subjectId: 'crash-agent',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });
    await first.flush();
    await first.close();
    const attestCount = rubric.requests.filter((r) => r.path === '/v1/tiered-attest').length;
    expect(attestCount).toBe(1);

    // A second process over the same WAL sees the anchor line and re-queues nothing.
    const second = withAttestation(async () => new Response('{}'), {
      rubricApiKey: 'test-key',
      subjectId: 'crash-agent',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });
    expect(second.attestor.recovered.leaves).toBe(0);
    const results = await second.flush();
    expect(results[0]!.status).toBe('empty');
    expect(rubric.requests.filter((r) => r.path === '/v1/tiered-attest')).toHaveLength(1);

    // The receipts are still retrievable after the restart, proofs and all.
    const replay = replayWal(walPath);
    const anyCallId = replay.leaves[0]!.callId;
    const receipt = second.getReceipt(anyCallId);
    expect(receipt && isAnchored(receipt)).toBe(true);

    await second.close();
  });

  it('starts cleanly on an empty or missing WAL directory', () => {
    const fresh = tmpWal('crash-empty');
    const replay = replayWal(fresh);
    expect(replay.leaves).toEqual([]);
    expect(replay.anchors).toEqual([]);
    expect(replay.corrupt).toEqual([]);
    rmSync(fresh, { recursive: true, force: true });
  });
});
