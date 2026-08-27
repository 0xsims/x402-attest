import { AnchorClient, AnchorError, backoffDelay, buildEnvelope } from './anchor.js';
import { buildMerkleTree, buildProof } from './merkle.js';
import { Wal, type AnchorEntry, type LeafEntry } from './wal.js';
import type {
  AnyReceipt,
  ProofStep,
  Receipt,
  RecordedEnvelope,
  ResolvedOptions,
} from './types.js';

/**
 * Batching and anchoring.
 *
 * Per-call anchoring is economically dead: an attestation costs about $0.005 while
 * the median x402 payment is a fraction of a cent, so anchoring each call would
 * cost an order of magnitude more than the thing it attests. Batching 256 calls
 * under one Merkle root brings the marginal cost to roughly $0.00002 per call
 * while keeping per-call verifiability intact — each leaf still gets an
 * independent inclusion proof against the anchored root.
 *
 * Nothing in this file is ever awaited by the request path.
 */

export type FlushStatus = 'anchored' | 'retrying' | 'skipped' | 'empty';

export type FlushResult = {
  batchId: string;
  status: FlushStatus;
  leafCount: number;
  root?: string;
  attestationId?: string;
  error?: string;
};

type PendingBatch = {
  batchId: string;
  leaves: LeafEntry[];
  root: string;
  proofs: Record<string, ProofStep[]>;
  envelope: ReturnType<typeof buildEnvelope>;
  attempt: number;
};

export class Batcher {
  private readonly opts: ResolvedOptions;
  private readonly wal: Wal;
  private readonly client: AnchorClient;

  private queue: LeafEntry[] = [];
  private ageTimer: NodeJS.Timeout | null = null;
  private retryTimers = new Set<NodeJS.Timeout>();
  private inflight = new Set<Promise<unknown>>();
  private retrying = new Map<string, PendingBatch>();

  private receipts = new Map<string, AnyReceipt>();
  private closed = false;
  private batchSeq = 0;

  constructor(opts: ResolvedOptions, wal: Wal, client: AnchorClient) {
    this.opts = opts;
    this.wal = wal;
    this.client = client;
  }

  /** Receipts known to this process, anchored or pending. */
  getReceipt(callId: string): AnyReceipt | undefined {
    return this.receipts.get(callId);
  }

  allReceipts(): AnyReceipt[] {
    return [...this.receipts.values()];
  }

  /** Number of leaves cut into a batch but not yet anchored. */
  get pendingAnchorCount(): number {
    let n = this.queue.length;
    for (const b of this.retrying.values()) n += b.leaves.length;
    return n;
  }

  /**
   * Enqueue a leaf that has already been durably written to the WAL.
   *
   * Returns synchronously. Any anchoring work it triggers runs detached — the
   * caller is on the request path and must not wait for the network.
   */
  add(leaf: LeafEntry): void {
    if (this.opts.mode === 'off') {
      this.recordPending(leaf);
      return;
    }
    this.queue.push(leaf);
    this.recordPending(leaf);

    if (this.opts.mode === 'immediate' || this.queue.length >= this.opts.batch.maxLeaves) {
      this.detach(this.flush());
      return;
    }
    this.armAgeTimer();
  }

  /** Re-queue leaves recovered from the WAL after a restart. */
  adoptRecovered(leaves: LeafEntry[]): void {
    for (const leaf of leaves) {
      this.recordPending(leaf);
      if (this.opts.mode !== 'off') this.queue.push(leaf);
    }
    if (this.queue.length > 0 && this.opts.mode !== 'off') this.armAgeTimer();
  }

  /** Rehydrate anchored receipts from replayed anchor entries. */
  adoptAnchors(anchors: AnchorEntry[], leaves: LeafEntry[]): void {
    const byCallId = new Map(leaves.map((l) => [l.callId, l]));
    for (const a of anchors) {
      for (const [callId, proof] of Object.entries(a.proofs ?? {})) {
        const leaf = byCallId.get(callId);
        if (!leaf) continue;
        const rebuilt: Receipt = {
          callRecord: leaf.record,
          leafHash: leaf.leafHash,
          proof,
          root: a.root,
          attestationId: a.attestationId,
          verifyUrl: a.verifyUrl,
          envelope: a.envelope,
        };
        if (a.verifyApiUrl) rebuilt.verifyApiUrl = a.verifyApiUrl;
        if (a.payloadCommitment) rebuilt.payloadCommitment = a.payloadCommitment;
        if (a.payloadHash) rebuilt.payloadHash = a.payloadHash;
        if (a.commitmentSalt) rebuilt.commitmentSalt = a.commitmentSalt;
        // Recombine what was submitted with what the server injected, because the
        // commitment covers the pair. A copy, not a mutation: `a.envelope` stays
        // the submitted bytes and `root` is untouched either way.
        if (a.x402Payment) rebuilt.envelope = { ...a.envelope, x402Payment: a.x402Payment };
        this.receipts.set(callId, rebuilt);
      }
    }
  }

  private recordPending(leaf: LeafEntry): void {
    if (!this.receipts.has(leaf.callId)) {
      this.receipts.set(leaf.callId, {
        callRecord: leaf.record,
        leafHash: leaf.leafHash,
        proof: null,
        root: null,
        attestationId: null,
        verifyUrl: null,
        envelope: null,
      });
    }
  }

  private armAgeTimer(): void {
    if (this.ageTimer || this.closed) return;
    this.ageTimer = setTimeout(() => {
      this.ageTimer = null;
      this.detach(this.flush());
    }, this.opts.batch.maxAgeMs);
    // Never hold the event loop open. An idle agent should be able to exit; the
    // signal handler and close() are what guarantee the drain.
    this.ageTimer.unref?.();
  }

  private clearAgeTimer(): void {
    if (this.ageTimer) {
      clearTimeout(this.ageTimer);
      this.ageTimer = null;
    }
  }

  /** Drain detached anchoring work. Bounded: each pass can only add retries. */
  private async settleInflight(): Promise<void> {
    for (let pass = 0; pass < 8 && this.inflight.size > 0; pass++) {
      await Promise.allSettled([...this.inflight]);
    }
  }

  private detach(p: Promise<unknown>): void {
    this.inflight.add(p);
    p.catch(() => {
      // Anchoring failures are surfaced through onAnchorError and retried. They
      // must never become an unhandled rejection in the host process.
    }).finally(() => this.inflight.delete(p));
  }

  /**
   * Cut the current queue into a batch and attempt to anchor it once.
   *
   * Resolves after the first attempt completes. On failure the batch moves to the
   * retry schedule and this resolves with `status: 'retrying'` rather than
   * blocking — retries are indefinite by design, and a `flush()` that waited for
   * them would hang for as long as Rubric is down.
   */
  async flush(): Promise<FlushResult[]> {
    this.clearAgeTimer();
    // Under a relaxed fsync policy the leaves may only be in the page cache.
    // Anything we are about to anchor must be on stable storage first.
    this.wal.syncNow();
    // Auto-triggered flushes run detached. An explicit flush() means "get
    // everything out now", so wait for those before reporting, otherwise a caller
    // that flushes and then inspects state races its own earlier batches.
    await this.settleInflight();

    if (this.opts.mode === 'off') {
      return [{ batchId: 'off', status: 'skipped', leafCount: this.queue.length }];
    }
    if (this.queue.length === 0) {
      return [{ batchId: 'none', status: 'empty', leafCount: 0 }];
    }

    const leaves = this.queue;
    this.queue = [];
    const batch = this.prepare(leaves);
    return [await this.attempt(batch)];
  }

  private prepare(leaves: LeafEntry[]): PendingBatch {
    const tree = buildMerkleTree(leaves.map((l) => l.leafHash));
    const proofs: Record<string, ProofStep[]> = {};
    leaves.forEach((leaf, i) => {
      proofs[leaf.callId] = buildProof(tree, i);
    });

    const first = leaves[0]!;
    const last = leaves[leaves.length - 1]!;
    const envelope = buildEnvelope({
      root: tree.root,
      leafCount: leaves.length,
      firstCallId: first.callId,
      lastCallId: last.callId,
      from: first.record.startedAt,
      to: last.record.endedAt,
      subjectId: this.opts.subjectId,
      policyId: this.opts.policyId,
    });

    return {
      batchId: `${this.opts.subjectId}:${++this.batchSeq}:${tree.root.slice(0, 12)}`,
      leaves,
      root: tree.root,
      proofs,
      envelope,
      attempt: 0,
    };
  }

  private async attempt(batch: PendingBatch): Promise<FlushResult> {
    batch.attempt++;
    try {
      const result = await this.client.anchor(batch.envelope);

      const entry: AnchorEntry = {
        type: 'anchor',
        batchId: batch.batchId,
        root: batch.root,
        attestationId: result.attestationId,
        verifyUrl: result.verifyUrl,
        verifyApiUrl: result.verifyApiUrl,
        at: this.opts.now(),
        leafCount: batch.leaves.length,
        proofs: batch.proofs,
        envelope: batch.envelope,
      };
      if (result.payloadCommitment) entry.payloadCommitment = result.payloadCommitment;
      if (result.payloadHash) entry.payloadHash = result.payloadHash;
      if (result.commitmentSalt) entry.commitmentSalt = result.commitmentSalt;
      if (result.x402Payment) entry.x402Payment = result.x402Payment;
      // Durable before it is observable: the anchor line is fsynced before any
      // receipt claims to be anchored, so a crash cannot leave a caller holding an
      // attestationId that the WAL has no record of.
      this.wal.appendAnchor(entry);
      this.retrying.delete(batch.batchId);

      // The payload the commitment actually covers.
      //
      // Rubric's keyless route commits to the submitted envelope plus an
      // `x402Payment` member it injects server-side (DEVIATIONS §21), so a
      // receipt recording only what was submitted cannot open its own
      // commitment. Extended by copy, once per batch: `batch.envelope` is the
      // object the root was built into and the one a retry re-submits, and it
      // must go back over the wire byte-identical. `root` is the same in both,
      // so the `envelope.root` check is unaffected either way.
      const committedEnvelope: RecordedEnvelope = result.x402Payment
        ? { ...batch.envelope, x402Payment: result.x402Payment }
        : batch.envelope;

      for (const leaf of batch.leaves) {
        const receipt: Receipt = {
          callRecord: leaf.record,
          leafHash: leaf.leafHash,
          proof: batch.proofs[leaf.callId] ?? [],
          root: batch.root,
          attestationId: result.attestationId,
          verifyUrl: result.verifyUrl,
          verifyApiUrl: result.verifyApiUrl,
          envelope: committedEnvelope,
        };
        if (result.payloadCommitment) receipt.payloadCommitment = result.payloadCommitment;
        if (result.payloadHash) receipt.payloadHash = result.payloadHash;
        if (result.commitmentSalt) receipt.commitmentSalt = result.commitmentSalt;
        this.receipts.set(leaf.callId, receipt);
        this.safeEmit(receipt);
      }

      return {
        batchId: batch.batchId,
        status: 'anchored',
        leafCount: batch.leaves.length,
        root: batch.root,
        attestationId: result.attestationId,
      };
    } catch (e) {
      const err = e instanceof Error ? e : new Error(String(e));
      try {
        this.opts.onAnchorError?.(err, batch.attempt);
      } catch {
        /* a broken error handler must not take down anchoring */
      }

      // Even a non-retryable error keeps the batch: the leaves are on disk and a
      // later `flush()` or a restart can re-attempt them. Dropping evidence
      // because the server said 400 is never the right trade.
      this.retrying.set(batch.batchId, batch);
      if (!this.closed) this.scheduleRetry(batch);

      return {
        batchId: batch.batchId,
        status: 'retrying',
        leafCount: batch.leaves.length,
        root: batch.root,
        error: err.message,
      };
    }
  }

  private scheduleRetry(batch: PendingBatch): void {
    const { minDelayMs, maxDelayMs } = this.opts.retry;
    const delay = backoffDelay(batch.attempt, minDelayMs, maxDelayMs);
    const timer = setTimeout(() => {
      this.retryTimers.delete(timer);
      if (this.closed) return;
      this.detach(this.attempt(batch));
    }, delay);
    timer.unref?.();
    this.retryTimers.add(timer);
  }

  /**
   * Retry every outstanding batch now, ignoring the backoff schedule.
   *
   * Used by `close()` and by callers that know connectivity has returned.
   */
  async retryNow(): Promise<FlushResult[]> {
    const batches = [...this.retrying.values()];
    return Promise.all(batches.map((b) => this.attempt(b)));
  }

  private safeEmit(r: AnyReceipt): void {
    if (!this.opts.onReceipt) return;
    try {
      this.opts.onReceipt(r);
    } catch {
      // The library records; the caller decides. A throwing callback is a caller
      // bug and must not corrupt the anchoring pipeline.
    }
  }

  /** Emit the pending receipt for a leaf as soon as it is durable. */
  emitPending(callId: string): void {
    const r = this.receipts.get(callId);
    if (r) this.safeEmit(r);
  }

  /**
   * Drain and stop.
   *
   * Flushes the queue, gives outstanding batches one immediate retry, and waits up
   * to `drainTimeoutMs` for in-flight work. Whatever does not anchor in time stays
   * in the WAL and is picked up by the next process that opens this `walPath` —
   * the timeout bounds the wait, not the durability.
   */
  async close(): Promise<FlushResult[]> {
    if (this.closed) return [];
    this.clearAgeTimer();

    const results: FlushResult[] = [];
    const drain = (async () => {
      results.push(...(await this.flush()));
      results.push(...(await this.retryNow()));
      await this.settleInflight();
    })();

    const timeout = new Promise<void>((resolve) => {
      const t = setTimeout(resolve, this.opts.drainTimeoutMs);
      t.unref?.();
    });
    await Promise.race([drain, timeout]);

    this.closed = true;
    for (const t of this.retryTimers) clearTimeout(t);
    this.retryTimers.clear();
    return results;
  }
}
