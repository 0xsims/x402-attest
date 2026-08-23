import {
  appendFileSync,
  closeSync,
  fdatasyncSync,
  fsyncSync,
  mkdirSync,
  openSync,
  readFileSync,
  writeSync,
  existsSync,
} from 'node:fs';
import { join } from 'node:path';
import { sha256Jcs } from './hash.js';
import type { BatchEnvelope, CallRecord, ProofStep, WalOptions } from './types.js';

/**
 * Append-only write-ahead log.
 *
 * The WAL is the durability boundary. A leaf is written and fsynced before the
 * wrapper returns, so the evidence for a call exists on disk before the caller can
 * act on the response. Everything after that point — batching, Merkle, anchoring —
 * is recoverable from this file.
 *
 * Append-only is deliberate: anchoring results are recorded as separate `anchor`
 * lines rather than by rewriting leaf lines in place. A log that is only ever
 * appended to cannot lose a committed record to a partial rewrite, and it means a
 * crash can only ever truncate the tail.
 */

export const LEAVES_FILE = 'leaves.jsonl';
export const ANCHORS_FILE = 'anchors.jsonl';
/** Payload keys are credentials, kept out of the evidence files entirely. */
export const KEYS_FILE = 'payload-keys.jsonl';

export type LeafEntry = {
  type: 'leaf';
  callId: string;
  leafHash: string;
  /** Epoch ms the leaf was written, for age-based flush after a restart. */
  at: number;
  record: CallRecord;
};

export type AnchorEntry = {
  type: 'anchor';
  batchId: string;
  root: string;
  attestationId: string;
  verifyUrl: string;
  at: number;
  leafCount: number;
  /** Inclusion proof per leaf, keyed by callId. */
  proofs: Record<string, ProofStep[]>;
  /**
   * The payload submitted for this batch, and the commitment Rubric issued for it.
   *
   * Persisted because Rubric never gives the payload back — a process that
   * restarts without these cannot reconstruct a verifiable receipt for leaves it
   * already anchored, only a receipt that says it was anchored.
   */
  envelope: BatchEnvelope;
  payloadCommitment?: string;
  payloadHash?: string;
};

export type WalReplay = {
  leaves: LeafEntry[];
  anchors: AnchorEntry[];
  /** Leaves whose batch has not been anchored. These must be re-queued. */
  unanchored: LeafEntry[];
  /** Lines that could not be parsed or failed their own hash check. */
  corrupt: { file: string; line: number; reason: string }[];
  /** True when the last line of leaves.jsonl was a partial write. */
  truncatedTail: boolean;
};

export class Wal {
  readonly dir: string;
  private leavesFd: number | null = null;
  private anchorsFd: number | null = null;
  private keysFd: number | null = null;
  private readonly policy: Required<WalOptions>;
  private dirty = false;
  private syncTimer: NodeJS.Timeout | null = null;

  constructor(dir: string, options: WalOptions = {}) {
    this.dir = dir;
    this.policy = {
      fsync: options.fsync ?? 'always',
      fsyncIntervalMs: options.fsyncIntervalMs ?? 250,
    };
    mkdirSync(dir, { recursive: true });
  }

  get leavesPath(): string {
    return join(this.dir, LEAVES_FILE);
  }
  get anchorsPath(): string {
    return join(this.dir, ANCHORS_FILE);
  }
  get keysPath(): string {
    return join(this.dir, KEYS_FILE);
  }

  private fd(which: 'leaves' | 'anchors' | 'keys'): number {
    if (which === 'leaves') {
      // 0o600: a receipt names hosts, paths, payees and amounts. Not secret, but
      // not world-readable either.
      this.leavesFd ??= openSync(this.leavesPath, 'a', 0o600);
      return this.leavesFd;
    }
    if (which === 'anchors') {
      this.anchorsFd ??= openSync(this.anchorsPath, 'a', 0o600);
      return this.anchorsFd;
    }
    this.keysFd ??= openSync(this.keysPath, 'a', 0o600);
    return this.keysFd;
  }

  /**
   * Append one line and fsync it.
   *
   * Synchronous by design. An async write would let the wrapper return before the
   * bytes are durable, which is precisely the window in which a crash loses the
   * record of a payment that has already been made. The cost is one fsync per
   * call, which is sub-millisecond on any SSD and is budgeted for in the
   * <5ms overhead target.
   */
  private appendSync(which: 'leaves' | 'anchors' | 'keys', obj: unknown): void {
    const fd = this.fd(which);
    const line = JSON.stringify(obj) + '\n';

    // The write itself always happens before we return. After this syscall the
    // bytes are in the kernel page cache and survive the process dying.
    writeSync(fd, line, null, 'utf8');
    this.dirty = true;

    // fdatasync, not fsync: the data and the file size must be durable, the
    // access-time metadata need not be.
    if (this.policy.fsync === 'always') {
      fdatasyncSync(fd);
      this.dirty = false;
      return;
    }
    if (this.policy.fsync === 'interval') this.armSyncTimer();
  }

  /**
   * Schedule the deferred sync off the request path.
   *
   * The obvious implementation — "if more than fsyncIntervalMs has elapsed,
   * fdatasync inline" — makes whichever call happens to cross the boundary pay
   * the whole cost. Measured, that is worse at p99 than syncing every call: the
   * median improves but the periodic spike lands squarely in the tail. Running it
   * on a timer means no call ever pays for it.
   */
  private armSyncTimer(): void {
    if (this.syncTimer) return;
    this.syncTimer = setTimeout(() => {
      this.syncTimer = null;
      this.syncNow();
    }, this.policy.fsyncIntervalMs);
    // Never hold the event loop open: close() and flush() both sync explicitly.
    this.syncTimer.unref?.();
  }

  /** Force everything written so far to stable storage. Called on flush and close. */
  syncNow(): void {
    if (this.syncTimer) {
      clearTimeout(this.syncTimer);
      this.syncTimer = null;
    }
    if (!this.dirty) return;
    for (const fd of [this.leavesFd, this.anchorsFd, this.keysFd]) {
      if (fd === null) continue;
      try {
        fdatasyncSync(fd);
      } catch {
        /* fd already closed, or a filesystem that cannot sync */
      }
    }
    this.dirty = false;
  }

  appendLeaf(entry: LeafEntry): void {
    this.appendSync('leaves', entry);
  }

  appendAnchor(entry: AnchorEntry): void {
    this.appendSync('anchors', entry);
  }

  /**
   * Record a tiered-attest payload key.
   *
   * Rubric returns the AES key exactly once. We keep it out of receipts and out of
   * the leaf log because it is a decryption credential, not evidence — but we do
   * not discard it, because without it the submitted payload cannot be recovered
   * from Rubric's warm store later.
   */
  appendPayloadKey(attestationId: string, payloadKey: string, at: number): void {
    this.appendSync('keys', { attestationId, payloadKey, at });
  }

  close(): void {
    this.syncNow();
    for (const fd of [this.leavesFd, this.anchorsFd, this.keysFd]) {
      if (fd !== null) {
        try {
          fsyncSync(fd);
        } catch {
          /* already closed or read-only fs; the data is either durable or lost */
        }
        try {
          closeSync(fd);
        } catch {
          /* ignore */
        }
      }
    }
    this.leavesFd = null;
    this.anchorsFd = null;
    this.keysFd = null;
  }

  /**
   * Replay the log after a restart.
   *
   * Tolerates a truncated final line — a crash between `write` and the next
   * newline leaves exactly that — and re-verifies each leaf against its own
   * recorded hash so silent bit-rot or hand-editing surfaces as `corrupt` rather
   * than as a leaf that will never verify.
   */
  replay(): WalReplay {
    const out: WalReplay = {
      leaves: [],
      anchors: [],
      unanchored: [],
      corrupt: [],
      truncatedTail: false,
    };

    const leavesRaw = existsSync(this.leavesPath)
      ? readFileSync(this.leavesPath, 'utf8')
      : '';
    if (leavesRaw.length > 0) {
      const lines = leavesRaw.split('\n');
      // A complete file ends with '\n', so the final element is ''. Anything else
      // is a partial write from a crash.
      const tail = lines.pop();
      if (tail !== undefined && tail.length > 0) {
        out.truncatedTail = true;
        out.corrupt.push({
          file: LEAVES_FILE,
          line: lines.length + 1,
          reason: 'partial line (crash during append)',
        });
      }
      lines.forEach((line, i) => {
        if (line.trim().length === 0) return;
        let parsed: LeafEntry;
        try {
          parsed = JSON.parse(line) as LeafEntry;
        } catch {
          out.corrupt.push({ file: LEAVES_FILE, line: i + 1, reason: 'unparseable JSON' });
          return;
        }
        if (parsed?.type !== 'leaf' || !parsed.record || !parsed.leafHash) {
          out.corrupt.push({ file: LEAVES_FILE, line: i + 1, reason: 'not a leaf entry' });
          return;
        }
        if (sha256Jcs(parsed.record) !== parsed.leafHash) {
          out.corrupt.push({
            file: LEAVES_FILE,
            line: i + 1,
            reason: `leaf hash mismatch for callId ${parsed.callId}`,
          });
          return;
        }
        out.leaves.push(parsed);
      });
    }

    const anchorsRaw = existsSync(this.anchorsPath)
      ? readFileSync(this.anchorsPath, 'utf8')
      : '';
    if (anchorsRaw.length > 0) {
      anchorsRaw.split('\n').forEach((line, i) => {
        if (line.trim().length === 0) return;
        try {
          const parsed = JSON.parse(line) as AnchorEntry;
          if (parsed?.type === 'anchor') out.anchors.push(parsed);
        } catch {
          // A truncated tail here costs at most one re-anchor, never a lost leaf.
          out.corrupt.push({ file: ANCHORS_FILE, line: i + 1, reason: 'unparseable JSON' });
        }
      });
    }

    const anchoredCallIds = new Set<string>();
    for (const a of out.anchors) {
      for (const callId of Object.keys(a.proofs ?? {})) anchoredCallIds.add(callId);
    }
    out.unanchored = out.leaves.filter((l) => !anchoredCallIds.has(l.callId));

    return out;
  }
}

/** Read a WAL directory without opening it for writing. Used by tooling and tests. */
export function replayWal(dir: string, options: WalOptions = {}): WalReplay {
  const wal = new Wal(dir, options);
  try {
    return wal.replay();
  } finally {
    wal.close();
  }
}

/** Append a line to an arbitrary file with fsync. Used by the export writer. */
export function appendLineSync(path: string, line: string): void {
  appendFileSync(path, line + '\n', { encoding: 'utf8', mode: 0o600 });
  const fd = openSync(path, 'r');
  try {
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
}
