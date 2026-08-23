import { createHash, randomBytes } from 'node:crypto';
import { jcsBytes } from './jcs.js';

/** sha256 over raw bytes, lowercase hex. */
export function sha256(data: Buffer | Uint8Array | string): string {
  return createHash('sha256')
    .update(typeof data === 'string' ? Buffer.from(data, 'utf8') : data)
    .digest('hex');
}

/** sha256 over the RFC 8785 canonical form of a value. This produces every leaf hash. */
export function sha256Jcs(value: unknown): string {
  return sha256(jcsBytes(value));
}

/**
 * Hash of a value that must not appear in clear.
 *
 * Prefixed so an auditor reading a receipt can tell a digest from a literal, and
 * so two receipts can be compared for equality of a redacted field without either
 * receipt disclosing it.
 */
export function tag(value: string): string {
  return 'sha256:' + sha256(value);
}

/** sha256 of the empty byte string — the body hash for requests with no body. */
export const EMPTY_SHA256 = sha256(Buffer.alloc(0));

/**
 * UUIDv7 (RFC 9562 §5.7): 48-bit big-endian Unix ms, 4-bit version, 12 bits of
 * sub-millisecond sequence, 2-bit variant, 62 bits random.
 *
 * Monotonic within a process: when two ids land in the same millisecond the
 * sequence counter increments, so `callId` sorts in call order and the WAL can be
 * replayed without a separate index. Falls back to a bumped timestamp if a single
 * millisecond ever overflows 4096 ids.
 */
let lastMs = -1;
let seq = 0;

export function uuidv7(now: () => number = Date.now): string {
  let ms = now();
  if (ms === lastMs) {
    seq++;
    if (seq > 0xfff) {
      // Overflow: borrow from the next millisecond rather than emit a duplicate.
      lastMs = ms = lastMs + 1;
      seq = 0;
    }
  } else if (ms < lastMs) {
    // Clock stepped backwards. Keep monotonicity; the timestamp is a sort key, not
    // a trusted time source — `startedAt` carries the actual wall clock.
    ms = lastMs;
    seq++;
    if (seq > 0xfff) {
      lastMs = ms = lastMs + 1;
      seq = 0;
    }
  } else {
    lastMs = ms;
    seq = 0;
  }

  const bytes = randomBytes(16);
  bytes.writeUIntBE(ms, 0, 6);
  bytes[6] = 0x70 | ((seq >> 8) & 0x0f);
  bytes[7] = seq & 0xff;
  bytes[8] = 0x80 | (bytes[8]! & 0x3f);

  const h = bytes.toString('hex');
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

/** Reset the UUIDv7 monotonic state. Test-only. */
export function __resetUuidState(): void {
  lastMs = -1;
  seq = 0;
}
