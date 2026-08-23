import type { CallRecord, Redact } from './types.js';

/**
 * Redaction.
 *
 * Ordering matters and is fixed: `bodyHash` is computed over the ORIGINAL bytes,
 * then redaction runs, then the leaf hash is taken over the redacted record. So a
 * redacted receipt still binds to exactly the bytes that crossed the wire — an
 * auditor holding the original body can prove it matches, while the receipt itself
 * discloses nothing.
 *
 * The leaf hash covers the redacted record, not the original. It has to: the
 * verifier only ever sees the redacted record, so hashing anything else would make
 * every receipt unverifiable.
 */

/**
 * Fields that `metadata` mode is allowed to keep in clear.
 *
 * An allowlist, not a denylist. A denylist over response bodies is a standing
 * invitation to leak the one field nobody thought of.
 */
export const METADATA_ALLOWLIST: readonly string[] = [
  'response.servedModel',
  'response.usage.promptTokens',
  'response.usage.completionTokens',
  'response.usage.totalTokens',
  'response.status',
] as const;

/** Deep clone via structuredClone; records are plain JSON by construction. */
function clone<T>(v: T): T {
  return structuredClone(v);
}

/**
 * Shallow-copy just the branch being edited.
 *
 * The record was built moments ago by `assembleRecord` and nothing else holds a
 * reference to it, so a deep clone buys no safety on the built-in paths — it only
 * buys allocations, and allocations on the request path show up as GC pauses in
 * the p99. A user-supplied redact function is different: that one gets a real
 * clone, because we cannot know what it will do with the object.
 */
function withResponse(rec: CallRecord, response: CallRecord['response']): CallRecord {
  return { ...rec, response };
}

/**
 * `hash-only` — the default. Strip every field derived from body content.
 *
 * `servedModel` and `usage` come out of the response body, so under hash-only they
 * are removed. The `model_matches_request` assertion still runs and still records
 * pass/fail; its `observed`/`expected` carry sha256 digests instead of names. The
 * audit conclusion survives; the content does not leave the process.
 */
function applyHashOnly(rec: CallRecord): CallRecord {
  const { servedModel: _servedModel, usage: _usage, ...response } = rec.response;
  return withResponse(rec, response);
}

function applyMetadata(rec: CallRecord): CallRecord {
  // The record is already built to the metadata allowlist; nothing is ever
  // populated from a body outside it. This branch exists so the mode is explicit
  // at the call site rather than implied by absence.
  return rec;
}

export function applyRedaction(rec: CallRecord, redact: Redact): CallRecord {
  if (typeof redact === 'function') {
    const out = redact(clone(rec));
    if (!out || typeof out !== 'object') {
      throw new TypeError('redact function must return a CallRecord');
    }
    return out;
  }
  return redact === 'metadata' ? applyMetadata(rec) : applyHashOnly(rec);
}
