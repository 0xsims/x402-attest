import { EMPTY_SHA256, sha256, tag } from './hash.js';
import {
  HEADER_ALLOWLIST,
  HEADER_ALLOWLIST_PREFIXES,
  type RequestRecord,
  type ResponseRecord,
} from './types.js';

/**
 * Building the observable parts of a call record.
 *
 * Two rules govern everything here: hash anything that could carry a secret, and
 * allowlist anything kept in clear. Neither is negotiable at runtime, because a
 * record that leaked once is leaked in an append-only log forever.
 */

/** Body that could not be read without consuming a stream the caller still needs. */
export const UNHASHABLE_BODY = 'unhashable:stream';

export type CapturedBody = { bytes: Uint8Array | null; hash: string; length: number };

const EMPTY_BODY: CapturedBody = { bytes: new Uint8Array(0), hash: EMPTY_SHA256, length: 0 };

/**
 * Read a request body into bytes for hashing.
 *
 * Streaming bodies are the one case we refuse: consuming the stream to hash it
 * would break the request the caller is trying to make. We record that the body
 * was unhashable rather than silently hashing nothing, because `bodyHash` equal to
 * the empty digest would be an affirmative false claim about the payload.
 */
export async function captureRequestBody(
  input: string | URL | Request,
  init?: RequestInit,
): Promise<CapturedBody> {
  const body = init?.body;

  // An explicit `body: null/undefined` in init means there is no body, and we must
  // not then go looking at a Request's body for one.
  if (init && 'body' in init && (body === undefined || body === null)) return EMPTY_BODY;

  if (body !== undefined && body !== null) {
    if (typeof body === 'string') return fromBytes(Buffer.from(body, 'utf8'));
    if (body instanceof Uint8Array) return fromBytes(body);
    if (body instanceof ArrayBuffer) return fromBytes(new Uint8Array(body));
    if (ArrayBuffer.isView(body)) {
      return fromBytes(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
    }
    if (body instanceof URLSearchParams) return fromBytes(Buffer.from(body.toString(), 'utf8'));
    if (typeof Blob !== 'undefined' && body instanceof Blob) {
      return fromBytes(new Uint8Array(await body.arrayBuffer()));
    }
    return { bytes: null, hash: UNHASHABLE_BODY, length: -1 };
  }

  if (typeof input === 'object' && input !== null && 'clone' in input) {
    const req = input as Request;
    if (!req.body) return EMPTY_BODY;
    try {
      // Cloning is what makes this safe: the caller's Request keeps an unread body.
      return fromBytes(new Uint8Array(await req.clone().arrayBuffer()));
    } catch {
      return { bytes: null, hash: UNHASHABLE_BODY, length: -1 };
    }
  }

  return EMPTY_BODY;
}

function fromBytes(bytes: Uint8Array): CapturedBody {
  return { bytes, hash: sha256(bytes), length: bytes.byteLength };
}

const DECODER = new TextDecoder('utf-8', { fatal: false });

/**
 * Parse captured bytes as JSON, or undefined.
 *
 * Decoded through a shared TextDecoder rather than `Buffer.from(bytes)`, which
 * would copy the whole body a second time purely to read two fields out of it.
 */
export function tryJson(bytes: Uint8Array | null): unknown {
  if (!bytes || bytes.byteLength === 0) return undefined;
  try {
    return JSON.parse(DECODER.decode(bytes));
  } catch {
    return undefined;
  }
}

function resolveUrl(input: string | URL | Request): URL | null {
  try {
    const raw =
      typeof input === 'string'
        ? input
        : input instanceof URL
          ? input.href
          : (input as Request).url;
    return new URL(raw);
  } catch {
    return null;
  }
}

function methodOf(input: string | URL | Request, init?: RequestInit): string {
  const m =
    init?.method ??
    (typeof input === 'object' && input !== null && 'method' in input
      ? (input as Request).method
      : undefined);
  return (m ?? 'GET').toUpperCase();
}

function contentTypeOf(input: string | URL | Request, init?: RequestInit): string | undefined {
  try {
    if (init?.headers) {
      const v = new Headers(init.headers as ConstructorParameters<typeof Headers>[0]).get('content-type');
      if (v) return v;
    }
    if (typeof input === 'object' && input !== null && 'headers' in input) {
      const v = (input as Request).headers.get('content-type');
      if (v) return v;
    }
  } catch {
    /* ignore malformed headers */
  }
  return undefined;
}

export function buildRequestRecord(
  input: string | URL | Request,
  init: RequestInit | undefined,
  body: CapturedBody,
): RequestRecord {
  const url = resolveUrl(input);

  const rec: RequestRecord = {
    method: methodOf(input, init),
    host: url?.host ?? 'unknown',
    path: url?.pathname ?? 'unknown',
    bodyHash: body.hash,
    bodyBytes: body.length < 0 ? 0 : body.length,
  };

  // Query strings routinely carry API keys, signed URLs and customer identifiers.
  // The hash still lets an auditor confirm a claimed query, which is all a receipt
  // needs to support.
  if (url && url.search.length > 1) rec.queryHash = tag(url.search.slice(1));

  const ct = contentTypeOf(input, init);
  if (ct) rec.contentType = ct;

  return rec;
}

/** Header allowlist. Exact names plus the ClawRouter prefix; everything else dropped. */
export function filterHeaders(headers: Headers | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  if (!headers) return out;
  headers.forEach((value, key) => {
    const k = key.toLowerCase();
    const allowed =
      HEADER_ALLOWLIST.includes(k) || HEADER_ALLOWLIST_PREFIXES.some((p) => k.startsWith(p));
    if (allowed) out[k] = value;
  });
  return out;
}

export function buildResponseRecord(
  status: number,
  headers: Headers | undefined,
  body: CapturedBody,
): ResponseRecord {
  return {
    status,
    bodyHash: body.hash,
    bodyBytes: body.length < 0 ? 0 : body.length,
    headers: filterHeaders(headers),
  };
}
