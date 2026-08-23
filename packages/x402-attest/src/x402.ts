import { sha256 } from './hash.js';
import type { ChallengeRecord, PaymentRecord, SettlementRecord } from './types.js';

/**
 * x402 wire parsing.
 *
 * The published protocol docs describe two header generations and do not pin a
 * formal JSON schema (the referenced OpenAPI document is a template placeholder as
 * of 2026-08-23). Current docs name the headers `PAYMENT-REQUIRED`,
 * `PAYMENT-SIGNATURE` and `PAYMENT-RESPONSE`, all base64-encoded JSON; the widely
 * deployed earlier generation uses `X-PAYMENT` / `X-PAYMENT-RESPONSE` with the
 * requirements carried in the 402 body instead of a header.
 *
 * Guessing wrong here does not corrupt evidence — it degrades assertions to
 * `unknown`, which is a truthful but much less useful receipt. So we read both
 * generations and both field spellings, and record exactly what we found.
 */

export const CHALLENGE_HEADERS = ['payment-required', 'x-payment-required'] as const;
export const PAYMENT_HEADERS = ['payment-signature', 'x-payment'] as const;
export const SETTLEMENT_HEADERS = ['payment-response', 'x-payment-response'] as const;

/** Decode base64 (standard or url-safe) JSON. Returns null rather than throwing. */
export function decodeB64Json(raw: string): unknown {
  try {
    const normalized = raw.trim().replace(/-/g, '+').replace(/_/g, '/');
    const text = Buffer.from(normalized, 'base64').toString('utf8');
    if (!text.trim().startsWith('{') && !text.trim().startsWith('[')) return null;
    return JSON.parse(text);
  } catch {
    return null;
  }
}

/** Some clients send the JSON unencoded. Accept either without complaint. */
export function decodeMaybeB64Json(raw: string): unknown {
  const trimmed = raw.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    try {
      return JSON.parse(trimmed);
    } catch {
      return null;
    }
  }
  return decodeB64Json(trimmed);
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' && v.length > 0 ? v : undefined;
}

function num(v: unknown): number | undefined {
  if (typeof v === 'number' && Number.isFinite(v)) return v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return Number(v);
  return undefined;
}

/**
 * Amounts appear as `maxAmountRequired` (x402 v1 requirements), `amount`, or
 * `price` (seller-side config echoed verbatim by some facilitators). All three
 * mean "the most this call may cost"; we record whichever is present.
 */
function amountOf(o: Record<string, unknown>): string | undefined {
  const raw = o['maxAmountRequired'] ?? o['amount'] ?? o['price'] ?? o['maxAmount'];
  if (typeof raw === 'string') return raw;
  if (typeof raw === 'number' && Number.isFinite(raw)) return String(raw);
  // `price` is sometimes an object: { amount, asset }.
  if (raw && typeof raw === 'object') {
    const inner = (raw as Record<string, unknown>)['amount'];
    if (typeof inner === 'string') return inner;
    if (typeof inner === 'number') return String(inner);
  }
  return undefined;
}

function assetOf(o: Record<string, unknown>): string | undefined {
  const direct = str(o['asset']) ?? str(o['currency']) ?? str(o['assetAddress']);
  if (direct) return direct;
  const price = o['price'];
  if (price && typeof price === 'object') {
    return str((price as Record<string, unknown>)['asset']);
  }
  return undefined;
}

/**
 * Normalize a network id to CAIP-2 for policy comparison.
 *
 * Policies are written in CAIP-2 (`eip155:8453`) but challenges in the wild still
 * say `base`. Comparing the raw strings would silently fail an allowlist that is
 * in fact satisfied, so we normalize both sides before comparing — and always
 * record the unnormalized observation in the receipt.
 */
const NETWORK_ALIASES: Record<string, string> = {
  base: 'eip155:8453',
  'base-mainnet': 'eip155:8453',
  'base-sepolia': 'eip155:84532',
  ethereum: 'eip155:1',
  mainnet: 'eip155:1',
  'avalanche-fuji': 'eip155:43113',
  avalanche: 'eip155:43114',
  polygon: 'eip155:137',
  'polygon-amoy': 'eip155:80002',
  solana: 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp',
  'solana-devnet': 'solana:EtWTRABZaYq6iMfeYKouRu166VU2xqa1',
};

export function normalizeNetwork(network: string | undefined): string | undefined {
  if (!network) return undefined;
  const key = network.trim().toLowerCase();
  return NETWORK_ALIASES[key] ?? key;
}

/** EVM addresses are case-insensitive; EIP-55 checksums differ by client. */
export function sameAddress(a: string | undefined, b: string | undefined): boolean | null {
  if (!a || !b) return null;
  return a.trim().toLowerCase() === b.trim().toLowerCase();
}

/**
 * Strip the query string from a challenge `resource` URL.
 *
 * The challenge body is not sensitive and is kept in clear — except for this
 * field, which is the seller echoing back the buyer's own request URL. Leaving it
 * verbatim would reinstate, in clear, exactly the query string that
 * `request.queryHash` exists to keep out of the record. Query strings carry API
 * keys and signed-URL tokens; a leak here is permanent, because the log is
 * append-only.
 */
export function sanitizeResource(resource: string | undefined): string | undefined {
  if (!resource) return undefined;
  try {
    const u = new URL(resource);
    u.search = '';
    u.hash = '';
    return u.toString();
  } catch {
    // Not a URL. Drop anything after the first '?' on principle.
    const q = resource.indexOf('?');
    return q === -1 ? resource : resource.slice(0, q);
  }
}

export type ParsedChallenge = {
  record: ChallengeRecord;
  /** The single `accepts` entry we matched, for downstream comparison. */
  raw: Record<string, unknown>;
};

/**
 * Extract the payment requirements from a 402.
 *
 * `body` is the parsed 402 JSON body (v1 style: `{ x402Version, accepts: [...] }`)
 * and `headerValue` is a `PAYMENT-REQUIRED` header if one was served. `rawBytes`
 * is what we hash — the challenge is not sensitive, but the hash is what binds the
 * receipt to the exact bytes the seller served.
 */
export function parseChallenge(
  source: { body?: unknown; headerValue?: string; rawBytes?: string },
  preferred?: { scheme?: string; network?: string },
): ParsedChallenge | undefined {
  let payload: unknown = source.body;
  if (source.headerValue) {
    const decoded = decodeMaybeB64Json(source.headerValue);
    if (decoded !== null && decoded !== undefined) payload = decoded;
  }
  if (!payload || typeof payload !== 'object') return undefined;

  const obj = payload as Record<string, unknown>;
  const accepts = Array.isArray(obj['accepts'])
    ? (obj['accepts'] as unknown[])
    : Array.isArray(obj['paymentRequirements'])
      ? (obj['paymentRequirements'] as unknown[])
      : // A bare requirements object with no envelope.
        amountOf(obj) !== undefined || str(obj['payTo'])
        ? [obj]
        : [];

  const candidates = accepts.filter(
    (a): a is Record<string, unknown> => !!a && typeof a === 'object',
  );
  if (candidates.length === 0) return undefined;

  // When the seller offers several options, attribute the record to the one the
  // client actually paid. Falling back to `accepts[0]` would make
  // `price_matches_challenge` fail on a correctly behaving multi-option client.
  const chosen =
    candidates.find(
      (c) =>
        (!preferred?.scheme || str(c['scheme']) === preferred.scheme) &&
        (!preferred?.network ||
          normalizeNetwork(str(c['network'])) === normalizeNetwork(preferred.network)),
    ) ?? candidates[0]!;

  const rawForHash =
    source.rawBytes ?? source.headerValue ?? JSON.stringify(source.body ?? payload);

  const record: ChallengeRecord = {
    scheme: str(chosen['scheme']) ?? 'unknown',
    network: str(chosen['network']) ?? 'unknown',
    maxAmountRequired: amountOf(chosen) ?? 'unknown',
    payTo: str(chosen['payTo']) ?? str(chosen['payToAddress']) ?? 'unknown',
    asset: assetOf(chosen) ?? 'unknown',
    rawHash: sha256(rawForHash),
  };

  const resource = sanitizeResource(str(chosen['resource']));
  if (resource) record.resource = resource;
  const timeout = num(chosen['maxTimeoutSeconds']);
  if (timeout !== undefined) record.maxTimeoutSeconds = timeout;

  return { record, raw: chosen };
}

/**
 * Extract what was authorized from the payment header.
 *
 * The header value itself is a signed authorization — a bearer instrument that
 * anyone holding it can submit. Only its sha256 ever reaches the record, and the
 * plaintext never leaves this function's stack frame.
 */
export function parsePaymentHeader(headerValue: string): PaymentRecord | undefined {
  const decoded = decodeMaybeB64Json(headerValue);
  const xPaymentHash = sha256(headerValue);
  if (!decoded || typeof decoded !== 'object') {
    // Undecodable is still evidence: we know a payment header was sent and can
    // bind it by hash, we just cannot describe it.
    return {
      scheme: 'unknown',
      network: 'unknown',
      amountAuthorized: 'unknown',
      asset: 'unknown',
      payTo: 'unknown',
      xPaymentHash,
    };
  }

  const obj = decoded as Record<string, unknown>;
  const payload = (obj['payload'] as Record<string, unknown>) ?? {};
  const authorization = (payload['authorization'] as Record<string, unknown>) ?? {};

  const amount =
    str(authorization['value']) ??
    str(payload['value']) ??
    amountOf(obj) ??
    amountOf(payload) ??
    'unknown';

  const payTo =
    str(authorization['to']) ?? str(payload['to']) ?? str(obj['payTo']) ?? 'unknown';

  return {
    scheme: str(obj['scheme']) ?? 'unknown',
    network: str(obj['network']) ?? 'unknown',
    amountAuthorized: amount,
    asset: assetOf(obj) ?? assetOf(payload) ?? 'unknown',
    payTo,
    xPaymentHash,
  };
}

/** Decode the settlement receipt the seller returns after submitting the payment. */
export function parseSettlementHeader(headerValue: string): SettlementRecord | undefined {
  const decoded = decodeMaybeB64Json(headerValue);
  if (!decoded || typeof decoded !== 'object') return undefined;
  const obj = decoded as Record<string, unknown>;

  const txHash =
    str(obj['transaction']) ?? str(obj['txHash']) ?? str(obj['transactionHash']);
  const network = str(obj['network']);
  // Absent `success` with a present tx hash is treated as settled; absent both is
  // treated as unsettled rather than optimistically true.
  const success =
    typeof obj['success'] === 'boolean' ? (obj['success'] as boolean) : Boolean(txHash);

  const rec: SettlementRecord = { success, source: 'x-payment-response' };
  if (txHash) rec.txHash = txHash;
  if (network) rec.network = network;
  return rec;
}

/** Some sellers report settlement in the response body instead of a header. */
export function parseSettlementBody(body: unknown): SettlementRecord | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const obj = body as Record<string, unknown>;
  const settlement =
    (obj['settlement'] as Record<string, unknown> | undefined) ??
    (obj['payment'] as Record<string, unknown> | undefined);
  if (!settlement || typeof settlement !== 'object') return undefined;

  const txHash =
    str(settlement['txHash']) ??
    str(settlement['transaction']) ??
    str(settlement['transactionHash']);
  if (!txHash && typeof settlement['success'] !== 'boolean') return undefined;

  const rec: SettlementRecord = {
    success:
      typeof settlement['success'] === 'boolean'
        ? (settlement['success'] as boolean)
        : Boolean(txHash),
    source: 'body',
  };
  if (txHash) rec.txHash = txHash;
  const network = str(settlement['network']);
  if (network) rec.network = network;
  return rec;
}

/** Read the first present header from a list of accepted spellings. */
export function pickHeader(
  headers: Headers | undefined,
  names: readonly string[],
): { name: string; value: string } | undefined {
  if (!headers) return undefined;
  for (const n of names) {
    const v = headers.get(n);
    if (v) return { name: n, value: v };
  }
  return undefined;
}

/** Model name requested, read from an OpenAI-compatible request body. */
export function extractRequestedModel(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  return str((body as Record<string, unknown>)['model']);
}

/**
 * Model name actually served.
 *
 * Checked in order of trustworthiness: an explicit router header beats the body,
 * because a substituting router is exactly the party whose body we are auditing.
 */
export function extractServedModel(
  body: unknown,
  headers: Headers | undefined,
): { model: string; source: string } | undefined {
  const headerNames = [
    'x-clawrouter-model',
    'x-clawrouter-served-model',
    'x-clawrouter-upstream-model',
    'x-served-model',
    'x-model',
  ];
  for (const n of headerNames) {
    const v = headers?.get(n);
    if (v) return { model: v, source: n };
  }
  if (body && typeof body === 'object') {
    const m = str((body as Record<string, unknown>)['model']);
    if (m) return { model: m, source: 'body.model' };
  }
  return undefined;
}

/** Token usage from an OpenAI-compatible response. Recorded only in `metadata` mode. */
export function extractUsage(
  body: unknown,
): { promptTokens?: number; completionTokens?: number; totalTokens?: number } | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const usage = (body as Record<string, unknown>)['usage'];
  if (!usage || typeof usage !== 'object') return undefined;
  const u = usage as Record<string, unknown>;
  const out: { promptTokens?: number; completionTokens?: number; totalTokens?: number } = {};
  const p = num(u['prompt_tokens'] ?? u['promptTokens'] ?? u['input_tokens']);
  const c = num(u['completion_tokens'] ?? u['completionTokens'] ?? u['output_tokens']);
  const t = num(u['total_tokens'] ?? u['totalTokens']);
  if (p !== undefined) out.promptTokens = p;
  if (c !== undefined) out.completionTokens = c;
  if (t !== undefined) out.totalTokens = t;
  return Object.keys(out).length > 0 ? out : undefined;
}
