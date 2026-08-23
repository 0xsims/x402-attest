import { createHash } from 'node:crypto';
import { MERKLE_PARAMS } from './merkle.js';
import { BATCH_SCHEMA_VERSION, type BatchEnvelope, type FetchLike } from './types.js';

/**
 * Rubric anchoring client.
 *
 * Deliberately a plain `fetch` client rather than a dependency on the Rubric SDK:
 * the SDK pulls a signing stack this library does not need (we anchor a root, we
 * do not custody keys), and a zero-dependency package is materially easier to
 * audit — which matters for something whose only product is auditability.
 */

/** The envelope submitted once per batch. Contains hashes and counts, never content. */
export type { BatchEnvelope };

export type AnchorResult = {
  attestationId: string;
  verifyUrl: string;
  /** Returned once by the tiered path. A credential — never placed in a receipt. */
  payloadKey?: string;
  /**
   * Commitment Rubric issued for the submitted payload.
   *
   * Not a secret, unlike `payloadKey`, and it is the only handle the public verify
   * endpoint gives back for the payload — so it goes into every receipt.
   */
  payloadCommitment?: string;
  payloadHash?: string;
  /**
   * Opening salt for the commitment, derived one-way from the payload key.
   * Safe to place in a receipt; the key it came from is not.
   */
  commitmentSalt?: string;
  /** Path actually taken, recorded so a receipt can be traced to how it was paid. */
  via: 'tiered' | 'direct' | 'x402';
  raw: unknown;
};

/**
 * Domain separator in Rubric's commitment salt derivation.
 * Confirmed against the server implementation, not guessed.
 */
export const COMMIT_DOMAIN = ':rubric-commit-v1';

/**
 * Derive the opening salt for a payload commitment.
 *
 * Rubric computes
 *   salt       = SHA-256(payloadKeyHex + ':rubric-commit-v1')
 *   commitment = SHA-256(salt + RFC8785(payload))
 *
 * The salt is a one-way function of the payload key, which is what makes this
 * safe to publish: a receipt can carry the salt, letting anyone recompute the
 * commitment from the envelope, while the AES key that decrypts the payload
 * stored at Rubric stays sealed. That is the opening the scheme was designed
 * for — "opening discloses {plaintext, salt} only".
 */
export function deriveCommitmentSalt(payloadKeyHex: string): string {
  return createHash('sha256').update(payloadKeyHex + COMMIT_DOMAIN).digest('hex');
}

/** Recompute a commitment from its salt and the canonical payload. */
export function computeCommitment(salt: string, canonicalPayload: string): string {
  return createHash('sha256').update(salt + canonicalPayload).digest('hex');
}

/** Read the commitment fields, tolerating both spellings seen in the wild. */
function commitmentOf(body: unknown): { payloadCommitment?: string; payloadHash?: string } {
  if (!body || typeof body !== 'object') return {};
  const o = body as Record<string, unknown>;
  const out: { payloadCommitment?: string; payloadHash?: string } = {};
  const c = o['payloadCommitment'] ?? o['payload_commitment'];
  const h = o['payloadHash'] ?? o['payload_hash'];
  if (typeof c === 'string' && c.length > 0) out.payloadCommitment = c;
  if (typeof h === 'string' && h.length > 0) out.payloadHash = h;
  return out;
}

export class AnchorError extends Error {
  readonly status?: number;
  readonly retryable: boolean;
  constructor(message: string, opts?: { status?: number; retryable?: boolean }) {
    super(message);
    this.name = 'AnchorError';
    this.status = opts?.status;
    // Default to retryable. Dropping a leaf because we misjudged an error as
    // permanent is the one failure this library must never have.
    this.retryable = opts?.retryable ?? true;
  }
}

export type AnchorClientOptions = {
  baseUrl: string;
  apiKey?: string;
  endpoint: 'tiered' | 'direct';
  subjectId: string;
  /** x402-capable fetch for the keyless path. MUST NOT be the attested wrapper. */
  anchorFetch?: FetchLike;
  /** Plain fetch for the keyed path. */
  httpFetch?: FetchLike;
  onPayloadKey?: (attestationId: string, key: string) => void;
};

export function verifyUrlFor(baseUrl: string, attestationId: string): string {
  return `${baseUrl.replace(/\/+$/, '')}/v1/verify/${encodeURIComponent(attestationId)}`;
}

export function buildEnvelope(input: {
  root: string;
  leafCount: number;
  firstCallId: string;
  lastCallId: string;
  from: string;
  to: string;
  subjectId: string;
  policyId?: string;
}): BatchEnvelope {
  const env: BatchEnvelope = {
    schemaVersion: BATCH_SCHEMA_VERSION,
    // Rubric's tiered endpoint does not accept a top-level `leafType`, so it
    // travels inside `data` where it stays part of the attested payload. The
    // direct endpoint takes it at the top level as well; see DEVIATIONS.md.
    leafType: 'DATA_RECORD',
    root: input.root,
    leafCount: input.leafCount,
    firstCallId: input.firstCallId,
    lastCallId: input.lastCallId,
    timeRange: { from: input.from, to: input.to },
    subjectId: input.subjectId,
    merkle: MERKLE_PARAMS,
  };
  if (input.policyId) env.policyId = input.policyId;
  return env;
}

async function readJson(res: Response): Promise<unknown> {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch {
    return { _nonJsonBody: text.slice(0, 512) };
  }
}

function pickAttestationId(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const o = body as Record<string, unknown>;
  const direct = o['attestationId'];
  if (typeof direct === 'string' && direct.length > 0) return direct;
  const nested = o['attestation'];
  if (nested && typeof nested === 'object') {
    const id = (nested as Record<string, unknown>)['attestationId'];
    if (typeof id === 'string' && id.length > 0) return id;
  }
  return undefined;
}

/**
 * 4xx other than 408/429 will not succeed on retry — a malformed envelope or a
 * revoked key is not a transient condition. Everything else keeps retrying.
 */
function isRetryableStatus(status: number): boolean {
  if (status === 408 || status === 429) return true;
  return status < 400 || status >= 500;
}

export class AnchorClient {
  private readonly opts: AnchorClientOptions;

  constructor(opts: AnchorClientOptions) {
    this.opts = opts;
    if (opts.endpoint === 'direct' && opts.apiKey) {
      // /v1/attest writes straight to HCS and bills HBAR on every call. Batching
      // makes this survivable, but it is still real money per flush, and the
      // endpoint is Enterprise-tier only.
      process.emitWarning(
        'x402-attest: anchorEndpoint "direct" uses POST /v1/attest, which is ' +
          'Enterprise-tier only and bills HBAR per attestation. The default ' +
          '"tiered" endpoint works on every tier including free Developer.',
        'RubricCostWarning',
      );
    }
  }

  async anchor(envelope: BatchEnvelope): Promise<AnchorResult> {
    return this.opts.apiKey ? this.anchorKeyed(envelope) : this.anchorKeyless(envelope);
  }

  /** API key present: sign-and-submit over plain HTTPS. */
  private async anchorKeyed(envelope: BatchEnvelope): Promise<AnchorResult> {
    const fetchImpl = this.opts.httpFetch ?? (globalThis.fetch as FetchLike);
    if (!fetchImpl) throw new AnchorError('no fetch implementation available');

    const path =
      this.opts.endpoint === 'direct' ? '/v1/attest' : '/v1/tiered-attest';
    const url = `${this.opts.baseUrl.replace(/\/+$/, '')}${path}`;

    const body =
      this.opts.endpoint === 'direct'
        ? {
            agentId: this.opts.subjectId,
            sourceId: this.opts.subjectId,
            leafType: 'DATA_RECORD' as const,
            data: envelope,
          }
        : { sourceId: this.opts.subjectId, data: envelope };

    let res: Response;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-api-key': this.opts.apiKey!,
        },
        body: JSON.stringify(body),
      });
    } catch (e) {
      throw new AnchorError(`anchor request failed: ${(e as Error).message}`, {
        retryable: true,
      });
    }

    const parsed = await readJson(res);
    if (!res.ok) {
      throw new AnchorError(`anchor rejected with HTTP ${res.status}`, {
        status: res.status,
        retryable: isRetryableStatus(res.status),
      });
    }

    const attestationId = pickAttestationId(parsed);
    if (!attestationId) {
      throw new AnchorError('anchor response contained no attestationId', {
        status: res.status,
      });
    }

    const payloadKey = (parsed as Record<string, unknown>)['payloadKey'];
    let commitmentSalt: string | undefined;
    if (typeof payloadKey === 'string' && payloadKey.length > 0) {
      this.opts.onPayloadKey?.(attestationId, payloadKey);
      commitmentSalt = deriveCommitmentSalt(payloadKey);
    }

    return {
      attestationId,
      verifyUrl: verifyUrlFor(this.opts.baseUrl, attestationId),
      ...commitmentOf(parsed),
      ...(commitmentSalt ? { commitmentSalt } : {}),
      via: this.opts.endpoint,
      raw: parsed,
    };
  }

  /**
   * No API key: pay for the attestation over x402.
   *
   * The attestation is bought the same way the calls it attests were bought, which
   * is the whole point — a buyer with a funded wallet and no Rubric relationship
   * still produces third-party-verifiable receipts.
   *
   * `anchorFetch` must be the raw x402 client, never the attested wrapper: wrapping
   * it would attest the attestation, which would need its own attestation.
   */
  private async anchorKeyless(envelope: BatchEnvelope): Promise<AnchorResult> {
    const fetchImpl = this.opts.anchorFetch;
    if (!fetchImpl) {
      throw new AnchorError(
        'keyless anchoring needs an x402-capable `anchorFetch`; pass one, set ' +
          '`rubricApiKey`, or use mode: "off"',
        { retryable: false },
      );
    }

    const url = `${this.opts.baseUrl.replace(/\/+$/, '')}/v1/x402/tiered-attest`;

    let res: Response;
    try {
      res = await fetchImpl(url, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ sourceId: this.opts.subjectId, data: envelope }),
      });
    } catch (e) {
      throw new AnchorError(`x402 anchor request failed: ${(e as Error).message}`, {
        retryable: true,
      });
    }

    const parsed = await readJson(res);

    if (res.status === 402) {
      // The x402 client could not complete payment — out of funds, no wallet, or
      // an unsupported scheme. Retryable: the wallet may be topped up.
      throw new AnchorError('x402 anchor unpaid: seller returned 402 after payment attempt', {
        status: 402,
        retryable: true,
      });
    }
    if (!res.ok) {
      throw new AnchorError(`x402 anchor rejected with HTTP ${res.status}`, {
        status: res.status,
        retryable: isRetryableStatus(res.status),
      });
    }

    const attestationId = pickAttestationId(parsed);
    if (!attestationId) {
      throw new AnchorError('x402 anchor response contained no attestationId', {
        status: res.status,
      });
    }

    const o = parsed as Record<string, unknown>;
    const payloadKey = o['payloadKey'];
    let commitmentSalt: string | undefined;
    if (typeof payloadKey === 'string' && payloadKey.length > 0) {
      this.opts.onPayloadKey?.(attestationId, payloadKey);
      commitmentSalt = deriveCommitmentSalt(payloadKey);
    }

    // Prefer the server-supplied verifyUrl when present; it is authoritative about
    // which node holds the record.
    const verifyUrl =
      typeof o['verifyUrl'] === 'string' && o['verifyUrl'].length > 0
        ? (o['verifyUrl'] as string)
        : verifyUrlFor(this.opts.baseUrl, attestationId);

    return {
      attestationId,
      verifyUrl,
      ...commitmentOf(parsed),
      ...(commitmentSalt ? { commitmentSalt } : {}),
      via: 'x402',
      raw: parsed,
    };
  }
}

/** Jittered exponential backoff: 1s, 2s, 4s ... capped, with full jitter. */
export function backoffDelay(
  attempt: number,
  minMs: number,
  maxMs: number,
  rand: () => number = Math.random,
): number {
  const exp = Math.min(maxMs, minMs * 2 ** Math.max(0, attempt - 1));
  // Full jitter. Synchronized retries from a fleet of agents after a Rubric
  // outage would otherwise arrive as one thundering herd.
  return Math.floor(exp / 2 + rand() * (exp / 2));
}
