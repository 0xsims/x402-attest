/**
 * Wire types for @tempus1/x402-attest.
 *
 * Everything in this file is part of the evidence format. Changing the shape of
 * `CallRecord` changes every leaf hash ever produced, so `v` is pinned and any
 * structural change requires a version bump plus a migration note in the README.
 */

/** Schema version embedded in each leaf. Bump on any `CallRecord` shape change. */
export const CALL_RECORD_VERSION = 1 as const;

/** Identifier for the batch envelope submitted to Rubric. */
export const BATCH_SCHEMA_VERSION = 'rubric.x402-attest/v1' as const;

export type Outcome =
  | 'ok'
  | 'http_error'
  | 'payment_failed'
  | 'timeout'
  | 'policy_violation';

export type AssertionResult = 'pass' | 'fail' | 'unknown';

/**
 * A check that was performed at call time.
 *
 * `unknown` is a first-class result: it records that the check was attempted and
 * the inputs were not discoverable. Omitting an assertion and asserting `unknown`
 * mean different things to an auditor, so we never omit.
 */
export type Assertion = {
  id: AssertionId;
  result: AssertionResult;
  observed?: string;
  expected?: string;
  /** Why the result is `unknown`, or why a comparison failed. Never contains body content. */
  detail?: string;
};

export type AssertionId =
  | 'price_matches_challenge'
  | 'payto_matches_challenge'
  | 'network_allowed'
  | 'payto_allowed'
  | 'price_within_policy'
  | 'budget_within_cap'
  | 'settled'
  | 'model_matches_request';

/** The full, ordered set of assertions computed for every call. */
export const REQUIRED_ASSERTIONS: readonly AssertionId[] = [
  'price_matches_challenge',
  'payto_matches_challenge',
  'network_allowed',
  'payto_allowed',
  'price_within_policy',
  'budget_within_cap',
  'settled',
  'model_matches_request',
] as const;

export type ChallengeRecord = {
  scheme: string;
  network: string;
  maxAmountRequired: string;
  payTo: string;
  asset: string;
  resource?: string;
  maxTimeoutSeconds?: number;
  /** sha256 of the canonical bytes of the full challenge body/header. */
  rawHash: string;
};

export type PaymentRecord = {
  scheme: string;
  network: string;
  amountAuthorized: string;
  asset: string;
  payTo: string;
  /**
   * sha256 of the payment authorization header ONLY.
   *
   * The header itself is a signed, replayable authorization. It is a bearer
   * secret and is never stored, logged, or transmitted by this library.
   */
  xPaymentHash: string;
};

export type SettlementRecord = {
  txHash?: string;
  network?: string;
  success: boolean;
  source: 'x-payment-response' | 'body' | 'none';
};

export type RequestRecord = {
  method: string;
  host: string;
  path: string;
  /** Hashed, not stored: query strings routinely carry API keys and PII. */
  queryHash?: string;
  bodyHash: string;
  bodyBytes: number;
  contentType?: string;
};

export type ResponseRecord = {
  status: number;
  bodyHash: string;
  bodyBytes: number;
  /** Allowlisted headers only. See `HEADER_ALLOWLIST`. */
  headers: Record<string, string>;
  /**
   * Model actually served. Present in clear only under `redact: 'metadata'`;
   * under the default `hash-only` this is omitted and the model comparison is
   * still recorded via the `model_matches_request` assertion.
   */
  servedModel?: string;
  /** Token counts, present only under `redact: 'metadata'`. */
  usage?: { promptTokens?: number; completionTokens?: number; totalTokens?: number };
};

export type CallRecord = {
  v: typeof CALL_RECORD_VERSION;
  /** UUIDv7 — time-ordered, so leaves sort monotonically without a separate index. */
  callId: string;
  subjectId: string;
  policyId?: string;
  sessionId?: string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  request: RequestRecord;
  challenge?: ChallengeRecord;
  payment?: PaymentRecord;
  settlement?: SettlementRecord;
  response: ResponseRecord;
  outcome: Outcome;
  assertions: Assertion[];
};

export type ProofStep = { hash: string; side: 'left' | 'right' };

/**
 * The exact payload submitted to Rubric for a batch.
 *
 * Carried in every receipt because Rubric does not give it back. Tiered payloads
 * are encrypted at rest and `/v1/verify` returns only a commitment to them, so a
 * verifier that does not hold the envelope has nothing to bind the root to.
 */
export type BatchEnvelope = {
  schemaVersion: typeof BATCH_SCHEMA_VERSION;
  leafType: 'DATA_RECORD';
  root: string;
  leafCount: number;
  firstCallId: string;
  lastCallId: string;
  timeRange: { from: string; to: string };
  subjectId: string;
  policyId?: string;
  merkle: {
    hash: string;
    leafPrefix: string;
    nodePrefix: string;
    oddNode: string;
  };
};

/**
 * The payment block Rubric's keyless route injects into the payload before it
 * commits to it.
 *
 * Observed on the live node (DEVIATIONS §21):
 *
 *   { x402Version, scheme, network, asset, amountAtomic, payer }
 *
 * Deliberately not narrowed to that shape. This is committed bytes: it is
 * carried verbatim and never interpreted, so a field the server adds later still
 * canonicalises to what it committed to instead of being silently dropped.
 */
export type X402PaymentMember = Record<string, unknown>;

/**
 * The envelope as committed, which is not always the envelope as submitted.
 *
 * `BatchEnvelope` is what goes over the wire. Rubric's keyless route commits to
 * that plus an `x402Payment` member it injects server-side, so a receipt has to
 * record the extended form or it cannot open its own commitment. `root` is
 * identical in both — the injected member sits alongside it and never touches
 * it, which is what keeps `envelope.root` a valid check on the proof chain.
 */
export type RecordedEnvelope = BatchEnvelope & { x402Payment?: X402PaymentMember };

export type Receipt = {
  callRecord: CallRecord;
  leafHash: string;
  proof: ProofStep[];
  root: string;
  attestationId: string;
  /**
   * The link to hand a person. Rubric's keyless path returns `/audit/{id}`, a
   * rendered HTML page — readable, but not something a verifier can parse.
   */
  verifyUrl: string;
  /**
   * The JSON endpoint a verifier calls, `/v1/verify/{id}`.
   *
   * Optional because receipts written before 0.1.1 do not carry it;
   * `verifyReceipt` derives it from `verifyUrl`'s origin in that case.
   */
  verifyApiUrl?: string;
  /**
   * The batch payload this leaf's root was submitted in, as the anchor
   * committed to it — including anything the server injected. See
   * `RecordedEnvelope`; this is the preimage `commitmentSalt` opens.
   */
  envelope: RecordedEnvelope;
  /**
   * Commitment Rubric issued for `envelope` at submission, echoed by the public
   * verify endpoint. This is what binds a receipt to the anchored attestation.
   */
  payloadCommitment?: string;
  /** Hash Rubric reported for the submitted payload, when it supplies one. */
  payloadHash?: string;
  /**
   * Opening salt for `payloadCommitment`, one-way derived from the payload key.
   *
   * Publishing this is what makes a receipt independently verifiable: anyone can
   * recompute SHA-256(salt + jcs(envelope)) and compare it to the commitment the
   * public verify endpoint holds. The AES key it was derived from is never in a
   * receipt — the salt discloses the opening, not the key.
   */
  commitmentSalt?: string;
};

/** A receipt that exists locally but whose batch has not been anchored yet. */
export type PendingReceipt = {
  callRecord: CallRecord;
  leafHash: string;
  proof: null;
  root: null;
  attestationId: null;
  verifyUrl: null;
  verifyApiUrl?: undefined;
  envelope: null;
  payloadCommitment?: undefined;
  payloadHash?: undefined;
  commitmentSalt?: undefined;
};

export type AnyReceipt = Receipt | PendingReceipt;

export function isAnchored(r: AnyReceipt): r is Receipt {
  return r.attestationId !== null;
}

export type Policy = {
  /** USD, decimal string. Compared against the authorized amount converted to USD. */
  maxPricePerCall?: string;
  /** CAIP-2 network ids, e.g. `eip155:8453`. */
  allowedNetworks?: string[];
  allowedPayTo?: string[];
  /** USD, decimal string. Cumulative across the session. */
  budgetCap?: string;
};

export type RedactMode = 'hash-only' | 'metadata';
export type RedactFn = (rec: CallRecord) => CallRecord;
export type Redact = RedactMode | RedactFn;

export type BatchOptions = {
  maxLeaves?: number;
  maxAgeMs?: number;
};

export type AnchorMode = 'batch' | 'immediate' | 'off';

/**
 * Durability policy for the write-ahead log.
 *
 * `always` (default) — fdatasync every leaf before the wrapper returns. Survives
 *   power loss. Costs one durable write per call: roughly 1-2ms on virtualized
 *   cloud storage, and it is the dominant term in the wrapper's added latency.
 * `interval` — write(2) every leaf before returning, fdatasync at most every
 *   `fsyncIntervalMs`. A leaf is in the kernel page cache the moment the wrapper
 *   returns, so it survives a process crash, an uncaught exception or a SIGKILL —
 *   which is what actually happens to agents. It does NOT survive power loss or a
 *   kernel panic within the interval.
 * `off` — write(2) only; fdatasync on flush and close.
 *
 * The default is `always` because the library's product is evidence. Operators on
 * slow storage who need the sub-5ms p99 more than they need power-loss durability
 * can make that trade knowingly; the library will not make it for them.
 */
export type WalFsyncPolicy = 'always' | 'interval' | 'off';

export type WalOptions = {
  fsync?: WalFsyncPolicy;
  fsyncIntervalMs?: number;
};

/**
 * How response bodies are read.
 *
 * `buffer` — read the body, hash it, hand the caller a reconstructed Response.
 *   The leaf is complete and durable before the wrapper returns, which is what
 *   makes the crash guarantee meaningful. Costs one extra pass over the body, and
 *   the reconstructed Response loses `url` and `redirected`.
 * `passthrough` — pipe the body through a hashing transform so bytes reach the
 *   caller unbuffered. The leaf lands when the stream ends; `close()` finalizes
 *   anything still open and attests it as incomplete.
 *
 * The default picks `passthrough` for `text/event-stream` and `buffer` otherwise:
 * buffering an SSE stream would defeat the point of streaming it.
 */
export type CaptureOptions = {
  stream?: 'buffer' | 'passthrough';
};

/**
 * Which Rubric endpoint the keyed path uses.
 *
 * `tiered` → POST /v1/tiered-attest. Works on every tier including free Developer.
 * `direct` → POST /v1/attest. Enterprise-only and bills HBAR per call; opt-in only.
 */
export type AnchorEndpoint = 'tiered' | 'direct';

export type AttestOptions = {
  subjectId: string;
  rubricApiKey?: string;
  policyId?: string;
  sessionId?: string;
  mode?: AnchorMode;
  batch?: BatchOptions;
  redact?: Redact;
  policy?: Policy;
  walPath?: string;
  onReceipt?: (r: AnyReceipt) => void;
  /** Called when anchoring fails. Purely informational; the batch is retried regardless. */
  onAnchorError?: (err: Error, attempt: number) => void;

  /** Base URL for the Rubric API. */
  rubricBaseUrl?: string;
  /** Endpoint for the keyed path. Defaults to `tiered` — `direct` bills HBAR per call. */
  anchorEndpoint?: AnchorEndpoint;
  /**
   * Fetch used to reach Rubric on the keyless (x402-paid) path. MUST be the
   * unwrapped x402 client, otherwise anchoring calls attest themselves forever.
   */
  anchorFetch?: FetchLike;
  /** Plain fetch used for the keyed path. Defaults to global fetch. */
  httpFetch?: FetchLike;

  /** Transport tap that observes the raw 402 and the payment header. See `createTap()`. */
  tap?: X402Tap;

  /** Decimals per asset symbol/address, for converting atomic amounts to USD. */
  assetDecimals?: Record<string, number>;
  /** Default decimals when the asset is unknown. USDC-shaped. */
  defaultAssetDecimals?: number;

  /** Install SIGINT/SIGTERM drain handlers. Disable in tests and in embedded use. */
  installSignalHandlers?: boolean;
  /** Drain budget for signal-triggered flushes. */
  drainTimeoutMs?: number;

  /** Retry backoff bounds for anchoring. */
  retry?: { minDelayMs?: number; maxDelayMs?: number };

  /** Write-ahead log durability policy. Defaults to fdatasync per leaf. */
  wal?: WalOptions;

  /** How response bodies are read. See `CaptureOptions`. */
  capture?: CaptureOptions;

  /** Injected clock, for deterministic tests. */
  now?: () => number;
  /** Injected sleep, for deterministic tests. */
  sleep?: (ms: number) => Promise<void>;
};

export type ResolvedOptions = Required<
  Pick<
    AttestOptions,
    | 'subjectId'
    | 'mode'
    | 'walPath'
    | 'rubricBaseUrl'
    | 'anchorEndpoint'
    | 'defaultAssetDecimals'
    | 'installSignalHandlers'
    | 'drainTimeoutMs'
    | 'now'
    | 'sleep'
  >
> & {
  batch: Required<BatchOptions>;
  retry: Required<NonNullable<AttestOptions['retry']>>;
  wal: Required<WalOptions>;
  policy: Policy;
  redact: Redact;
  assetDecimals: Record<string, number>;
} & Omit<
    AttestOptions,
    | 'subjectId'
    | 'mode'
    | 'walPath'
    | 'rubricBaseUrl'
    | 'anchorEndpoint'
    | 'defaultAssetDecimals'
    | 'installSignalHandlers'
    | 'drainTimeoutMs'
    | 'now'
    | 'sleep'
    | 'batch'
    | 'retry'
    | 'policy'
    | 'redact'
    | 'assetDecimals'
    | 'wal'
  >;

export type FetchLike = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

/**
 * Transport-level observer.
 *
 * `withAttestation` wraps an x402 client that handles the 402 → pay → retry loop
 * internally, so from the outside only the final 200 is visible. Installing a tap
 * underneath that client is what makes `challenge`, `payment` and therefore the
 * price/payTo assertions observable rather than `unknown`.
 */
export type X402Tap = {
  /** Wrap the fetch you hand to your x402 client. */
  wrapFetch: (inner: FetchLike) => FetchLike;
  /** Internal: begin a correlation scope for one logical call. */
  __run: <T>(fn: () => Promise<T>) => Promise<T>;
  /** Internal: observations collected during the current scope. */
  __take: () => TapObservation;
};

export type TapObservation = {
  challengeBody?: unknown;
  /**
   * Bytes to hash for `challenge.rawHash` — the header value when one was served,
   * otherwise the raw 402 body text.
   */
  challengeRaw?: string;
  /**
   * The challenge as delivered in a header, decoded out of its envelope but not
   * yet base64-decoded.
   *
   * Kept separate from `challengeRaw` because sellers serve both a header and a
   * body: BlockRun answers a 402 with `PAYMENT-REQUIRED`, `X-PAYMENT-REQUIRED`
   * and `WWW-Authenticate` *and* a human-readable JSON error body. With one
   * field for both, the call site cannot tell which it is holding, and picking
   * the body loses `accepts` entirely — which is how a correct payment came to
   * be recorded with a USD-formatted price and no payee.
   */
  challengeHeader?: string;
  paymentHeader?: string;
  paymentHeaderName?: string;
  settlementHeader?: string;
  attempts: number;
};

export type ExportFormat = 'jsonl' | 'csv';

export type ExportOptions = {
  format?: ExportFormat;
  /** ISO 8601 or epoch ms. Inclusive lower bound on `startedAt`. */
  from?: string | number | Date;
  /** ISO 8601 or epoch ms. Inclusive upper bound on `startedAt`. */
  to?: string | number | Date;
};

/**
 * Response headers captured verbatim. Never widen this to a wildcard: response
 * headers are where sellers leak set-cookie, authorization echoes and rate-limit
 * identifiers, none of which belong in a durable audit record.
 */
export const HEADER_ALLOWLIST: readonly string[] = [
  'x-payment-response',
  'payment-response',
  'x-request-id',
  'content-type',
  'server-timing',
] as const;

/** Prefixes captured verbatim (ClawRouter routing headers). */
export const HEADER_ALLOWLIST_PREFIXES: readonly string[] = ['x-clawrouter-'] as const;
