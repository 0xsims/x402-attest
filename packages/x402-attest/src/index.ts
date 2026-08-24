import { ZERO, addDecimal, formatDecimal, type Decimal } from './decimal.js';
import { EMPTY_SHA256, sha256, sha256Jcs, uuidv7 } from './hash.js';
import { AnchorClient } from './anchor.js';
import { Batcher, type FlushResult } from './batcher.js';
import { amountToUsd, computeAssertions } from './assertions.js';
import { applyRedaction } from './redact.js';
import {
  buildRequestRecord,
  buildResponseRecord,
  captureRequestBody,
  tryJson,
  type CapturedBody,
} from './record.js';
import { createTap } from './tap.js';
import { Wal, type LeafEntry } from './wal.js';
import {
  CALL_RECORD_VERSION,
  type AnyReceipt,
  type AttestOptions,
  type CallRecord,
  type ExportOptions,
  type FetchLike,
  type Outcome,
  type PaymentRecord,
  type ResolvedOptions,
  type SettlementRecord,
  type TapObservation,
} from './types.js';
import {
  SETTLEMENT_HEADERS,
  extractRequestedModel,
  extractServedModel,
  extractUsage,
  parseChallenge,
  parsePaymentHeader,
  parseSettlementBody,
  parseSettlementHeader,
  pickChallengeHeader,
  pickHeader,
} from './x402.js';
import { toCsv, toJsonl } from './exporter.js';

export const DEFAULT_RUBRIC_BASE_URL = 'https://rubric-protocol.com';

/** Statuses that must not carry a body; constructing one with bytes throws. */
const NULL_BODY_STATUS = new Set([101, 103, 204, 205, 304]);

/** Body hash placeholder for a call whose response never completed. */
export const INCOMPLETE_BODY = 'incomplete:crash';

function resolveOptions(options: AttestOptions): ResolvedOptions {
  if (!options?.subjectId) {
    throw new TypeError('withAttestation requires a subjectId: an audit record needs a subject');
  }
  return {
    ...options,
    subjectId: options.subjectId,
    mode: options.mode ?? 'batch',
    walPath: options.walPath ?? './.rubric-wal',
    rubricBaseUrl: options.rubricBaseUrl ?? DEFAULT_RUBRIC_BASE_URL,
    anchorEndpoint: options.anchorEndpoint ?? 'tiered',
    defaultAssetDecimals: options.defaultAssetDecimals ?? 6,
    installSignalHandlers: options.installSignalHandlers ?? true,
    drainTimeoutMs: options.drainTimeoutMs ?? 5_000,
    now: options.now ?? Date.now,
    sleep: options.sleep ?? ((ms) => new Promise((r) => setTimeout(r, ms))),
    batch: {
      maxLeaves: options.batch?.maxLeaves ?? 256,
      maxAgeMs: options.batch?.maxAgeMs ?? 60_000,
    },
    retry: {
      minDelayMs: options.retry?.minDelayMs ?? 1_000,
      maxDelayMs: options.retry?.maxDelayMs ?? 60_000,
    },
    wal: {
      fsync: options.wal?.fsync ?? 'always',
      fsyncIntervalMs: options.wal?.fsyncIntervalMs ?? 250,
    },
    policy: options.policy ?? {},
    redact: options.redact ?? 'hash-only',
    assetDecimals: normalizeAssetDecimals(options.assetDecimals),
  };
}

function normalizeAssetDecimals(input?: Record<string, number>): Record<string, number> {
  const out: Record<string, number> = {};
  for (const [k, v] of Object.entries(input ?? {})) out[k.trim().toLowerCase()] = v;
  return out;
}

export type AttestedFetch<F extends FetchLike = FetchLike> = F & {
  /** Cut the current batch and attempt to anchor it once. */
  flush: () => Promise<FlushResult[]>;
  /** Drain, stop timers, close the WAL. Idempotent. */
  close: () => Promise<FlushResult[]>;
  getReceipt: (callId: string) => AnyReceipt | undefined;
  exportReceipts: (opts?: ExportOptions) => string;
  /** Escape hatch for tests and diagnostics. */
  readonly attestor: Attestor;
};

/** Every attestor created in this process, for the module-level helpers and signals. */
const REGISTRY = new Set<Attestor>();

const SIGNALS: NodeJS.Signals[] = ['SIGINT', 'SIGTERM'];
const installedHandlers = new Map<NodeJS.Signals, () => void>();

/**
 * SIGINT/SIGTERM drain, installed once per process rather than once per attestor.
 *
 * Drains every live attestor, then re-raises the signal so a Ctrl-C still stops
 * the process — a library that swallows SIGINT is a library people rip out. If the
 * drain overruns `drainTimeoutMs` we let the signal through anyway: the WAL is
 * already durable, so giving up costs a retry on next start, not evidence.
 *
 * Per-attestor handlers would each re-raise, so a process with three attestors
 * would deliver the signal to itself three times.
 */
function installSignalHandlers(): void {
  if (installedHandlers.size > 0) return;
  for (const signal of SIGNALS) {
    const handler = (): void => {
      void close().finally(() => {
        removeSignalHandlers();
        process.kill(process.pid, signal);
      });
    };
    installedHandlers.set(signal, handler);
    process.once(signal, handler);
  }
}

function removeSignalHandlers(): void {
  for (const [signal, handler] of installedHandlers) {
    process.removeListener(signal, handler);
  }
  installedHandlers.clear();
}

export class Attestor {
  readonly opts: ResolvedOptions;
  readonly wal: Wal;
  readonly batcher: Batcher;

  private sessionSpend: Decimal = ZERO;
  private closed = false;
  /** Calls whose response body is still streaming, keyed by callId. */
  private open = new Map<string, () => void>();
  /** Leaves recovered from a previous process that never completed. */
  readonly recovered: { leaves: number; corrupt: number };

  constructor(options: AttestOptions) {
    this.opts = resolveOptions(options);
    this.wal = new Wal(this.opts.walPath, this.opts.wal);

    const client = new AnchorClient({
      baseUrl: this.opts.rubricBaseUrl,
      apiKey: this.opts.rubricApiKey,
      endpoint: this.opts.anchorEndpoint,
      subjectId: this.opts.subjectId,
      anchorFetch: this.opts.anchorFetch,
      httpFetch: this.opts.httpFetch,
      onPayloadKey: (id, key) => this.wal.appendPayloadKey(id, key, this.opts.now()),
    });

    this.batcher = new Batcher(this.opts, this.wal, client);

    // Recovery runs at construction, before the first call: a restart must pick up
    // where the crash left off, not start a fresh log alongside the old one.
    const replay = this.wal.replay();
    this.batcher.adoptAnchors(replay.anchors, replay.leaves);
    this.batcher.adoptRecovered(replay.unanchored);
    this.recovered = { leaves: replay.unanchored.length, corrupt: replay.corrupt.length };

    // Rebuild session spend so a budget cap survives a restart. A cap that resets
    // on crash is not a cap.
    for (const leaf of replay.leaves) {
      if (leaf.record.sessionId && leaf.record.sessionId === this.opts.sessionId) {
        const usd = amountToUsd(
          leaf.record.payment?.amountAuthorized ?? leaf.record.challenge?.maxAmountRequired,
          leaf.record.payment?.asset ?? leaf.record.challenge?.asset,
          this.assertionCtxBase(),
        );
        if (usd) this.sessionSpend = addDecimal(this.sessionSpend, usd);
      }
    }

    REGISTRY.add(this);
    if (this.opts.installSignalHandlers) installSignalHandlers();
  }

  private assertionCtxBase() {
    return {
      policy: this.opts.policy,
      sessionSpendBefore: this.sessionSpend,
      assetDecimals: this.opts.assetDecimals,
      defaultAssetDecimals: this.opts.defaultAssetDecimals,
      redact: this.opts.redact,
    };
  }

  /** Cumulative session spend in USD, as a decimal string. */
  get spendUsd(): string {
    return formatDecimal(this.sessionSpend);
  }

  /**
   * Persist a completed leaf and hand it to the batcher.
   *
   * The fsync happens here, synchronously, before the caller can observe the
   * response. Everything after this line is best-effort; everything up to it is
   * durable.
   */
  private commitLeaf(record: CallRecord): LeafEntry {
    const redacted = applyRedaction(record, this.opts.redact);
    const leafHash = sha256Jcs(redacted);
    const entry: LeafEntry = {
      type: 'leaf',
      callId: redacted.callId,
      leafHash,
      at: this.opts.now(),
      record: redacted,
    };
    this.wal.appendLeaf(entry);
    this.batcher.add(entry);
    this.batcher.emitPending(redacted.callId);
    return entry;
  }

  /** Cumulative session spend before the current call, for the budget assertion. */
  get spendBefore(): Decimal {
    return this.sessionSpend;
  }

  addSpend(usd: Decimal): void {
    this.sessionSpend = addDecimal(this.sessionSpend, usd);
  }

  registerOpen(callId: string, finalize: () => void): void {
    this.open.set(callId, finalize);
  }

  resolveOpen(callId: string): void {
    this.open.delete(callId);
  }

  commit(record: CallRecord): LeafEntry {
    return this.commitLeaf(record);
  }

  async flush(): Promise<FlushResult[]> {
    return this.batcher.flush();
  }

  getReceipt(callId: string): AnyReceipt | undefined {
    return this.batcher.getReceipt(callId);
  }

  exportReceipts(opts: ExportOptions = {}): string {
    const receipts = this.batcher.allReceipts();
    return (opts.format ?? 'jsonl') === 'csv' ? toCsv(receipts, opts) : toJsonl(receipts, opts);
  }

  async close(): Promise<FlushResult[]> {
    if (this.closed) return [];
    // Streams still in flight would otherwise never produce a leaf. Attesting them
    // as incomplete is the point: a call we started and cannot account for is
    // exactly the record an auditor wants to see.
    for (const finalize of [...this.open.values()]) {
      try {
        finalize();
      } catch {
        /* finalization is best-effort at shutdown */
      }
    }
    this.open.clear();

    const results = await this.batcher.close();
    this.wal.close();
    this.closed = true;
    REGISTRY.delete(this);
    if (REGISTRY.size === 0) removeSignalHandlers();
    return results;
  }
}

/**
 * Wrap an x402 payment client so every paid call produces a verifiable receipt.
 *
 * The returned function has the same signature as the one passed in — swapping it
 * in is one changed line — and never rejects for attestation reasons. If this
 * library has a bug, the caller's request still goes through and still returns.
 */
export function withAttestation<F extends FetchLike>(
  baseFetch: F,
  options: AttestOptions,
): AttestedFetch<F> {
  const attestor = new Attestor(options);
  const opts = attestor.opts;
  const tap = opts.tap;

  const wrapped = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    const startedAtMs = opts.now();
    const callId = uuidv7(opts.now);
    const startedAt = new Date(startedAtMs).toISOString();

    let reqBody: CapturedBody;
    try {
      reqBody = await captureRequestBody(input, init);
    } catch {
      reqBody = { bytes: null, hash: EMPTY_SHA256, length: 0 };
    }

    let res: Response | undefined;
    let thrown: unknown;
    let obs: TapObservation = { attempts: 0 };

    const exec = async (): Promise<void> => {
      try {
        res = await baseFetch(input, init);
      } catch (e) {
        thrown = e;
      }
      if (tap) obs = tap.__take();
    };

    // The one and only await on the request path. Everything after it is bounded
    // local work: hashing, JCS, one fsync.
    await (tap ? tap.__run(exec) : exec());

    const finishRecord = (resBody: CapturedBody, incomplete: boolean): void => {
      try {
        const endedAtMs = opts.now();
        const record = assembleRecord({
          attestor,
          callId,
          startedAt,
          startedAtMs,
          endedAtMs,
          input,
          init,
          reqBody,
          res,
          resBody,
          thrown,
          obs,
          incomplete,
        });
        attestor.commit(record);
      } catch {
        // An attestation bug must never surface as a failed HTTP call. The WAL
        // simply has no line for this call, which the batch leaf count will show.
      } finally {
        attestor.resolveOpen(callId);
      }
    };

    if (!res || !isResponseLike(res)) {
      // Transport failure, or a client that does not return a Response. Both are
      // attestable: a call that never completed is evidence too.
      finishRecord({ bytes: new Uint8Array(0), hash: EMPTY_SHA256, length: 0 }, false);
      if (thrown) throw thrown;
      return res as unknown as Response;
    }

    const passthrough = shouldStream(opts, res);

    if (!passthrough) {
      // Buffer-and-reconstruct. Reading the body here is what lets the leaf be
      // complete and fsynced before we return, which is the durability guarantee
      // the spec asks for. The cost is that the response is materialized.
      let bytes: Uint8Array;
      try {
        bytes = new Uint8Array(await res.arrayBuffer());
      } catch {
        bytes = new Uint8Array(0);
      }
      finishRecord({ bytes, hash: sha256(bytes), length: bytes.byteLength }, false);
      return rebuildResponse(res, bytes);
    }

    // Streaming: hash as the bytes flow to the caller so we never buffer an SSE
    // stream or delay first-token latency. The leaf is written when the stream
    // ends. A caller that abandons the stream never triggers `flush`, so close()
    // finalizes whatever is still open and attests it as incomplete.
    return streamAndAttest(res, callId, attestor, finishRecord);
  };

  const attested = wrapped as AttestedFetch<F>;
  Object.defineProperties(attested, {
    flush: { value: () => attestor.flush(), enumerable: false },
    close: { value: () => attestor.close(), enumerable: false },
    getReceipt: { value: (id: string) => attestor.getReceipt(id), enumerable: false },
    exportReceipts: {
      value: (o?: ExportOptions) => attestor.exportReceipts(o),
      enumerable: false,
    },
    attestor: { value: attestor, enumerable: false },
  });
  return attested;
}

function isResponseLike(v: unknown): v is Response {
  return (
    !!v &&
    typeof v === 'object' &&
    typeof (v as Response).arrayBuffer === 'function' &&
    typeof (v as Response).status === 'number'
  );
}

function shouldStream(opts: ResolvedOptions, res: Response): boolean {
  const mode = opts.capture?.stream;
  if (mode === 'passthrough') return true;
  if (mode === 'buffer') return false;
  // Default: buffer, except for server-sent events, where materializing the body
  // would defeat the purpose of streaming and stall the caller.
  return (res.headers?.get('content-type') ?? '').includes('text/event-stream');
}

function rebuildResponse(res: Response, bytes: Uint8Array): Response {
  const body = NULL_BODY_STATUS.has(res.status) || bytes.byteLength === 0 ? null : bytes;
  try {
    return new Response(body, {
      status: res.status,
      statusText: res.statusText,
      headers: res.headers,
    });
  } catch {
    // Some statuses reject a reconstructed Response entirely; hand back the
    // original rather than fail the caller's request.
    return res;
  }
}

function streamAndAttest(
  res: Response,
  callId: string,
  attestor: Attestor,
  finish: (body: CapturedBody, incomplete: boolean) => void,
): Response {
  const chunks: Uint8Array[] = [];
  let length = 0;
  let done = false;

  const finalize = (incomplete: boolean): void => {
    if (done) return;
    done = true;
    const joined = Buffer.concat(chunks.map((c) => Buffer.from(c)));
    finish(
      incomplete
        ? { bytes: null, hash: INCOMPLETE_BODY, length }
        : { bytes: joined, hash: sha256(joined), length },
      incomplete,
    );
  };

  attestor.registerOpen(callId, () => finalize(true));

  if (!res.body) {
    finalize(false);
    return res;
  }

  const transform = new TransformStream<Uint8Array, Uint8Array>({
    transform(chunk, controller) {
      chunks.push(chunk);
      length += chunk.byteLength;
      controller.enqueue(chunk);
    },
    flush() {
      finalize(false);
    },
  });

  return new Response(res.body.pipeThrough(transform), {
    status: res.status,
    statusText: res.statusText,
    headers: res.headers,
  });
}

/** Assemble the full call record from every observation we managed to make. */
function assembleRecord(args: {
  attestor: Attestor;
  callId: string;
  startedAt: string;
  startedAtMs: number;
  endedAtMs: number;
  input: string | URL | Request;
  init?: RequestInit;
  reqBody: CapturedBody;
  res?: Response;
  resBody: CapturedBody;
  thrown: unknown;
  obs: TapObservation;
  incomplete: boolean;
}): CallRecord {
  const { attestor, obs, res } = args;
  const opts = attestor.opts;

  const requestRec = buildRequestRecord(args.input, args.init, args.reqBody);
  const responseRec = buildResponseRecord(res?.status ?? 0, res?.headers, args.resBody);

  const reqJson = tryJson(args.reqBody.bytes);
  const resJson = tryJson(args.resBody.bytes);

  // Payment first: which option the client actually paid disambiguates a
  // multi-option challenge.
  const payment: PaymentRecord | undefined = obs.paymentHeader
    ? parsePaymentHeader(obs.paymentHeader)
    : undefined;

  // The header is passed unconditionally. `parseChallenge` prefers a decodable
  // header over the body, and that precedence is right whether or not a body is
  // also present: sellers serve both, and the body is a human-readable error
  // ("price": "0.002000" USD) while the header is the machine-readable
  // requirements ("amount": "2000" atomic). Making the header conditional on the
  // body's absence — as this once did — silently substituted the former for the
  // latter and failed `price_matches_challenge` on correct payments.
  //
  // Without a tap the 402 is only visible when it is the final response, but
  // then its headers are right here — read them the same way, so the no-tap path
  // does not fall back to the body for a reason the tapped path no longer does.
  const challengeHeader =
    obs.challengeHeader ??
    (res?.status === 402 ? pickChallengeHeader(res.headers) : undefined);

  const parsedChallenge = parseChallenge(
    {
      body: obs.challengeBody ?? (res?.status === 402 ? resJson : undefined),
      headerValue: challengeHeader,
      rawBytes: obs.challengeRaw ?? challengeHeader,
    },
    payment ? { scheme: payment.scheme, network: payment.network } : undefined,
  );

  const settlementHeader =
    obs.settlementHeader ?? pickHeader(res?.headers, SETTLEMENT_HEADERS)?.value;
  const settlement: SettlementRecord | undefined =
    (settlementHeader ? parseSettlementHeader(settlementHeader) : undefined) ??
    parseSettlementBody(resJson);

  const requestedModel = extractRequestedModel(reqJson);
  const served = extractServedModel(resJson, res?.headers);

  if (served && opts.redact === 'metadata') {
    responseRec.servedModel = served.model;
    const usage = extractUsage(resJson);
    if (usage) responseRec.usage = usage;
  }

  const assertionResult = computeAssertions({
    policy: opts.policy,
    challenge: parsedChallenge?.record,
    payment,
    settlement,
    requestedModel,
    servedModel: served?.model,
    servedModelSource: served?.source,
    sessionSpendBefore: attestor.spendBefore,
    assetDecimals: opts.assetDecimals,
    defaultAssetDecimals: opts.defaultAssetDecimals,
    redact: opts.redact,
  });

  attestor.addSpend(assertionResult.spendUsd);

  const record: CallRecord = {
    v: CALL_RECORD_VERSION,
    callId: args.callId,
    subjectId: opts.subjectId,
    startedAt: args.startedAt,
    endedAt: new Date(args.endedAtMs).toISOString(),
    durationMs: Math.max(0, args.endedAtMs - args.startedAtMs),
    request: requestRec,
    response: responseRec,
    outcome: decideOutcome({
      anyFailed: assertionResult.anyFailed,
      thrown: args.thrown,
      incomplete: args.incomplete,
      status: res?.status,
      settlement,
      hadPayment: !!payment,
    }),
    assertions: assertionResult.assertions,
  };

  if (opts.policyId) record.policyId = opts.policyId;
  if (opts.sessionId) record.sessionId = opts.sessionId;
  if (parsedChallenge) record.challenge = parsedChallenge.record;
  if (payment) record.payment = payment;
  record.settlement = settlement ?? { success: false, source: 'none' };

  return record;
}

/**
 * Outcome precedence.
 *
 * A policy violation outranks everything else, per spec: the caller must not have
 * to dig through assertions to notice that a check failed. The HTTP status is
 * still recorded on the response, so nothing is lost by the override.
 */
function decideOutcome(args: {
  anyFailed: boolean;
  thrown: unknown;
  incomplete: boolean;
  status?: number;
  settlement?: SettlementRecord;
  hadPayment: boolean;
}): Outcome {
  if (args.anyFailed) return 'policy_violation';
  if (args.thrown) {
    const msg = String((args.thrown as Error)?.name ?? '') + String((args.thrown as Error)?.message ?? '');
    return /timeout|aborted|ETIMEDOUT|AbortError/i.test(msg) ? 'timeout' : 'http_error';
  }
  if (args.incomplete) return 'timeout';
  if (args.status === 402) return 'payment_failed';
  if (args.hadPayment && args.settlement && args.settlement.source !== 'none' && !args.settlement.success) {
    return 'payment_failed';
  }
  if (args.status !== undefined && args.status >= 400) return 'http_error';
  return 'ok';
}

/* ------------------------------------------------------------------ *
 * Module-level helpers, operating across every attestor in the process.
 * Convenient for shutdown hooks that do not hold a reference to the wrapper.
 * ------------------------------------------------------------------ */

export async function flush(): Promise<FlushResult[]> {
  const out: FlushResult[] = [];
  for (const a of [...REGISTRY]) out.push(...(await a.flush()));
  return out;
}

export async function close(): Promise<FlushResult[]> {
  const out: FlushResult[] = [];
  for (const a of [...REGISTRY]) out.push(...(await a.close()));
  return out;
}

export function getReceipt(callId: string): AnyReceipt | undefined {
  for (const a of REGISTRY) {
    const r = a.getReceipt(callId);
    if (r) return r;
  }
  return undefined;
}

export function exportReceipts(opts: ExportOptions = {}): string {
  const all = [...REGISTRY].flatMap((a) => a.batcher.allReceipts());
  return (opts.format ?? 'jsonl') === 'csv' ? toCsv(all, opts) : toJsonl(all, opts);
}

export { createTap };
export { replayWal, Wal } from './wal.js';
export { jcs, jcsBytes } from './jcs.js';
export { sha256, sha256Jcs, uuidv7 } from './hash.js';
export {
  buildMerkleTree,
  buildProof,
  computeRootFromProof,
  hashLeaf,
  hashNode,
  verifyProof,
  MERKLE_PARAMS,
} from './merkle.js';
export { verifyReceipt, VERIFY_EXIT } from './verify.js';
export type { VerifyResult, VerifyOptions } from './verify.js';
export type { FlushResult } from './batcher.js';
export * from './types.js';
