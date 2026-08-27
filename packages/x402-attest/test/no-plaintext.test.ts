import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { readFileSync, rmSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { createTap, withAttestation, type AttestedFetch } from '../src/index.js';
import { verifyReceipt } from '../src/verify.js';
import { isAnchored, type AnyReceipt, type CallRecord, type FetchLike } from '../src/types.js';
import { startMockSeller, type MockSeller } from './mocks/seller.js';
import { PAYLOAD_KEY, startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';
import { createMockX402Fetch } from './mocks/x402client.js';

/**
 * MANDATORY: no plaintext body content may ever leave the process.
 *
 * The library's core privacy claim is that hashing happens locally and only
 * digests are transmitted. A regression here is not a bug, it is a breach — the
 * anchored record is append-only and public, so a leak cannot be walked back.
 *
 * Sentinels are planted in the request body, the response body and the model
 * name, and every byte the process emits is searched for them.
 */

const REQ_SENTINEL = 'SENTINEL-REQUEST-PLAINTEXT-9f3a2b';
const RES_SENTINEL = 'SENTINEL-RESPONSE-PLAINTEXT-7c1d4e';
/** Model name as it appears in the response BODY. Body content: must never leak. */
const BODY_MODEL_SENTINEL = 'SENTINEL-BODY-MODEL-5e8b17';
/**
 * Model name as it appears in the `x-clawrouter-model` response header.
 *
 * Header, not body. The spec's header allowlist captures `x-clawrouter-*`
 * verbatim precisely because routing headers are the evidence for the
 * proof-of-routing claim, so this one IS kept in clear in the local record. It
 * still must never be transmitted.
 */
const HEADER_MODEL_SENTINEL = 'SENTINEL-HEADER-MODEL-2d94af';

describe('no plaintext ever leaves the process', () => {
  let seller: MockSeller;
  let rubric: MockRubric;
  let walPath: string;
  /** Every byte handed to an outbound fetch that this library originated. */
  let outbound: string[];
  /** The wrapper from the most recent `run()`, for exercising `exportReceipts`. */
  let lastFetch: AttestedFetch<FetchLike> | undefined;

  beforeEach(async () => {
    seller = await startMockSeller({
      servedModel: HEADER_MODEL_SENTINEL,
      responseBody: {
        model: BODY_MODEL_SENTINEL,
        choices: [{ message: { content: RES_SENTINEL } }],
        usage: { prompt_tokens: 3, completion_tokens: 4, total_tokens: 7 },
      },
    });
    rubric = await startMockRubric();
    walPath = tmpWal('no-plaintext');
    outbound = [];
    lastFetch = undefined;
  });

  afterEach(async () => {
    await seller.close();
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  /** Records everything the library sends to Rubric, headers and URL included. */
  const recordingFetch = (): FetchLike => async (input, init) => {
    outbound.push(String(input));
    outbound.push(JSON.stringify(init?.headers ?? {}));
    if (init?.body) outbound.push(String(init.body));
    return fetch(input as string, init);
  };

  async function run(over: Record<string, unknown> = {}) {
    const tap = createTap();
    const receipts: AnyReceipt[] = [];
    const fetchAndPay = withAttestation(createMockX402Fetch(tap.wrapFetch(fetch)), {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      sessionId: 'privacy-session',
      walPath,
      rubricBaseUrl: rubric.url,
      httpFetch: recordingFetch(),
      tap,
      installSignalHandlers: false,
      policy: { maxPricePerCall: '1.00', allowedNetworks: ['eip155:8453'] },
      onReceipt: (r) => receipts.push(r),
      ...over,
    });
    lastFetch = fetchAndPay;

    const res = await fetchAndPay(`${seller.url}/v1/chat/completions?apikey=${REQ_SENTINEL}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        model: BODY_MODEL_SENTINEL,
        messages: [{ content: REQ_SENTINEL }],
      }),
    });
    // The caller still gets the real content. Privacy is about what we emit, not
    // about degrading the response.
    expect(await res.text()).toContain(RES_SENTINEL);

    await fetchAndPay.flush();
    await fetchAndPay.close();
    return receipts;
  }

  /** Body-derived content. Must not appear anywhere: wire, receipt, or WAL. */
  const SENTINELS = [REQ_SENTINEL, RES_SENTINEL, BODY_MODEL_SENTINEL];

  function assertClean(haystack: string, label: string) {
    for (const s of SENTINELS) {
      expect(haystack.includes(s), `${label} leaked ${s}`).toBe(false);
    }
  }

  it('transmits no body substring in any outbound payload (hash-only, the default)', async () => {
    const receipts = await run();

    // 1. Everything the library sent over the wire to Rubric.
    expect(outbound.length).toBeGreaterThan(0);
    assertClean(outbound.join('\n'), 'outbound fetch payloads');

    // 2. Everything the mock Rubric node actually received, independently captured.
    const received = rubric.requests
      .map((r) => `${r.path} ${JSON.stringify(r.headers)} ${r.body}`)
      .join('\n');
    expect(rubric.requests.length).toBeGreaterThan(0);
    assertClean(received, 'bytes received by Rubric');

    // 3. The receipts themselves, which are handed to callers and exported.
    assertClean(JSON.stringify(receipts), 'receipts');

    // 4. The on-disk WAL. Local, but the promise is "no body content leaves the
    //    process", and a WAL gets shipped to auditors.
    assertClean(readFileSync(join(walPath, 'leaves.jsonl'), 'utf8'), 'WAL');
  });

  it('still records the checks it performed, using digests instead of content', async () => {
    const receipts = await run();
    const rec = receipts[0]!.callRecord;

    // Hashes are present and bound to the real bytes...
    expect(rec.request.bodyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rec.response.bodyHash).toMatch(/^[0-9a-f]{64}$/);
    expect(rec.request.bodyBytes).toBeGreaterThan(0);
    expect(rec.request.queryHash).toMatch(/^sha256:[0-9a-f]{64}$/);

    // ...and the routing check still reached a real verdict without naming names.
    // The header reports a different model than the body requested, so this is a
    // substitution — detected, recorded, and described only in digests.
    const model = rec.assertions.find((a) => a.id === 'model_matches_request')!;
    expect(model.result).toBe('fail');
    expect(model.observed).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(model.expected).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(rec.response.servedModel).toBeUndefined();
  });

  it('keeps outbound payloads clean even in metadata mode', async () => {
    // metadata mode deliberately keeps the model name in the LOCAL record. It must
    // still never be transmitted: only the Merkle root is anchored.
    const receipts = await run({ redact: 'metadata' });

    expect(receipts[0]!.callRecord.response.servedModel).toBe(HEADER_MODEL_SENTINEL);
    expect(receipts[0]!.callRecord.response.usage).toEqual({
      promptTokens: 3,
      completionTokens: 4,
      totalTokens: 7,
    });

    assertClean(outbound.join('\n'), 'outbound payloads (metadata mode)');
    assertClean(
      rubric.requests.map((r) => r.body).join('\n'),
      'bytes received by Rubric (metadata mode)',
    );
    // The header-derived model name is in the local record but not on the wire.
    expect(outbound.join('\n')).not.toContain(HEADER_MODEL_SENTINEL);
  });

  it('captures allowlisted routing headers in clear but never transmits them', async () => {
    const receipts = await run();
    const rec = receipts[0]!.callRecord;

    // By design, per the header allowlist: x-clawrouter-* is the router's own
    // routing metadata and is the evidence behind the substitution check.
    expect(rec.response.headers['x-clawrouter-model']).toBe(HEADER_MODEL_SENTINEL);
    // ...and it still never reaches Rubric, because only the root is anchored.
    expect(outbound.join('\n')).not.toContain(HEADER_MODEL_SENTINEL);
    expect(rubric.requests.map((r) => r.body).join('\n')).not.toContain(
      HEADER_MODEL_SENTINEL,
    );
  });

  it('hashes the original bytes, then redacts — a custom fn cannot change the hash', async () => {
    let seen: CallRecord | undefined;
    let originalHash: string | undefined;

    const receipts = await run({
      redact: (rec: CallRecord): CallRecord => {
        seen = structuredClone(rec);
        originalHash = rec.response.bodyHash;
        // Blow away everything the fn is allowed to touch.
        return {
          ...rec,
          request: { ...rec.request, host: 'redacted', path: '/redacted' },
          response: { ...rec.response, headers: {} },
        };
      },
    });

    // The fn ran, and it received a record whose bodyHash was already computed
    // over the ORIGINAL bytes.
    expect(seen).toBeDefined();
    expect(originalHash).toMatch(/^[0-9a-f]{64}$/);

    const rec = receipts[0]!.callRecord;
    expect(rec.request.host).toBe('redacted');
    expect(rec.response.headers).toEqual({});
    // Same hash before and after redaction: the receipt still binds to the exact
    // bytes that crossed the wire.
    expect(rec.response.bodyHash).toBe(originalHash);

    assertClean(JSON.stringify(receipts), 'receipts (custom redaction)');
  });

  it('never records or transmits the payment authorization header', async () => {
    const receipts = await run();
    const header = seller.received[0]!;
    expect(header.length).toBeGreaterThan(50);

    // The header is a signed, replayable bearer authorization. Only its hash is
    // ever written down.
    expect(JSON.stringify(receipts)).not.toContain(header);
    expect(outbound.join('\n')).not.toContain(header);
    expect(readFileSync(join(walPath, 'leaves.jsonl'), 'utf8')).not.toContain(header);
    expect(receipts[0]!.callRecord.payment!.xPaymentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  /**
   * MANDATORY: the payload decryption key is a credential, not evidence.
   *
   * Rubric's keyed anchor path hands back `payloadKey` — the AES key that
   * decrypts the payload it holds in its warm store — with the response. The
   * library keeps it, because losing it makes the submitted payload
   * unrecoverable, but it keeps it in exactly one place: a 0600 file next to the
   * WAL. It must never reach a receipt, an export or a verifier's output, all
   * three of which are meant to be handed to strangers.
   *
   * The salt is the opposite: safe to publish, and it is what makes a receipt
   * independently verifiable. The two differ by one SHA-256, which is precisely
   * why a regression here would be easy to miss and impossible to walk back.
   */
  it('never lets the payload decryption key into a receipt, an export, or a verify result', async () => {
    const receipts = await run();
    // Guard the guard: an empty or trivial sentinel would make every assertion
    // below vacuously true.
    expect(PAYLOAD_KEY).toMatch(/^[0-9a-f]{64}$/);

    // 1. The receipts handed to callers — and the one place they legitimately
    //    carry commitment material, to prove this is not just an absent field.
    const anchored = receipts.filter(isAnchored);
    expect(anchored.length).toBeGreaterThan(0);
    expect(anchored[0]!.commitmentSalt).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(receipts)).not.toContain(PAYLOAD_KEY);

    // 2. Both export formats — the file an auditor actually receives.
    expect(lastFetch!.exportReceipts({ format: 'jsonl' })).not.toContain(PAYLOAD_KEY);
    expect(lastFetch!.exportReceipts({ format: 'csv' })).not.toContain(PAYLOAD_KEY);

    // 3. The verifier's own output, which gets pasted into tickets and CI logs.
    for (const r of anchored) {
      const result = await verifyReceipt(r, { fetchImpl: fetch });
      expect(result.checks.commitment).toBe('pass');
      expect(JSON.stringify(result)).not.toContain(PAYLOAD_KEY);
    }

    // 4. The wire, and the two WAL files that are not the key file.
    assertClean(outbound.join('\n'), 'outbound payloads');
    expect(outbound.join('\n')).not.toContain(PAYLOAD_KEY);
    expect(readFileSync(join(walPath, 'leaves.jsonl'), 'utf8')).not.toContain(PAYLOAD_KEY);
    expect(readFileSync(join(walPath, 'anchors.jsonl'), 'utf8')).not.toContain(PAYLOAD_KEY);
  });

  it('publishes the salt while withholding the key it is one SHA-256 away from', async () => {
    const receipts = await run();
    const [anchored] = receipts.filter(isAnchored);
    expect(anchored).toBeDefined();

    // salt = SHA-256(payloadKeyHex + ':rubric-commit-v1'), read from the server
    // implementation rather than inferred from a passing test.
    const salt = createHash('sha256').update(`${PAYLOAD_KEY}:rubric-commit-v1`).digest('hex');
    expect(anchored!.commitmentSalt).toBe(salt);

    const serialized = JSON.stringify(anchored);
    expect(serialized).toContain(salt);
    expect(serialized).not.toContain(PAYLOAD_KEY);

    // The key is retained, exactly once, in a file the WAL creates 0600 — it is
    // the only way to recover the payload from Rubric's store later.
    const keyFile = join(walPath, 'payload-keys.jsonl');
    expect(readFileSync(keyFile, 'utf8')).toContain(PAYLOAD_KEY);
    expect(statSync(keyFile).mode & 0o777).toBe(0o600);
  });

  it('sends only a root and counts to Rubric — no per-call detail at all', async () => {
    await run();
    const attest = rubric.requests.find((r) => r.path === '/v1/tiered-attest')!;
    const sent = JSON.parse(attest.body) as { data: Record<string, unknown> };

    // Enumerate the payload explicitly. If a future change starts shipping call
    // records upstream, this fails loudly rather than leaking quietly.
    expect(Object.keys(sent.data).sort()).toEqual([
      'firstCallId',
      'lastCallId',
      'leafCount',
      'leafType',
      'merkle',
      'root',
      'schemaVersion',
      'subjectId',
      'timeRange',
    ]);
  });
});
