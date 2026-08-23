import { describe, expect, it } from 'vitest';
import {
  ZERO,
  addDecimal,
  atomicToDecimal,
  compareDecimal,
  formatDecimal,
  isDecimalString,
  lte,
  parseDecimal,
} from '../src/decimal.js';
import { EMPTY_SHA256, __resetUuidState, sha256, tag, uuidv7 } from '../src/hash.js';
import {
  decodeB64Json,
  decodeMaybeB64Json,
  extractRequestedModel,
  extractServedModel,
  extractUsage,
  normalizeNetwork,
  parseChallenge,
  parsePaymentHeader,
  parseSettlementBody,
  parseSettlementHeader,
  pickHeader,
  sameAddress,
  sanitizeResource,
} from '../src/x402.js';
import { buildRequestRecord, captureRequestBody, filterHeaders, tryJson, UNHASHABLE_BODY } from '../src/record.js';
import { applyRedaction, METADATA_ALLOWLIST } from '../src/redact.js';
import { buildEnvelope, verifyUrlFor } from '../src/anchor.js';
import type { CallRecord } from '../src/types.js';

describe('decimal arithmetic', () => {
  it('parses, compares and formats without floating point error', () => {
    expect(compareDecimal(parseDecimal('0.1'), parseDecimal('0.10'))).toBe(0);
    expect(compareDecimal(addDecimal(parseDecimal('0.1'), parseDecimal('0.2')), parseDecimal('0.3'))).toBe(0);
    expect(formatDecimal(addDecimal(parseDecimal('0.1'), parseDecimal('0.2')))).toBe('0.3');
    expect(compareDecimal(parseDecimal('2'), parseDecimal('10'))).toBe(-1);
    expect(compareDecimal(parseDecimal('-1'), parseDecimal('1'))).toBe(-1);
  });

  it('handles signs, zero and bare fractions', () => {
    expect(formatDecimal(parseDecimal('-0.50'))).toBe('-0.50');
    expect(formatDecimal(parseDecimal('-0'))).toBe('0');
    expect(formatDecimal(parseDecimal('.5'))).toBe('0.5');
    expect(formatDecimal(parseDecimal('+3'))).toBe('3');
    expect(formatDecimal(ZERO)).toBe('0');
    expect(formatDecimal(addDecimal(parseDecimal('-5'), parseDecimal('3')))).toBe('-2');
  });

  it('rejects non-numeric input rather than coercing it', () => {
    expect(() => parseDecimal('abc')).toThrow(/not a decimal/);
    expect(() => parseDecimal('1e5')).toThrow();
    expect(() => parseDecimal('')).toThrow();
    expect(isDecimalString('1.25')).toBe(true);
    expect(isDecimalString('1,25')).toBe(false);
    expect(lte('1', '2')).toBe(true);
    expect(lte('3', '2')).toBe(false);
    expect(lte('x', '2')).toBeNull();
  });

  it('converts atomic units at the asset decimals', () => {
    expect(formatDecimal(atomicToDecimal('1000', 6))).toBe('0.001000');
    expect(formatDecimal(atomicToDecimal('1', 18))).toBe('0.000000000000000001');
    expect(formatDecimal(atomicToDecimal('0', 6))).toBe('0.000000');
    expect(() => atomicToDecimal('1.5', 6)).toThrow(/not an integer/);
    expect(() => atomicToDecimal('1', -1)).toThrow(/implausible/);
    expect(() => atomicToDecimal('1', 99)).toThrow(/implausible/);
  });

  it('handles amounts far beyond Number.MAX_SAFE_INTEGER', () => {
    const huge = '123456789012345678901234567890';
    expect(formatDecimal(atomicToDecimal(huge, 6))).toBe('123456789012345678901234.567890');
  });
});

describe('uuidv7', () => {
  it('is a well-formed v7 uuid', () => {
    expect(uuidv7()).toMatch(
      /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
    );
  });

  it('sorts lexically in generation order', () => {
    __resetUuidState();
    const ids = Array.from({ length: 5000 }, () => uuidv7());
    expect([...ids].sort()).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('stays monotonic when the clock steps backwards', () => {
    __resetUuidState();
    let t = 1_700_000_000_000;
    const clock = () => t;
    const a = uuidv7(clock);
    t -= 5_000; // NTP correction, container migration, whatever
    const b = uuidv7(clock);
    expect(b > a).toBe(true);
  });

  it('survives more than 4096 ids inside a single millisecond', () => {
    __resetUuidState();
    const clock = () => 1_700_000_000_000;
    const ids = Array.from({ length: 5000 }, () => uuidv7(clock));
    expect(new Set(ids).size).toBe(5000);
    expect([...ids].sort()).toEqual(ids);
  });
});

describe('hash helpers', () => {
  it('hashes strings and bytes identically', () => {
    expect(sha256('abc')).toBe(sha256(Buffer.from('abc')));
    expect(EMPTY_SHA256).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
    expect(tag('x')).toBe('sha256:' + sha256('x'));
  });
});

describe('x402 wire parsing', () => {
  const b64 = (v: unknown) => Buffer.from(JSON.stringify(v)).toString('base64');

  it('decodes base64 and raw JSON, and refuses junk', () => {
    expect(decodeB64Json(b64({ a: 1 }))).toEqual({ a: 1 });
    expect(decodeB64Json('not base64 at all!!')).toBeNull();
    expect(decodeMaybeB64Json('{"a":1}')).toEqual({ a: 1 });
    expect(decodeMaybeB64Json('{bad json')).toBeNull();
    // url-safe base64 is accepted too.
    expect(decodeMaybeB64Json(b64({ a: 1 }).replace(/\+/g, '-').replace(/\//g, '_'))).toEqual({ a: 1 });
  });

  it('normalizes network aliases to CAIP-2', () => {
    expect(normalizeNetwork('base')).toBe('eip155:8453');
    expect(normalizeNetwork('Base-Sepolia')).toBe('eip155:84532');
    expect(normalizeNetwork('eip155:8453')).toBe('eip155:8453');
    expect(normalizeNetwork('something-new')).toBe('something-new');
    expect(normalizeNetwork(undefined)).toBeUndefined();
  });

  it('compares addresses case-insensitively and reports unknown honestly', () => {
    expect(sameAddress('0xABC', '0xabc')).toBe(true);
    expect(sameAddress('0xABC', '0xdef')).toBe(false);
    expect(sameAddress(undefined, '0xabc')).toBeNull();
  });

  it('parses an accepts[] challenge and picks the option that was paid', () => {
    const body = {
      x402Version: 1,
      accepts: [
        { scheme: 'exact', network: 'solana:x', maxAmountRequired: '5', payTo: '0xsol', asset: 'a' },
        {
          scheme: 'exact',
          network: 'eip155:8453',
          maxAmountRequired: '1000',
          payTo: '0xevm',
          asset: 'usdc',
          resource: 'https://s.example/x?key=SECRET',
          maxTimeoutSeconds: 60,
        },
      ],
    };
    // Without the preference the first option wins, which would make
    // price_matches_challenge fail on a correct multi-option client.
    const chosen = parseChallenge({ body }, { scheme: 'exact', network: 'base' })!;
    expect(chosen.record.maxAmountRequired).toBe('1000');
    expect(chosen.record.payTo).toBe('0xevm');
    // The query string is stripped: it is the buyer's own URL echoed back.
    expect(chosen.record.resource).toBe('https://s.example/x');
    expect(chosen.record.rawHash).toMatch(/^[0-9a-f]{64}$/);

    expect(parseChallenge({ body }).record.maxAmountRequired).toBe('5');
  });

  it('accepts a bare requirements object and a header-borne challenge', () => {
    const bare = { scheme: 'exact', network: 'base', price: '0.001', payTo: '0xa', asset: 'usdc' };
    expect(parseChallenge({ body: bare })!.record.maxAmountRequired).toBe('0.001');

    const viaHeader = parseChallenge({ headerValue: b64({ accepts: [bare] }) })!;
    expect(viaHeader.record.payTo).toBe('0xa');

    // price as an object.
    const priceObj = { scheme: 'exact', network: 'base', payTo: '0xa', price: { amount: '250', asset: 'usdc' } };
    expect(parseChallenge({ body: priceObj })!.record.maxAmountRequired).toBe('250');
    expect(parseChallenge({ body: priceObj })!.record.asset).toBe('usdc');

    expect(parseChallenge({ body: undefined })).toBeUndefined();
    expect(parseChallenge({ body: { accepts: [] } })).toBeUndefined();
    expect(parseChallenge({ body: 'nope' })).toBeUndefined();
  });

  it('strips query strings from resource URLs, however malformed', () => {
    expect(sanitizeResource('https://a.example/p?k=v#frag')).toBe('https://a.example/p');
    expect(sanitizeResource('/relative/path?k=v')).toBe('/relative/path');
    expect(sanitizeResource(undefined)).toBeUndefined();
  });

  it('parses a payment header down to a hash plus what was authorized', () => {
    const header = b64({
      x402Version: 1,
      scheme: 'exact',
      network: 'eip155:8453',
      asset: 'usdc',
      payload: { signature: '0xsig', authorization: { to: '0xpayee', value: '1000' } },
    });
    const p = parsePaymentHeader(header)!;
    expect(p.amountAuthorized).toBe('1000');
    expect(p.payTo).toBe('0xpayee');
    expect(p.xPaymentHash).toBe(sha256(header));

    // Even an undecodable header is bound by hash rather than dropped.
    const opaque = parsePaymentHeader('!!!not-decodable!!!')!;
    expect(opaque.amountAuthorized).toBe('unknown');
    expect(opaque.xPaymentHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('parses settlement from a header or a body, and infers success carefully', () => {
    expect(parseSettlementHeader(b64({ success: true, transaction: '0xtx', network: 'base' }))).toEqual({
      success: true,
      txHash: '0xtx',
      network: 'base',
      source: 'x-payment-response',
    });
    // A tx hash with no explicit success flag counts as settled.
    expect(parseSettlementHeader(b64({ transaction: '0xtx' }))!.success).toBe(true);
    // Neither present: not optimistically true.
    expect(parseSettlementHeader(b64({}))!.success).toBe(false);
    expect(parseSettlementHeader('garbage')).toBeUndefined();

    expect(parseSettlementBody({ settlement: { txHash: '0xtx', network: 'base' } })!.source).toBe('body');
    expect(parseSettlementBody({ payment: { success: false } })!.success).toBe(false);
    expect(parseSettlementBody({ other: 1 })).toBeUndefined();
    expect(parseSettlementBody(null)).toBeUndefined();
  });

  it('reads headers by any accepted spelling', () => {
    const h = new Headers({ 'x-payment-response': 'v' });
    expect(pickHeader(h, ['payment-response', 'x-payment-response'])).toEqual({
      name: 'x-payment-response',
      value: 'v',
    });
    expect(pickHeader(h, ['nope'])).toBeUndefined();
    expect(pickHeader(undefined, ['x'])).toBeUndefined();
  });

  it('prefers a routing header over the body when reading the served model', () => {
    const headers = new Headers({ 'x-clawrouter-model': 'gemini-flash' });
    // The router is the party being audited, so its declared header outranks the
    // body it also controls.
    expect(extractServedModel({ model: 'gpt-4o' }, headers)).toEqual({
      model: 'gemini-flash',
      source: 'x-clawrouter-model',
    });
    expect(extractServedModel({ model: 'gpt-4o' }, undefined)).toEqual({
      model: 'gpt-4o',
      source: 'body.model',
    });
    expect(extractServedModel({}, undefined)).toBeUndefined();
    expect(extractRequestedModel({ model: 'gpt-4o' })).toBe('gpt-4o');
    expect(extractRequestedModel('nope')).toBeUndefined();
  });

  it('reads token usage in both snake and camel spellings', () => {
    expect(extractUsage({ usage: { prompt_tokens: 1, completion_tokens: 2, total_tokens: 3 } })).toEqual({
      promptTokens: 1,
      completionTokens: 2,
      totalTokens: 3,
    });
    expect(extractUsage({ usage: { input_tokens: 4 } })).toEqual({ promptTokens: 4 });
    expect(extractUsage({ usage: {} })).toBeUndefined();
    expect(extractUsage({})).toBeUndefined();
  });
});

describe('request capture', () => {
  it('hashes every body form fetch accepts', async () => {
    expect((await captureRequestBody('http://x/', { body: 'abc' })).hash).toBe(sha256('abc'));
    expect((await captureRequestBody('http://x/', { body: new Uint8Array([1, 2]) })).hash).toBe(
      sha256(Buffer.from([1, 2])),
    );
    expect((await captureRequestBody('http://x/', { body: new ArrayBuffer(2) })).hash).toBe(
      sha256(Buffer.alloc(2)),
    );
    expect((await captureRequestBody('http://x/', { body: new URLSearchParams({ a: 'b' }) })).hash).toBe(
      sha256('a=b'),
    );
    expect((await captureRequestBody('http://x/', { body: new Blob(['hi']) })).hash).toBe(sha256('hi'));
    expect((await captureRequestBody('http://x/', {})).hash).toBe(EMPTY_SHA256);
    expect((await captureRequestBody('http://x/')).hash).toBe(EMPTY_SHA256);
  });

  it('reads a Request body via clone, leaving the caller a usable Request', async () => {
    const req = new Request('http://x/', { method: 'POST', body: 'payload' });
    expect((await captureRequestBody(req)).hash).toBe(sha256('payload'));
    // The caller's Request is still unread.
    expect(await req.text()).toBe('payload');
  });

  it('records an unreadable stream body as unhashable rather than as empty', async () => {
    const stream = new ReadableStream({
      start(c) {
        c.enqueue(new TextEncoder().encode('x'));
        c.close();
      },
    });
    const captured = await captureRequestBody('http://x/', { body: stream, duplex: 'half' } as RequestInit);
    // Claiming the empty-string digest here would be an affirmative false claim
    // about what was sent.
    expect(captured.hash).toBe(UNHASHABLE_BODY);
    expect(captured.hash).not.toBe(EMPTY_SHA256);
  });

  it('builds a request record with a hashed query and no raw query anywhere', () => {
    const rec = buildRequestRecord(
      'https://h.example/a/b?token=SECRET',
      { method: 'post', headers: { 'content-type': 'application/json' } },
      { bytes: null, hash: 'x', length: 3 },
    );
    expect(rec).toMatchObject({
      method: 'POST',
      host: 'h.example',
      path: '/a/b',
      contentType: 'application/json',
      bodyBytes: 3,
    });
    expect(rec.queryHash).toBe(tag('token=SECRET'));
    expect(JSON.stringify(rec)).not.toContain('SECRET');
  });

  it('degrades gracefully on an unparseable URL', () => {
    const rec = buildRequestRecord('::::not a url', {}, { bytes: null, hash: 'x', length: -1 });
    expect(rec.host).toBe('unknown');
    expect(rec.path).toBe('unknown');
    // A negative sentinel length must not leak into the record as -1 bytes.
    expect(rec.bodyBytes).toBe(0);
  });

  it('allowlists response headers by exact name and by clawrouter prefix', () => {
    const headers = new Headers({
      'content-type': 'application/json',
      'x-request-id': 'r1',
      'server-timing': 'db;dur=1',
      'x-payment-response': 'p',
      'payment-response': 'p2',
      'x-clawrouter-tier': 'SIMPLE',
      'x-clawrouter-confidence': '0.9',
      'set-cookie': 'leak=1',
      authorization: 'Bearer leak',
      'x-ratelimit-remaining': '99',
    });
    const kept = filterHeaders(headers);
    expect(Object.keys(kept).sort()).toEqual([
      'content-type',
      'payment-response',
      'server-timing',
      'x-clawrouter-confidence',
      'x-clawrouter-tier',
      'x-payment-response',
      'x-request-id',
    ]);
    expect(kept['set-cookie']).toBeUndefined();
    expect(kept['authorization']).toBeUndefined();
    expect(filterHeaders(undefined)).toEqual({});
  });

  it('parses captured bytes as JSON only when they are JSON', () => {
    expect(tryJson(new TextEncoder().encode('{"a":1}'))).toEqual({ a: 1 });
    expect(tryJson(new TextEncoder().encode('not json'))).toBeUndefined();
    expect(tryJson(new Uint8Array(0))).toBeUndefined();
    expect(tryJson(null)).toBeUndefined();
  });
});

describe('redaction', () => {
  const base: CallRecord = {
    v: 1,
    callId: 'c1',
    subjectId: 's',
    startedAt: '2026-08-23T00:00:00.000Z',
    endedAt: '2026-08-23T00:00:00.001Z',
    durationMs: 1,
    request: { method: 'GET', host: 'h', path: '/p', bodyHash: 'a', bodyBytes: 0 },
    response: {
      status: 200,
      bodyHash: 'b',
      bodyBytes: 1,
      headers: {},
      servedModel: 'gpt-4o',
      usage: { totalTokens: 9 },
    },
    outcome: 'ok',
    assertions: [],
  };

  it('strips body-derived fields under hash-only', () => {
    const out = applyRedaction(base, 'hash-only');
    expect(out.response.servedModel).toBeUndefined();
    expect(out.response.usage).toBeUndefined();
    // Hashes still bind to the original bytes.
    expect(out.response.bodyHash).toBe('b');
  });

  it('keeps allowlisted metadata under metadata mode', () => {
    const out = applyRedaction(base, 'metadata');
    expect(out.response.servedModel).toBe('gpt-4o');
    expect(METADATA_ALLOWLIST).toContain('response.servedModel');
  });

  it('runs a custom function against a clone and rejects a bad return', () => {
    let received: CallRecord | undefined;
    const out = applyRedaction(base, (r) => {
      received = r;
      r.request.host = 'redacted';
      return r;
    });
    expect(out.request.host).toBe('redacted');
    // The original is untouched: the fn got a clone.
    expect(base.request.host).toBe('h');
    expect(received).not.toBe(base);

    expect(() => applyRedaction(base, (() => null) as never)).toThrow(/must return a CallRecord/);
  });
});

describe('anchor envelope', () => {
  it('carries the root, the counts and the Merkle parameters, and nothing else', () => {
    const env = buildEnvelope({
      root: 'a'.repeat(64),
      leafCount: 3,
      firstCallId: 'c1',
      lastCallId: 'c3',
      from: '2026-08-23T00:00:00.000Z',
      to: '2026-08-23T00:01:00.000Z',
      subjectId: 'agent-alpha',
      policyId: 'p1',
    });
    expect(env.leafType).toBe('DATA_RECORD');
    expect(env.schemaVersion).toBe('rubric.x402-attest/v1');
    expect(env.merkle.oddNode).toBe('promote');
    expect(env.policyId).toBe('p1');

    // policyId is omitted rather than emitted as undefined when unset.
    const noPolicy = buildEnvelope({
      root: 'b'.repeat(64),
      leafCount: 1,
      firstCallId: 'c',
      lastCallId: 'c',
      from: 'x',
      to: 'y',
      subjectId: 's',
    });
    expect('policyId' in noPolicy).toBe(false);
  });

  it('builds the public verify URL', () => {
    expect(verifyUrlFor('https://rubric-protocol.com/', 'att 1')).toBe(
      'https://rubric-protocol.com/v1/verify/att%201',
    );
  });
});
