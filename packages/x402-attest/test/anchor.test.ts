import { describe, expect, it, vi } from 'vitest';
import { AnchorClient, AnchorError, buildEnvelope } from '../src/anchor.js';
import type { FetchLike } from '../src/types.js';

/**
 * The anchoring client, exercised directly.
 *
 * Every branch here decides what happens to evidence when something goes wrong, so
 * the behaviour worth pinning is: classify honestly, and never make a claim the
 * server did not support.
 */

const ENVELOPE = buildEnvelope({
  root: 'a'.repeat(64),
  leafCount: 2,
  firstCallId: 'c1',
  lastCallId: 'c2',
  from: '2026-08-23T00:00:00.000Z',
  to: '2026-08-23T00:01:00.000Z',
  subjectId: 'agent-alpha',
});

const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });

describe('AnchorClient — keyed path', () => {
  it('posts to /v1/tiered-attest with the api key and surfaces the payload key', async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const keys: [string, string][] = [];
    const httpFetch: FetchLike = async (url, init) => {
      calls.push({ url: String(url), init });
      return json(200, { attestationId: 'att-1', payloadKey: 'k'.repeat(64), status: 'buffered' });
    };

    const client = new AnchorClient({
      baseUrl: 'https://rubric-protocol.com/',
      apiKey: 'secret-key',
      endpoint: 'tiered',
      subjectId: 'agent-alpha',
      httpFetch,
      onPayloadKey: (id, key) => keys.push([id, key]),
    });

    const result = await client.anchor(ENVELOPE);

    expect(calls[0]!.url).toBe('https://rubric-protocol.com/v1/tiered-attest');
    expect((calls[0]!.init!.headers as Record<string, string>)['x-api-key']).toBe('secret-key');
    const sent = JSON.parse(String(calls[0]!.init!.body));
    expect(sent).toEqual({ sourceId: 'agent-alpha', data: ENVELOPE });
    expect(sent.leafType).toBeUndefined(); // tiered takes no top-level leafType
    expect(sent.data.leafType).toBe('DATA_RECORD');

    expect(result).toMatchObject({
      attestationId: 'att-1',
      via: 'tiered',
      verifyUrl: 'https://rubric-protocol.com/v1/verify/att-1',
    });
    // The key is handed to the caller to store separately, never returned in-band.
    expect(keys).toEqual([['att-1', 'k'.repeat(64)]]);
    expect(result.payloadKey).toBeUndefined();
  });

  it('warns loudly and sends the /v1/attest body shape when asked for the direct path', async () => {
    const warn = vi.spyOn(process, 'emitWarning').mockImplementation(() => {});
    const calls: string[] = [];
    const httpFetch: FetchLike = async (url, init) => {
      calls.push(String(url));
      return json(200, { attestationId: 'att-2', stage: 'local' });
    };

    const client = new AnchorClient({
      baseUrl: 'https://rubric-protocol.com',
      apiKey: 'ent-key',
      endpoint: 'direct',
      subjectId: 'agent-alpha',
      httpFetch,
    });

    // /v1/attest is Enterprise-only and bills HBAR per call, so choosing it must
    // never be silent.
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('bills HBAR'), 'RubricCostWarning');

    const result = await client.anchor(ENVELOPE);
    expect(calls[0]).toBe('https://rubric-protocol.com/v1/attest');
    expect(result.via).toBe('direct');
    warn.mockRestore();
  });

  it('classifies 4xx as permanent and 5xx as transient', async () => {
    const mk = (status: number) =>
      new AnchorClient({
        baseUrl: 'https://r.example',
        apiKey: 'k',
        endpoint: 'tiered',
        subjectId: 's',
        httpFetch: async () => json(status, { error: 'nope' }),
      });

    for (const [status, retryable] of [
      [400, false],
      [401, false],
      [403, false],
      [408, true],
      [429, true],
      [500, true],
      [503, true],
    ] as [number, boolean][]) {
      const err = await mk(status)
        .anchor(ENVELOPE)
        .catch((e) => e as AnchorError);
      expect(err).toBeInstanceOf(AnchorError);
      expect(err.status, `status ${status}`).toBe(status);
      expect(err.retryable, `status ${status} retryable`).toBe(retryable);
    }
  });

  it('treats a transport error as retryable', async () => {
    const client = new AnchorClient({
      baseUrl: 'https://r.example',
      apiKey: 'k',
      endpoint: 'tiered',
      subjectId: 's',
      httpFetch: async () => {
        throw new Error('ECONNRESET');
      },
    });
    const err = (await client.anchor(ENVELOPE).catch((e) => e)) as AnchorError;
    expect(err.message).toMatch(/anchor request failed: ECONNRESET/);
    expect(err.retryable).toBe(true);
  });

  it('refuses a 200 that carries no attestationId', async () => {
    const client = new AnchorClient({
      baseUrl: 'https://r.example',
      apiKey: 'k',
      endpoint: 'tiered',
      subjectId: 's',
      httpFetch: async () => json(200, { status: 'buffered' }),
    });
    // Better to retry than to hand back a receipt pointing at nothing.
    await expect(client.anchor(ENVELOPE)).rejects.toThrow(/no attestationId/);
  });

  it('reads a nested attestationId, and tolerates a non-JSON body', async () => {
    const nested = new AnchorClient({
      baseUrl: 'https://r.example',
      apiKey: 'k',
      endpoint: 'tiered',
      subjectId: 's',
      httpFetch: async () => json(200, { attestation: { attestationId: 'att-nested' } }),
    });
    expect((await nested.anchor(ENVELOPE)).attestationId).toBe('att-nested');

    const html = new AnchorClient({
      baseUrl: 'https://r.example',
      apiKey: 'k',
      endpoint: 'tiered',
      subjectId: 's',
      httpFetch: async () => new Response('<html>502 Bad Gateway</html>', { status: 502 }),
    });
    const err = (await html.anchor(ENVELOPE).catch((e) => e)) as AnchorError;
    expect(err.status).toBe(502);
    expect(err.retryable).toBe(true);
  });
});

describe('AnchorClient — keyless x402 path', () => {
  it('posts to /v1/x402/tiered-attest with no api key and prefers the served verifyUrl', async () => {
    const calls: { url: string; init?: RequestInit }[] = [];
    const anchorFetch: FetchLike = async (url, init) => {
      calls.push({ url: String(url), init });
      return json(200, {
        success: true,
        paid: true,
        settled: true,
        attestationId: 'att-x402',
        verifyUrl: 'https://eu.rubric-protocol.com/v1/verify/att-x402',
      });
    };

    const client = new AnchorClient({
      baseUrl: 'https://rubric-protocol.com',
      endpoint: 'tiered',
      subjectId: 'agent-alpha',
      anchorFetch,
    });

    const result = await client.anchor(ENVELOPE);
    expect(calls[0]!.url).toBe('https://rubric-protocol.com/v1/x402/tiered-attest');
    expect((calls[0]!.init!.headers as Record<string, string>)['x-api-key']).toBeUndefined();
    expect(result.via).toBe('x402');
    // The node that holds the record is authoritative about where to verify it.
    expect(result.verifyUrl).toBe('https://eu.rubric-protocol.com/v1/verify/att-x402');
  });

  it('takes the opening salt from the server when no payload key is returned', async () => {
    // The live keyless route never returns `payloadKey` — it is a decryption
    // credential, and paying $0.005 for an attestation does not buy it. It
    // returns the already-derived salt, which is one-way in that key.
    const salt = 'c'.repeat(64);
    const keys: string[] = [];
    const client = new AnchorClient({
      baseUrl: 'https://rubric-protocol.com',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () =>
        json(200, {
          attestationId: 'att-salt',
          commitmentSalt: salt,
          payloadCommitment: 'd'.repeat(64),
        }),
      onPayloadKey: (_id, k) => keys.push(k),
    });

    const result = await client.anchor(ENVELOPE);
    expect(result.commitmentSalt).toBe(salt);
    expect(result.payloadCommitment).toBe('d'.repeat(64));
    // Nothing to retain: there was no key, so the restricted key log stays empty.
    expect(keys).toEqual([]);
  });

  it('ignores a malformed salt rather than writing it into a receipt', async () => {
    const client = new AnchorClient({
      baseUrl: 'https://rubric-protocol.com',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () => json(200, { attestationId: 'att-bad', commitmentSalt: 'not-a-digest' }),
    });
    // A salt that cannot be a sha256 digest would recompute to a commitment that
    // matches nothing, turning a server quirk into a tampering accusation.
    expect((await client.anchor(ENVELOPE)).commitmentSalt).toBeUndefined();
  });

  it('falls back to the configured base URL when none is served', async () => {
    const client = new AnchorClient({
      baseUrl: 'https://rubric-protocol.com',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () => json(200, { attestationId: 'att-y' }),
    });
    expect((await client.anchor(ENVELOPE)).verifyUrl).toBe(
      'https://rubric-protocol.com/v1/verify/att-y',
    );
  });

  it('treats an unpaid 402 as retryable — the wallet may get topped up', async () => {
    const client = new AnchorClient({
      baseUrl: 'https://r.example',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () => json(402, { x402Version: 1, accepts: [] }),
    });
    const err = (await client.anchor(ENVELOPE).catch((e) => e)) as AnchorError;
    expect(err.status).toBe(402);
    expect(err.retryable).toBe(true);
    expect(err.message).toMatch(/unpaid/);
  });

  it('explains itself when no anchorFetch was supplied', async () => {
    const client = new AnchorClient({
      baseUrl: 'https://r.example',
      endpoint: 'tiered',
      subjectId: 's',
    });
    const err = (await client.anchor(ENVELOPE).catch((e) => e)) as AnchorError;
    expect(err.message).toMatch(/keyless anchoring needs an x402-capable `anchorFetch`/);
    expect(err.retryable).toBe(false);
  });

  it('reports a transport failure and a rejected anchor distinctly', async () => {
    const dead = new AnchorClient({
      baseUrl: 'https://r.example',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () => {
        throw new Error('ENOTFOUND');
      },
    });
    await expect(dead.anchor(ENVELOPE)).rejects.toThrow(/x402 anchor request failed/);

    const rejected = new AnchorClient({
      baseUrl: 'https://r.example',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () => json(500, { error: 'boom' }),
    });
    await expect(rejected.anchor(ENVELOPE)).rejects.toThrow(/x402 anchor rejected with HTTP 500/);

    const empty = new AnchorClient({
      baseUrl: 'https://r.example',
      endpoint: 'tiered',
      subjectId: 's',
      anchorFetch: async () => json(200, { success: true }),
    });
    await expect(empty.anchor(ENVELOPE)).rejects.toThrow(/no attestationId/);
  });
});
