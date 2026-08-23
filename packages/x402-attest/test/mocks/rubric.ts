import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { randomUUID } from 'node:crypto';

/**
 * Mock Rubric node.
 *
 * Implements the three endpoints this library touches, in the shapes the live
 * docs describe as of 2026-08-23:
 *   POST /v1/tiered-attest      -> { attestationId, payloadKey, payloadCommitment, status }
 *   POST /v1/x402/tiered-attest -> 402, then { attestationId, verifyUrl, settlement, ... }
 *   GET  /v1/verify/:id         -> { found, status, verified, source, attestation }
 *
 * /v1/attest is deliberately NOT implemented. It is Enterprise-only and bills HBAR
 * per call; a mock of it in a test suite is an invitation for someone to point the
 * suite at production.
 */

export type MockRubricOptions = {
  /** Reject every request with 503 until set false. Simulates an outage. */
  down?: boolean;
  /** Fail this many requests, then start succeeding. */
  failFirst?: number;
  /** Status reported by /v1/verify. Default 'anchored'. */
  verifyStatus?: string;
  /** Price of a keyless attestation, atomic USDC. */
  attestPrice?: string;
  /** Corrupt the stored root so verification detects a mismatch. */
  corruptRoot?: boolean;
};

export type MockRubric = {
  url: string;
  server: Server;
  options: MockRubricOptions;
  /** Everything received, byte for byte, for the no-plaintext test. */
  requests: { path: string; headers: Record<string, string | string[] | undefined>; body: string }[];
  stored: Map<string, unknown>;
  attemptCount: number;
  close: () => Promise<void>;
};

const RUBRIC_PAYEE = '0x9999999999999999999999999999999999999999';

export async function startMockRubric(options: MockRubricOptions = {}): Promise<MockRubric> {
  const requests: MockRubric['requests'] = [];
  const stored = new Map<string, unknown>();
  const state = { attempts: 0 };

  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const body = Buffer.concat(chunks).toString('utf8');
      const path = (req.url ?? '').split('?')[0] ?? '';

      requests.push({ path, headers: req.headers, body });

      const json = (status: number, payload: unknown, headers: Record<string, string> = {}) => {
        res.writeHead(status, { 'content-type': 'application/json', ...headers });
        res.end(JSON.stringify(payload));
      };

      if (path.startsWith('/v1/verify/')) {
        const id = decodeURIComponent(path.slice('/v1/verify/'.length));
        const record = stored.get(id);
        if (!record) return json(200, { found: false, status: 'unknown' });
        return json(200, {
          found: true,
          status: options.verifyStatus ?? 'anchored',
          sequenceNumber: 276123,
          hcsExplorerUrl: `https://hashscan.io/mainnet/topic/0.0.10416909`,
          mirrorNodeUrl: 'https://mainnet.mirrornode.hedera.com',
          verified: true,
          source: 'warm-store',
          attestation: {
            attestationId: id,
            algorithm: 'ML-DSA-65',
            publicKey: 'mock-public-key',
            signature: 'mock-signature',
            data: record,
          },
        });
      }

      const isAttest =
        path === '/v1/tiered-attest' || path === '/v1/x402/tiered-attest';

      if (!isAttest) return json(404, { error: 'not found' });

      state.attempts++;

      if (options.down) return json(503, { error: 'service unavailable' });
      if (options.failFirst !== undefined && state.attempts <= options.failFirst) {
        return json(503, { error: 'temporarily unavailable' });
      }

      // Keyless path: demand payment before attesting.
      if (path === '/v1/x402/tiered-attest') {
        const payment =
          (req.headers['payment-signature'] as string | undefined) ??
          (req.headers['x-payment'] as string | undefined);
        if (!payment) {
          return json(402, {
            x402Version: 1,
            error: 'PAYMENT-SIGNATURE header is required',
            accepts: [
              {
                scheme: 'exact',
                network: 'eip155:8453',
                maxAmountRequired: options.attestPrice ?? '5000',
                payTo: RUBRIC_PAYEE,
                asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
                resource: `http://${req.headers.host}${path}`,
                maxTimeoutSeconds: 60,
              },
            ],
          });
        }
      } else {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey) return json(401, { error: 'x-api-key required' });
      }

      let parsed: { data?: unknown; sourceId?: string };
      try {
        parsed = JSON.parse(body) as { data?: unknown; sourceId?: string };
      } catch {
        return json(400, { error: 'invalid JSON' });
      }

      const attestationId = randomUUID();
      const record = options.corruptRoot
        ? { ...(parsed.data as object), root: 'f'.repeat(64) }
        : parsed.data;
      stored.set(attestationId, record);

      const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;

      if (path === '/v1/x402/tiered-attest') {
        return json(
          200,
          {
            success: true,
            paid: true,
            settled: true,
            settlement: { txHash: '0x' + 'ab'.repeat(32), network: 'base' },
            attestationId,
            algorithm: 'ML-DSA-65',
            topic: '0.0.10416909',
            verifyUrl: `${base}/v1/verify/${attestationId}`,
          },
          {
            'payment-response': Buffer.from(
              JSON.stringify({ success: true, transaction: '0x' + 'ab'.repeat(32), network: 'base' }),
            ).toString('base64'),
          },
        );
      }

      return json(200, {
        attestationId,
        payloadKey: 'a'.repeat(64),
        payloadCommitment: 'b'.repeat(64),
        status: 'buffered',
      });
    })();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    server,
    options,
    requests,
    stored,
    get attemptCount() {
      return state.attempts;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

/** A temp WAL directory unique to one test. */
export function tmpWal(name: string): string {
  return `./.tmp-test/${name}-${process.pid}-${Math.random().toString(36).slice(2, 8)}`;
}
