import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createHash, randomUUID } from 'node:crypto';
import { jcs } from '../../src/jcs.js';

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
  /**
   * Serve a different commitment from /v1/verify than the one issued at
   * submission, so verification detects a receipt bound to another payload.
   */
  corruptCommitment?: boolean;
};

export type MockRubric = {
  url: string;
  server: Server;
  options: MockRubricOptions;
  /** Everything received, byte for byte, for the no-plaintext test. */
  requests: { path: string; headers: Record<string, string | string[] | undefined>; body: string }[];
  stored: Map<string, StoredAttestation>;
  attemptCount: number;
  close: () => Promise<void>;
};

const RUBRIC_PAYEE = '0x9999999999999999999999999999999999999999';

/** Fixed so tests can derive the same opening salt the server would. */
export const PAYLOAD_KEY = 'a'.repeat(64);

/** What the node retains: a commitment, never the plaintext payload. */
export type StoredAttestation = {
  commitment: string;
  payloadHash: string;
  /** Kept only so tests can assert on what was sent; the real node encrypts this. */
  submitted: unknown;
};

export async function startMockRubric(options: MockRubricOptions = {}): Promise<MockRubric> {
  const requests: MockRubric['requests'] = [];
  const stored = new Map<string, StoredAttestation>();
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
        if (!record) {
          return json(200, {
            found: false,
            id,
            scannedPages: 30,
            note:
              "Not found in this node's stores, in any peer node, or on HCS. " +
              'Tiered attestations are Merkle-batched and are not published to HCS as ' +
              'individual messages, so a mirror-node scan cannot resolve one by id; ' +
              "they resolve from the serving node's store.",
          });
        }

        // Mirrors the shape observed against the live mainnet node on 2026-08-23.
        //
        // The submitted payload is NOT echoed back. Tiered payloads are encrypted at
        // rest and the endpoint exposes only `payload.payload_commitment` and
        // `payload_hash`. An earlier version of this mock returned `data: <submitted
        // payload>`, which is what the verifier was written against — the mock
        // encoded the assumption and then validated it, so a verifier that could
        // never work against the real API passed every test.
        //
        // The commitment is echoed exactly as issued at submission time. How Rubric
        // derives it is deliberately NOT modelled here: that is unconfirmed, and
        // guessing it in a mock is the same mistake a second time.
        return json(200, {
          found: true,
          status: options.verifyStatus ?? 'anchored',
          verified: true,
          payloadHashMatch: true,
          aggregateBinding: 'strong',
          source: 'warm-store',
          sequenceNumber: 291514,
          hcsTopicId: '0.0.10416909',
          hcsSequence: 291514,
          hcsExplorerUrl: 'https://hashscan.io/mainnet/topic/0.0.10416909',
          mirrorNodeUrl:
            'https://mainnet-public.mirrornode.hedera.com/api/v1/topics/0.0.10416909/messages?sequencenumber=291514&limit=1',
          note:
            'Attestation is ML-DSA-65 signed and anchored on Hedera HCS. Verify ' +
            'independently via HashScan or Mirror Node — no Rubric involvement required.',
          reason: 'tiered: leaf re-derived, inclusion proven, envelope signature valid',
          attestation: {
            attestation_id: id,
            attestation_type: 'tiered',
            rubric_version: '1.0',
            issuer_node_region: 'us',
            issued_at: new Date(0).toISOString(),
            payload: {
              payload_commitment: options.corruptCommitment ? 'f'.repeat(64) : record.commitment,
            },
            payload_hash: record.payloadHash,
            merkle_proof: ['e810aa20f40fd5a0ee3bb4b1781c2a3159e657771dbbde9482195eff62a933a8'],
            merkle_proof_directions: ['R'],
            batch_root: '069d3474e45511ecc48e08d4e7d1060253c06dd856bac5d12d1cbe44234209a4',
            batch_size: 2,
            publicKey: 'mock-ml-dsa-65-public-key',
            signature: 'mock-ml-dsa-65-signature',
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

      // Rubric's actual commitment scheme, confirmed against the server source:
      //   salt       = SHA-256(payloadKeyHex + ':rubric-commit-v1')
      //   commitment = SHA-256(salt + RFC8785(payload))
      // The salt is one-way in the key, which is why a receipt can publish it.
      const canonical = jcs(parsed.data);
      const salt = createHash('sha256')
        .update(PAYLOAD_KEY + ':rubric-commit-v1')
        .digest('hex');
      const commitment = createHash('sha256').update(salt + canonical).digest('hex');
      const payloadHash = createHash('sha256').update(canonical).digest('hex');
      stored.set(attestationId, { commitment, payloadHash, submitted: parsed.data });

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
            payloadKey: PAYLOAD_KEY,
            payloadCommitment: commitment,
            payloadHash,
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
        payloadKey: PAYLOAD_KEY,
        payloadCommitment: commitment,
        payloadHash,
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
