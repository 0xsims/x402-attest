import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';

/**
 * Mock x402 seller, with the facilitator's settlement role folded in.
 *
 * Serves a real 402 challenge, checks that a payment header arrived, and returns a
 * `PAYMENT-RESPONSE` settlement receipt.
 *
 * The three x402 roles across this directory:
 *   seller.ts     — this file. Prices the resource, serves the 402, and reports
 *                   settlement. Real deployments split the settlement half out to
 *                   a facilitator, but from the buyer's side — which is the only
 *                   side this library observes — the wire is identical: a 402 in,
 *                   a `PAYMENT-RESPONSE` header out. Splitting them here would add
 *                   a process without adding an observable difference.
 *   x402client.ts — the buyer's payment client. Reads requirements, signs an
 *                   authorization, retries.
 *   rubric.ts     — the attestation node, including its own x402-paid endpoint.
 *
 * No live network anywhere in the test suite.
 *
 * Failure modes are configurable because the failures are the interesting part:
 * `settlementFails`, `rejectPayment`, `omitSettlementHeader`,
 * `settleToDifferentPayee`.
 */

export type SellerConfig = {
  /** Atomic units of the asset. USDC has 6 decimals, so 1000 == $0.001. */
  maxAmountRequired: string;
  payTo: string;
  network: string;
  scheme: string;
  asset: string;
  /** Model name to report in the response body and routing header. */
  servedModel?: string;
  /** Advertise one payee but bank the payment somewhere else. */
  settleToDifferentPayee?: string;
  /** Report settlement failure. */
  settlementFails?: boolean;
  /** Omit the settlement header entirely. */
  omitSettlementHeader?: boolean;
  /** Refuse the payment and return a second 402. */
  rejectPayment?: boolean;
  /** Respond with SSE instead of JSON. */
  stream?: boolean;
  /** Artificial delay before responding, ms. */
  delayMs?: number;
  /** Body returned on success. */
  responseBody?: unknown;
};

export const DEFAULT_SELLER: SellerConfig = {
  maxAmountRequired: '1000',
  payTo: '0x1111111111111111111111111111111111111111',
  network: 'eip155:8453',
  scheme: 'exact',
  asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
};

export type MockSeller = {
  url: string;
  server: Server;
  config: SellerConfig;
  /** Every payment header the seller received, for assertions. */
  received: string[];
  /** Everything the seller was sent, to prove no plaintext leaks the other way. */
  requestBodies: string[];
  close: () => Promise<void>;
};

function b64(v: unknown): string {
  return Buffer.from(JSON.stringify(v), 'utf8').toString('base64');
}

export async function startMockSeller(
  overrides: Partial<SellerConfig> = {},
): Promise<MockSeller> {
  const config: SellerConfig = { ...DEFAULT_SELLER, ...overrides };
  const received: string[] = [];
  const requestBodies: string[] = [];

  const server = createServer((req, res) => {
    void (async () => {
      const chunks: Buffer[] = [];
      for await (const c of req) chunks.push(c as Buffer);
      const rawBody = Buffer.concat(chunks).toString('utf8');
      if (rawBody) requestBodies.push(rawBody);

      const payment =
        (req.headers['payment-signature'] as string | undefined) ??
        (req.headers['x-payment'] as string | undefined);

      if (config.delayMs) await new Promise((r) => setTimeout(r, config.delayMs));

      if (!payment || config.rejectPayment) {
        if (payment) received.push(payment);
        const challenge = {
          x402Version: 1,
          error: payment ? 'payment rejected' : 'PAYMENT-SIGNATURE header is required',
          accepts: [
            {
              scheme: config.scheme,
              network: config.network,
              maxAmountRequired: config.maxAmountRequired,
              payTo: config.payTo,
              asset: config.asset,
              resource: `http://${req.headers.host}${req.url}`,
              description: 'mock paid resource',
              mimeType: 'application/json',
              maxTimeoutSeconds: 60,
              extra: { name: 'USDC', version: '2' },
            },
          ],
        };
        res.writeHead(402, {
          'content-type': 'application/json',
          'x-request-id': 'req-402',
        });
        res.end(JSON.stringify(challenge));
        return;
      }

      received.push(payment);

      const headers: Record<string, string> = {
        'content-type': config.stream ? 'text/event-stream' : 'application/json',
        'x-request-id': 'req-200',
        // Never captured: the allowlist must drop this.
        'set-cookie': 'session=super-secret-cookie',
        authorization: 'Bearer leaked-token-should-not-be-captured',
      };

      if (!config.omitSettlementHeader) {
        headers['payment-response'] = b64({
          success: !config.settlementFails,
          transaction: config.settlementFails
            ? undefined
            : '0xabc123def4567890abc123def4567890abc123def4567890abc123def4567890',
          network: config.network,
          payer: config.settleToDifferentPayee ?? '0x2222222222222222222222222222222222222222',
        });
      }

      if (config.servedModel) headers['x-clawrouter-model'] = config.servedModel;

      if (config.stream) {
        res.writeHead(200, headers);
        const model = config.servedModel ?? 'mock-model';
        res.write(`data: ${JSON.stringify({ model, choices: [{ delta: { content: 'he' } }] })}\n\n`);
        await new Promise((r) => setTimeout(r, 5));
        res.write(`data: ${JSON.stringify({ model, choices: [{ delta: { content: 'llo' } }] })}\n\n`);
        res.write('data: [DONE]\n\n');
        res.end();
        return;
      }

      const body = config.responseBody ?? {
        id: 'chatcmpl-mock',
        model: config.servedModel ?? 'mock-model',
        choices: [{ index: 0, message: { role: 'assistant', content: 'mock completion' } }],
        usage: { prompt_tokens: 11, completion_tokens: 7, total_tokens: 18 },
      };
      res.writeHead(200, headers);
      res.end(JSON.stringify(body));
    })();
  });

  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;

  return {
    url: `http://127.0.0.1:${port}`,
    server,
    config,
    received,
    requestBodies,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
