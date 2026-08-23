import { createHash } from 'node:crypto';
import type { FetchLike } from '../../src/types.js';

/**
 * Mock x402 payment client.
 *
 * Stands in for x402-fetch: on a 402 it reads the requirements, signs an
 * authorization, and retries with the payment header. The "signature" is a hash,
 * not real ECDSA — this library never validates signatures, it only records what
 * was authorized, so a real signer would add nothing to the tests.
 */

export type MockClientOptions = {
  /** Pay a different amount than advertised, to exercise price_matches_challenge. */
  overrideAmount?: string;
  /** Pay a different address than advertised. */
  overridePayTo?: string;
  /** Refuse to pay above this atomic amount. */
  maxAtomic?: bigint;
  /** Which header spelling to send. */
  headerName?: 'PAYMENT-SIGNATURE' | 'X-PAYMENT';
  /** Count of payments attempted. */
  onPay?: (amount: string) => void;
};

export const BUYER = '0x2222222222222222222222222222222222222222';

export function createMockX402Fetch(
  inner: FetchLike,
  options: MockClientOptions = {},
): FetchLike {
  const headerName = options.headerName ?? 'PAYMENT-SIGNATURE';

  return async (input, init) => {
    const first = await inner(input, init);
    if (first.status !== 402) return first;

    let challenge: { accepts?: Record<string, unknown>[] };
    try {
      challenge = (await first.clone().json()) as { accepts?: Record<string, unknown>[] };
    } catch {
      return first;
    }

    const req = challenge.accepts?.[0];
    if (!req) return first;

    const advertised = String(req['maxAmountRequired'] ?? '0');
    if (options.maxAtomic !== undefined && BigInt(advertised) > options.maxAtomic) {
      // A real client refuses and surfaces the 402 unchanged. The wrapper attests
      // that as payment_failed, which is precisely the record worth keeping.
      return first;
    }

    const amount = options.overrideAmount ?? advertised;
    const payTo = options.overridePayTo ?? String(req['payTo'] ?? '');
    options.onPay?.(amount);

    const authorization = {
      from: BUYER,
      to: payTo,
      value: amount,
      validAfter: '0',
      validBefore: '99999999999',
      nonce: '0x' + '11'.repeat(32),
    };

    const payload = {
      x402Version: 1,
      scheme: String(req['scheme'] ?? 'exact'),
      network: String(req['network'] ?? 'eip155:8453'),
      asset: String(req['asset'] ?? ''),
      payload: {
        // Stand-in for an EIP-3009 signature. Deterministic so tests can assert on it.
        signature:
          '0x' + createHash('sha256').update(JSON.stringify(authorization)).digest('hex'),
        authorization,
      },
    };

    const header = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64');
    const headers = new Headers(init?.headers as ConstructorParameters<typeof Headers>[0]);
    headers.set(headerName, header);

    return inner(input, { ...init, headers });
  };
}
