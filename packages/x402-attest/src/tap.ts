import { AsyncLocalStorage } from 'node:async_hooks';
import {
  CHALLENGE_HEADERS,
  PAYMENT_HEADERS,
  SETTLEMENT_HEADERS,
  pickHeader,
} from './x402.js';
import type { FetchLike, TapObservation, X402Tap } from './types.js';

/**
 * Transport-level observer for the x402 payment handshake.
 *
 * `withAttestation` wraps an x402 client that resolves 402 -> pay -> retry
 * internally. From outside that client only the final 200 is visible, so the
 * challenge the seller served and the authorization the client signed — the two
 * inputs to half the assertions — are invisible.
 *
 * Installing this tap underneath the x402 client is what turns
 * `price_matches_challenge` and `payto_matches_challenge` from `unknown` into real
 * checks. It is optional: without it the library still produces valid receipts,
 * they just assert less. That tradeoff is stated plainly in the README rather than
 * papered over.
 *
 * Correlation uses AsyncLocalStorage, so concurrent calls through the same tapped
 * fetch cannot attribute one call's challenge to another's receipt.
 */

function headersOf(input: string | URL | Request, init?: RequestInit): Headers | undefined {
  try {
    if (init?.headers) return new Headers(init.headers as ConstructorParameters<typeof Headers>[0]);
    if (typeof input === 'object' && input !== null && 'headers' in input) {
      return (input as Request).headers;
    }
  } catch {
    /* malformed headers are the caller's problem, not an attestation failure */
  }
  return undefined;
}

export function createTap(): X402Tap {
  const als = new AsyncLocalStorage<TapObservation>();

  const wrapFetch = (inner: FetchLike): FetchLike => {
    return async (input, init) => {
      const store = als.getStore();

      // Outgoing: capture the payment authorization by hash only. The value is
      // read here and never stored — `parsePaymentHeader` hashes it and discards
      // the plaintext.
      if (store) {
        store.attempts++;
        const sent = pickHeader(headersOf(input, init), PAYMENT_HEADERS);
        if (sent) {
          store.paymentHeader = sent.value;
          store.paymentHeaderName = sent.name;
        }
      }

      const res = await inner(input, init);
      if (!store) return res;

      // Incoming: the 402 carries the requirements, either as a header or as the
      // body. Only 402s are cloned and read; every other response passes through
      // untouched so we add nothing to the hot path.
      const challengeHeader = pickHeader(res.headers, CHALLENGE_HEADERS);
      if (challengeHeader) store.challengeRaw = challengeHeader.value;

      if (res.status === 402 && !store.challengeBody) {
        try {
          const text = await res.clone().text();
          store.challengeRaw ??= text;
          store.challengeBody = JSON.parse(text);
        } catch {
          /* an unparseable 402 body still leaves challengeRaw for hashing */
        }
      }

      const settlement = pickHeader(res.headers, SETTLEMENT_HEADERS);
      if (settlement) store.settlementHeader = settlement.value;

      return res;
    };
  };

  return {
    wrapFetch,
    __run: <T>(fn: () => Promise<T>): Promise<T> => als.run({ attempts: 0 }, fn),
    __take: (): TapObservation => als.getStore() ?? { attempts: 0 },
  };
}
