import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { rmSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { createWalletClient, http } from 'viem';
import { base } from 'viem/chains';
import { wrapFetchWithPayment } from 'x402-fetch';
import { createTap, withAttestation } from '../src/index.js';
import type { AnyReceipt } from '../src/types.js';
import { startMockSeller, type MockSeller } from './mocks/seller.js';
import { tmpWal } from './mocks/rubric.js';

/**
 * The tap, against the real x402 client.
 *
 * Everything else in this suite proves the library is self-consistent. This one
 * proves the single assumption the design rests on and that a mock cannot test:
 * that `createTap()` can actually be installed underneath a real x402 client.
 *
 * If it cannot, the library still works and still tells the truth — but four of
 * the eight assertions degrade to `unknown` for every user, which is most of the
 * value gone. That is worth a real dependency in devDependencies.
 *
 * Uses x402-fetch 1.2.0 with a viem wallet built from a throwaway key. No funds
 * and no chain access are needed: the `exact` scheme signs an EIP-3009
 * authorization offline, and the mock seller does not verify signatures — we are
 * testing observability of the handshake, not settlement.
 */

const PAYEE = '0x1111111111111111111111111111111111111111';
// Throwaway key, never funded, never used anywhere else.
const THROWAWAY = '0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d';

describe('tap against the real x402 client (x402-fetch)', () => {
  let seller: MockSeller;
  let walPath: string;
  const cleanup: (() => Promise<void>)[] = [];

  beforeEach(async () => {
    // The real client selects requirements by network name, and
    // ChainIdToNetwork[8453] is "base" — not CAIP-2. Serve what it expects.
    seller = await startMockSeller({ network: 'base', maxAmountRequired: '1000' });
    walPath = tmpWal('real-client');
  });

  afterEach(async () => {
    for (const fn of cleanup.splice(0)) await fn();
    await seller.close();
    rmSync(walPath, { recursive: true, force: true });
  });

  function build() {
    const account = privateKeyToAccount(THROWAWAY);
    const wallet = createWalletClient({ account, chain: base, transport: http() });
    const receipts: AnyReceipt[] = [];
    const tap = createTap();

    // THE INTEGRATION POINT: the tap wraps the transport, the real client wraps
    // the tap, and the attestor wraps the client. wrapFetchWithPayment takes
    // fetch as its first argument and calls it, which is what makes this work.
    const x402Fetch = wrapFetchWithPayment(tap.wrapFetch(fetch), wallet);

    const fetchAndPay = withAttestation(x402Fetch as never, {
      subjectId: 'agent-alpha',
      walPath,
      mode: 'off',
      installSignalHandlers: false,
      tap,
      policy: {
        maxPricePerCall: '0.05',
        // Policy in CAIP-2, challenge in legacy "base". Normalization bridges them.
        allowedNetworks: ['eip155:8453'],
        allowedPayTo: [PAYEE],
        budgetCap: '25.00',
      },
      onReceipt: (r) => receipts.push(r),
    });
    cleanup.push(() => fetchAndPay.close().then(() => undefined));
    return { fetchAndPay, receipts };
  }

  it('observes the full handshake through a real client', async () => {
    const { fetchAndPay, receipts } = build();

    const res = await fetchAndPay(`${seller.url}/paid`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'world' }),
    });
    expect(res.status).toBe(200);

    // The real client paid: two requests, the second carrying X-PAYMENT.
    expect(seller.received).toHaveLength(1);

    const rec = receipts.at(-1)!.callRecord;

    // The challenge the real seller served, as the real client saw it.
    expect(rec.challenge).toBeDefined();
    expect(rec.challenge!.maxAmountRequired).toBe('1000');
    expect(rec.challenge!.payTo).toBe(PAYEE);
    expect(rec.challenge!.network).toBe('base');

    // The authorization the real client signed — captured, hashed, never stored.
    expect(rec.payment).toBeDefined();
    expect(rec.payment!.amountAuthorized).toBe('1000');
    expect(rec.payment!.payTo).toBe(PAYEE);
    expect(rec.payment!.xPaymentHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(rec)).not.toContain(seller.received[0]!);
  });

  it('produces real verdicts, not `unknown`, for the checks the tap enables', async () => {
    const { fetchAndPay, receipts } = build();
    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });

    const byId = new Map(receipts.at(-1)!.callRecord.assertions.map((a) => [a.id, a]));

    // These four are exactly the ones that are `unknown` without a tap.
    expect(byId.get('price_matches_challenge')!.result).toBe('pass');
    expect(byId.get('payto_matches_challenge')!.result).toBe('pass');
    expect(byId.get('price_within_policy')!.result).toBe('pass');
    expect(byId.get('budget_within_cap')!.result).toBe('pass');

    // Legacy "base" satisfies a CAIP-2 policy via the alias table.
    expect(byId.get('network_allowed')!.result).toBe('pass');
    expect(byId.get('network_allowed')!.observed).toBe('base');

    expect(receipts.at(-1)!.callRecord.outcome).toBe('ok');
  });

  it('detects a real overpayment — the client authorizing more than advertised', async () => {
    // Seller advertises 1000; the client is told the requirement is 5000.
    await seller.close();
    seller = await startMockSeller({ network: 'base', maxAmountRequired: '5000' });

    const { fetchAndPay, receipts } = build();
    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });

    const byId = new Map(receipts.at(-1)!.callRecord.assertions.map((a) => [a.id, a]));
    // Authorized matches what was advertised, so this passes...
    expect(byId.get('price_matches_challenge')!.result).toBe('pass');
    expect(byId.get('price_matches_challenge')!.observed).toBe('5000');
    // ...and the real signed amount is what the policy check sees.
    expect(byId.get('price_within_policy')!.observed).toBe('0.005000');
  });

  it('without the tap, those same four checks go unknown — the tap is the difference', async () => {
    // Same real client, same real seller, tap simply not installed underneath.
    // This is what makes the tap's value precise rather than asserted.
    const account = privateKeyToAccount(THROWAWAY);
    const wallet = createWalletClient({ account, chain: base, transport: http() });
    const receipts: AnyReceipt[] = [];
    const untapped = withAttestation(wrapFetchWithPayment(fetch, wallet) as never, {
      subjectId: 'agent-alpha',
      walPath,
      mode: 'off',
      installSignalHandlers: false,
      policy: { maxPricePerCall: '0.05', allowedNetworks: ['eip155:8453'], budgetCap: '25.00' },
      onReceipt: (r) => receipts.push(r),
    });
    cleanup.push(() => untapped.close().then(() => undefined));

    const res = await untapped(`${seller.url}/paid`, { method: 'POST', body: '{}' });
    expect(res.status).toBe(200);

    const byId = new Map(receipts.at(-1)!.callRecord.assertions.map((a) => [a.id, a]));
    // The 402 handshake happened entirely inside the client, so nothing about the
    // challenge or the authorization was observable.
    expect(receipts.at(-1)!.callRecord.challenge).toBeUndefined();
    expect(receipts.at(-1)!.callRecord.payment).toBeUndefined();
    for (const id of ['price_matches_challenge', 'payto_matches_challenge', 'price_within_policy'] as const) {
      expect(byId.get(id)!.result, id).toBe('unknown');
    }
    // Honest degradation: unknown, never an optimistic pass.
    expect([...byId.values()].some((a) => a.result === 'fail')).toBe(false);

    // The settlement header is on the final response, so this one survives either way.
    expect(byId.get('settled')!.result).toBe('pass');
  });

  it('confirms the header name the shipping client actually uses', async () => {
    // docs.x402.org documents PAYMENT-SIGNATURE; x402-fetch 1.2.0 sends X-PAYMENT.
    // Reading both is why this library observes anything at all here.
    const { fetchAndPay } = build();
    await fetchAndPay(`${seller.url}/paid`, { method: 'POST', body: '{}' });

    const decoded = JSON.parse(Buffer.from(seller.received[0]!, 'base64').toString('utf8'));
    expect(decoded.scheme).toBe('exact');
    expect(decoded.network).toBe('base');
    expect(decoded.payload.authorization.value).toBe('1000');
    expect(decoded.payload.authorization.to).toBe(PAYEE);
    // A real EIP-3009 signature from viem.
    expect(decoded.payload.signature).toMatch(/^0x[0-9a-f]{130}$/i);
  });
});
