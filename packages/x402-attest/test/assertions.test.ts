import { describe, expect, it } from 'vitest';
import { amountToUsd, computeAssertions, type AssertionContext } from '../src/assertions.js';
import { ZERO, parseDecimal } from '../src/decimal.js';
import { tag } from '../src/hash.js';
import type { AssertionId } from '../src/types.js';

const PAYEE = '0x1111111111111111111111111111111111111111';
const OTHER = '0x3333333333333333333333333333333333333333';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

function ctx(over: Partial<AssertionContext> = {}): AssertionContext {
  return {
    policy: {
      maxPricePerCall: '0.05',
      allowedNetworks: ['eip155:8453'],
      allowedPayTo: [PAYEE],
      budgetCap: '25.00',
    },
    challenge: {
      scheme: 'exact',
      network: 'eip155:8453',
      maxAmountRequired: '1000',
      payTo: PAYEE,
      asset: USDC,
      rawHash: 'a'.repeat(64),
    },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      amountAuthorized: '1000',
      asset: USDC,
      payTo: PAYEE,
      xPaymentHash: 'b'.repeat(64),
    },
    settlement: { success: true, txHash: '0x' + 'c'.repeat(64), source: 'x-payment-response' },
    sessionSpendBefore: ZERO,
    assetDecimals: {},
    defaultAssetDecimals: 6,
    redact: 'hash-only',
    ...over,
  };
}

const get = (r: ReturnType<typeof computeAssertions>, id: AssertionId) =>
  r.assertions.find((a) => a.id === id)!;

describe('assertions', () => {
  it('records all eight, in a fixed order, on every call', () => {
    const r = computeAssertions(ctx());
    expect(r.assertions.map((a) => a.id)).toEqual([
      'price_matches_challenge',
      'payto_matches_challenge',
      'network_allowed',
      'payto_allowed',
      'price_within_policy',
      'budget_within_cap',
      'settled',
      'model_matches_request',
    ]);
  });

  it('passes everything on a clean, fully observed call', () => {
    const r = computeAssertions(ctx({ requestedModel: 'gpt-4o', servedModel: 'gpt-4o' }));
    expect(r.anyFailed).toBe(false);
    for (const a of r.assertions) expect(a.result).toBe('pass');
  });

  describe('price_matches_challenge', () => {
    it('fails when the client authorized more than the challenge advertised', () => {
      const r = computeAssertions(
        ctx({ payment: { ...ctx().payment!, amountAuthorized: '50000' } }),
      );
      const a = get(r, 'price_matches_challenge');
      expect(a.result).toBe('fail');
      expect(a.observed).toBe('50000');
      expect(a.expected).toBe('1000');
      expect(r.anyFailed).toBe(true);
    });

    it('compares numerically, so 1000 and 1000.0 are the same authorization', () => {
      const r = computeAssertions(
        ctx({ payment: { ...ctx().payment!, amountAuthorized: '1000.0' } }),
      );
      expect(get(r, 'price_matches_challenge').result).toBe('pass');
    });

    it('is unknown, never pass, when the challenge was not observed', () => {
      const r = computeAssertions(ctx({ challenge: undefined }));
      const a = get(r, 'price_matches_challenge');
      expect(a.result).toBe('unknown');
      expect(a.detail).toMatch(/no challenge/);
    });
  });

  describe('payto_matches_challenge', () => {
    it('fails when the payment went somewhere the challenge did not name', () => {
      const r = computeAssertions(ctx({ payment: { ...ctx().payment!, payTo: OTHER } }));
      expect(get(r, 'payto_matches_challenge').result).toBe('fail');
      expect(r.anyFailed).toBe(true);
    });

    it('treats EVM addresses case-insensitively', () => {
      const r = computeAssertions(
        ctx({ payment: { ...ctx().payment!, payTo: PAYEE.toUpperCase().replace('0X', '0x') } }),
      );
      expect(get(r, 'payto_matches_challenge').result).toBe('pass');
    });
  });

  describe('network_allowed', () => {
    it('fails on a network outside the policy', () => {
      const r = computeAssertions(
        ctx({ payment: { ...ctx().payment!, network: 'eip155:137' } }),
      );
      const a = get(r, 'network_allowed');
      expect(a.result).toBe('fail');
      expect(a.observed).toBe('eip155:137');
    });

    it('normalizes legacy network names before comparing', () => {
      // A challenge saying "base" satisfies a policy written as eip155:8453. Raw
      // string comparison would raise a violation that is not one.
      const r = computeAssertions(ctx({ payment: { ...ctx().payment!, network: 'base' } }));
      expect(get(r, 'network_allowed').result).toBe('pass');
      expect(get(r, 'network_allowed').observed).toBe('base');
    });

    it('is unknown when the policy sets no allowlist', () => {
      const r = computeAssertions(ctx({ policy: {} }));
      expect(get(r, 'network_allowed').result).toBe('unknown');
      expect(get(r, 'network_allowed').detail).toMatch(/not set/);
    });
  });

  describe('payto_allowed', () => {
    it('fails when the payee is not on the allowlist', () => {
      const r = computeAssertions(ctx({ payment: { ...ctx().payment!, payTo: OTHER } }));
      expect(get(r, 'payto_allowed').result).toBe('fail');
    });

    it('is unknown, not pass, when no allowlist is configured', () => {
      const r = computeAssertions(ctx({ policy: { maxPricePerCall: '0.05' } }));
      expect(get(r, 'payto_allowed').result).toBe('unknown');
    });
  });

  describe('price_within_policy', () => {
    it('fails when the call costs more than the per-call cap', () => {
      // 100000 atomic USDC == $0.10, over the $0.05 cap.
      const r = computeAssertions(
        ctx({ payment: { ...ctx().payment!, amountAuthorized: '100000' } }),
      );
      const a = get(r, 'price_within_policy');
      expect(a.result).toBe('fail');
      expect(a.observed).toBe('0.100000');
      expect(a.expected).toBe('0.05');
    });

    it('converts atomic units using the asset decimals, not raw integers', () => {
      // Without the conversion, 1000 > 0.05 would read as a violation.
      expect(get(computeAssertions(ctx()), 'price_within_policy').result).toBe('pass');
    });

    it('honours a per-asset decimals override', () => {
      const r = computeAssertions(
        ctx({
          assetDecimals: { [USDC.toLowerCase()]: 2 },
          payment: { ...ctx().payment!, amountAuthorized: '1000' },
        }),
      );
      // At 2 decimals, 1000 atomic is $10.00 and blows the cap.
      expect(get(r, 'price_within_policy').result).toBe('fail');
    });
  });

  describe('budget_within_cap', () => {
    it('fails when cumulative session spend crosses the cap', () => {
      const r = computeAssertions(
        ctx({
          sessionSpendBefore: parseDecimal('24.999'),
          payment: { ...ctx().payment!, amountAuthorized: '2000' },
        }),
      );
      const a = get(r, 'budget_within_cap');
      expect(a.result).toBe('fail');
      expect(a.observed).toBe('25.001000');
      expect(a.expected).toBe('25.00');
    });

    it('passes right up to the cap, inclusive', () => {
      const r = computeAssertions({
        ...ctx(),
        sessionSpendBefore: parseDecimal('24.999'),
        payment: { ...ctx().payment!, amountAuthorized: '1000' },
      });
      expect(get(r, 'budget_within_cap').result).toBe('pass');
    });

    it('uses exact decimal arithmetic, not floating point', () => {
      // 0.1 + 0.2 > 0.3 in IEEE754. It must not be a violation here.
      const r = computeAssertions(
        ctx({
          policy: { budgetCap: '0.3' },
          sessionSpendBefore: parseDecimal('0.1'),
          payment: { ...ctx().payment!, amountAuthorized: '0.2' },
          challenge: { ...ctx().challenge!, maxAmountRequired: '0.2' },
        }),
      );
      expect(get(r, 'budget_within_cap').result).toBe('pass');
    });

    it('reports unknown rather than pass when the call cannot be priced', () => {
      const r = computeAssertions(ctx({ payment: undefined, challenge: undefined }));
      const a = get(r, 'budget_within_cap');
      expect(a.result).toBe('unknown');
      expect(a.detail).toMatch(/lower bound/);
    });
  });

  describe('settled', () => {
    it('fails when the facilitator reported settlement failure', () => {
      const r = computeAssertions(
        ctx({ settlement: { success: false, source: 'x-payment-response' } }),
      );
      expect(get(r, 'settled').result).toBe('fail');
    });

    it('is unknown when no settlement receipt was served', () => {
      const r = computeAssertions(ctx({ settlement: undefined }));
      const a = get(r, 'settled');
      expect(a.result).toBe('unknown');
      expect(a.detail).toMatch(/no settlement receipt/);
    });

    it('is unknown when success is claimed without a transaction hash', () => {
      const r = computeAssertions(ctx({ settlement: { success: true, source: 'body' } }));
      expect(get(r, 'settled').result).toBe('unknown');
    });
  });

  describe('model_matches_request — proof of routing', () => {
    it('fails when the router substituted a cheaper model', () => {
      const r = computeAssertions(
        ctx({
          requestedModel: 'anthropic/claude-sonnet-4.6',
          servedModel: 'google/gemini-2.5-flash',
          servedModelSource: 'x-clawrouter-model',
        }),
      );
      const a = get(r, 'model_matches_request');
      expect(a.result).toBe('fail');
      expect(a.detail).toContain('x-clawrouter-model');
      expect(r.anyFailed).toBe(true);
    });

    it('hashes model names under hash-only so no body content is disclosed', () => {
      const r = computeAssertions(
        ctx({ requestedModel: 'gpt-4o', servedModel: 'gemini-2.5-flash' }),
      );
      const a = get(r, 'model_matches_request');
      expect(a.expected).toBe(tag('gpt-4o'));
      expect(a.observed).toBe(tag('gemini-2.5-flash'));
      expect(a.expected).not.toContain('gpt-4o');
      expect(a.observed).not.toContain('gemini');
    });

    it('keeps model names in clear under metadata mode', () => {
      const r = computeAssertions(
        ctx({ redact: 'metadata', requestedModel: 'gpt-4o', servedModel: 'gemini-2.5-flash' }),
      );
      expect(get(r, 'model_matches_request').observed).toBe('gemini-2.5-flash');
    });

    it('accepts an alias resolving to a pinned build', () => {
      const r = computeAssertions(
        ctx({ requestedModel: 'gpt-4o', servedModel: 'gpt-4o-2026-05-13' }),
      );
      expect(get(r, 'model_matches_request').result).toBe('pass');
    });

    it('is unknown — never pass — when the served model is undiscoverable', () => {
      const r = computeAssertions(ctx({ requestedModel: 'gpt-4o', servedModel: undefined }));
      const a = get(r, 'model_matches_request');
      expect(a.result).toBe('unknown');
      expect(a.detail).toMatch(/not discoverable/);
    });

    it('is unknown on a non-LLM route', () => {
      expect(get(computeAssertions(ctx()), 'model_matches_request').result).toBe('unknown');
    });
  });

  describe('amountToUsd', () => {
    it('treats integers as atomic units and decimals as already-USD', () => {
      const c = ctx();
      expect(amountToUsd('1000', USDC, c)!.scale).toBe(6);
      expect(amountToUsd('0.05', USDC, c)!.scale).toBe(2);
      expect(amountToUsd('unknown', USDC, c)).toBeNull();
      expect(amountToUsd('not-a-number', USDC, c)).toBeNull();
      expect(amountToUsd(undefined, USDC, c)).toBeNull();
    });
  });
});
