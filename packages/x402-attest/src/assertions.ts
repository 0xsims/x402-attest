import {
  ZERO,
  addDecimal,
  atomicToDecimal,
  compareDecimal,
  formatDecimal,
  isDecimalString,
  parseDecimal,
  type Decimal,
} from './decimal.js';
import { tag } from './hash.js';
import { normalizeNetwork, sameAddress } from './x402.js';
import type {
  Assertion,
  AssertionId,
  ChallengeRecord,
  PaymentRecord,
  Policy,
  Redact,
  SettlementRecord,
} from './types.js';

/**
 * The assertion engine.
 *
 * A receipt that only says "I called X and paid Y" is a log line. What makes it an
 * audit artifact is the record of checks performed at the moment of the call, by
 * the party carrying the obligation, including the checks that could not be
 * completed. Hence `unknown` is never omitted and never silently upgraded to
 * `pass`.
 */

const UNKNOWN_LITERAL = 'unknown';

function known(v: string | undefined): v is string {
  return typeof v === 'string' && v.length > 0 && v !== UNKNOWN_LITERAL;
}

export type AssertionContext = {
  policy: Policy;
  challenge?: ChallengeRecord;
  payment?: PaymentRecord;
  settlement?: SettlementRecord;
  requestedModel?: string;
  servedModel?: string;
  servedModelSource?: string;
  /** Cumulative USD spend for this session BEFORE the current call. */
  sessionSpendBefore: Decimal;
  assetDecimals: Record<string, number>;
  defaultAssetDecimals: number;
  redact: Redact;
};

export type AssertionOutcome = {
  assertions: Assertion[];
  /** USD value of this call, for session budget accumulation. Zero when unknown. */
  spendUsd: Decimal;
  /** True when at least one assertion failed. Drives `outcome: 'policy_violation'`. */
  anyFailed: boolean;
};

/**
 * Under `hash-only` a model name is response-body content and must not appear in
 * clear. Hashing preserves the audit value — an auditor with the model name can
 * confirm the match — without the receipt disclosing what was served.
 */
function maybeHash(value: string, redact: Redact): string {
  return redact === 'metadata' ? value : tag(value);
}

function decimals(asset: string | undefined, ctx: AssertionContext): number {
  if (!asset) return ctx.defaultAssetDecimals;
  const key = asset.trim().toLowerCase();
  return ctx.assetDecimals[key] ?? ctx.defaultAssetDecimals;
}

/**
 * Interpret a wire amount as USD.
 *
 * x402 quotes atomic units of the asset, so `1000` USDC-atomic is $0.001. But some
 * facilitators echo the seller's configured `price` string, which is already
 * decimal USD. The presence of a decimal point disambiguates: atomic amounts are
 * integers by construction.
 */
export function amountToUsd(
  amount: string | undefined,
  asset: string | undefined,
  ctx: AssertionContext,
): Decimal | null {
  if (!known(amount)) return null;
  const s = amount.trim();
  try {
    if (s.includes('.')) return parseDecimal(s);
    if (!/^\d+$/.test(s)) return null;
    return atomicToDecimal(s, decimals(asset, ctx));
  } catch {
    return null;
  }
}

function mk(
  id: AssertionId,
  result: Assertion['result'],
  fields?: { observed?: string; expected?: string; detail?: string },
): Assertion {
  const a: Assertion = { id, result };
  if (fields?.observed !== undefined) a.observed = fields.observed;
  if (fields?.expected !== undefined) a.expected = fields.expected;
  if (fields?.detail !== undefined) a.detail = fields.detail;
  return a;
}

function priceMatchesChallenge(ctx: AssertionContext): Assertion {
  const id: AssertionId = 'price_matches_challenge';
  const authorized = ctx.payment?.amountAuthorized;
  const advertised = ctx.challenge?.maxAmountRequired;

  if (!known(authorized) || !known(advertised)) {
    return mk(id, 'unknown', {
      observed: authorized,
      expected: advertised,
      detail: !ctx.payment
        ? 'no payment observed'
        : !ctx.challenge
          ? 'no challenge observed'
          : 'amount not present on the wire',
    });
  }

  // Numeric, not string, comparison: "1000" and "1000.0" authorize the same value
  // and a string compare would raise a false violation.
  let match: boolean;
  if (isDecimalString(authorized) && isDecimalString(advertised)) {
    match = compareDecimal(parseDecimal(authorized), parseDecimal(advertised)) === 0;
  } else {
    match = authorized === advertised;
  }
  return mk(id, match ? 'pass' : 'fail', { observed: authorized, expected: advertised });
}

function payToMatchesChallenge(ctx: AssertionContext): Assertion {
  const id: AssertionId = 'payto_matches_challenge';
  const paid = ctx.payment?.payTo;
  const named = ctx.challenge?.payTo;
  const same = known(paid) && known(named) ? sameAddress(paid, named) : null;
  if (same === null) {
    return mk(id, 'unknown', {
      observed: known(paid) ? paid : undefined,
      expected: known(named) ? named : undefined,
      detail: 'payee not observable on both sides',
    });
  }
  return mk(id, same ? 'pass' : 'fail', { observed: paid, expected: named });
}

function networkAllowed(ctx: AssertionContext): Assertion {
  const id: AssertionId = 'network_allowed';
  const allowed = ctx.policy.allowedNetworks;
  const observedRaw = known(ctx.payment?.network)
    ? ctx.payment!.network
    : known(ctx.challenge?.network)
      ? ctx.challenge!.network
      : undefined;

  if (!allowed || allowed.length === 0) {
    return mk(id, 'unknown', { observed: observedRaw, detail: 'policy.allowedNetworks not set' });
  }
  if (!observedRaw) {
    return mk(id, 'unknown', {
      expected: allowed.join(','),
      detail: 'no network observed',
    });
  }
  const norm = normalizeNetwork(observedRaw);
  const ok = allowed.some((a) => normalizeNetwork(a) === norm);
  return mk(id, ok ? 'pass' : 'fail', { observed: observedRaw, expected: allowed.join(',') });
}

function payToAllowed(ctx: AssertionContext): Assertion {
  const id: AssertionId = 'payto_allowed';
  const allowed = ctx.policy.allowedPayTo;
  const observed = known(ctx.payment?.payTo)
    ? ctx.payment!.payTo
    : known(ctx.challenge?.payTo)
      ? ctx.challenge!.payTo
      : undefined;

  if (!allowed || allowed.length === 0) {
    return mk(id, 'unknown', { observed, detail: 'policy.allowedPayTo not set' });
  }
  if (!observed) {
    return mk(id, 'unknown', { expected: allowed.join(','), detail: 'no payee observed' });
  }
  const ok = allowed.some((a) => sameAddress(a, observed) === true);
  return mk(id, ok ? 'pass' : 'fail', { observed, expected: allowed.join(',') });
}

function priceWithinPolicy(ctx: AssertionContext, spend: Decimal | null): Assertion {
  const id: AssertionId = 'price_within_policy';
  const cap = ctx.policy.maxPricePerCall;
  if (!cap) {
    return mk(id, 'unknown', { detail: 'policy.maxPricePerCall not set' });
  }
  if (spend === null) {
    return mk(id, 'unknown', { expected: cap, detail: 'no priceable amount observed' });
  }
  let capDec: Decimal;
  try {
    capDec = parseDecimal(cap);
  } catch {
    return mk(id, 'unknown', { expected: cap, detail: 'policy.maxPricePerCall unparseable' });
  }
  const ok = compareDecimal(spend, capDec) <= 0;
  return mk(id, ok ? 'pass' : 'fail', { observed: formatDecimal(spend), expected: cap });
}

function budgetWithinCap(ctx: AssertionContext, spend: Decimal | null): Assertion {
  const id: AssertionId = 'budget_within_cap';
  const cap = ctx.policy.budgetCap;
  if (!cap) return mk(id, 'unknown', { detail: 'policy.budgetCap not set' });

  let capDec: Decimal;
  try {
    capDec = parseDecimal(cap);
  } catch {
    return mk(id, 'unknown', { expected: cap, detail: 'policy.budgetCap unparseable' });
  }

  const cumulative = addDecimal(ctx.sessionSpendBefore, spend ?? ZERO);
  const ok = compareDecimal(cumulative, capDec) <= 0;

  // An unpriceable call still reports cumulative spend, flagged as a lower bound —
  // "we cannot price this call" must not read as "the budget is fine".
  const detail =
    spend === null
      ? 'current call not priceable; cumulative figure is a lower bound'
      : undefined;
  return mk(id, spend === null && ok ? 'unknown' : ok ? 'pass' : 'fail', {
    observed: formatDecimal(cumulative),
    expected: cap,
    detail,
  });
}

function settled(ctx: AssertionContext): Assertion {
  const id: AssertionId = 'settled';
  const s = ctx.settlement;
  if (!s || s.source === 'none') {
    return mk(id, 'unknown', {
      detail: ctx.payment ? 'no settlement receipt observed' : 'no payment made',
    });
  }
  if (!s.success) {
    return mk(id, 'fail', { observed: 'success=false', detail: `source=${s.source}` });
  }
  if (!s.txHash) {
    return mk(id, 'unknown', {
      observed: 'success=true',
      detail: `settlement reported success without a transaction hash (source=${s.source})`,
    });
  }
  return mk(id, 'pass', { observed: s.txHash, detail: `source=${s.source}` });
}

/**
 * Proof of routing.
 *
 * A router that quietly serves a cheaper model than the one requested is the
 * single most consequential thing a buyer cannot otherwise prove after the fact.
 * When neither side is discoverable the result is `unknown` — guessing `pass` here
 * would turn the receipt into an alibi for the behaviour it exists to detect.
 */
function modelMatchesRequest(ctx: AssertionContext): Assertion {
  const id: AssertionId = 'model_matches_request';
  const requested = ctx.requestedModel;
  const served = ctx.servedModel;

  if (!requested && !served) {
    return mk(id, 'unknown', { detail: 'not an LLM route, or no model field present' });
  }
  if (!requested) {
    return mk(id, 'unknown', {
      observed: maybeHash(served!, ctx.redact),
      detail: 'model served but none requested',
    });
  }
  if (!served) {
    return mk(id, 'unknown', {
      expected: maybeHash(requested, ctx.redact),
      detail: 'model requested but served model not discoverable',
    });
  }

  // Routers legitimately resolve an alias to a pinned build
  // ("gpt-4o" -> "gpt-4o-2026-05-13"). Prefix-matching that case as a pass, and
  // anything else as a fail, is the distinction that matters to a buyer.
  const r = requested.trim().toLowerCase();
  const s = served.trim().toLowerCase();
  const match = r === s || s.startsWith(r + '-') || r.startsWith(s + '-');

  return mk(id, match ? 'pass' : 'fail', {
    observed: maybeHash(served, ctx.redact),
    expected: maybeHash(requested, ctx.redact),
    detail: ctx.servedModelSource ? `served-model source=${ctx.servedModelSource}` : undefined,
  });
}

/** Compute all eight assertions, in a fixed order so leaf hashes stay comparable. */
export function computeAssertions(ctx: AssertionContext): AssertionOutcome {
  const spend = amountToUsd(
    ctx.payment?.amountAuthorized ?? ctx.challenge?.maxAmountRequired,
    ctx.payment?.asset ?? ctx.challenge?.asset,
    ctx,
  );

  const assertions: Assertion[] = [
    priceMatchesChallenge(ctx),
    payToMatchesChallenge(ctx),
    networkAllowed(ctx),
    payToAllowed(ctx),
    priceWithinPolicy(ctx, spend),
    budgetWithinCap(ctx, spend),
    settled(ctx),
    modelMatchesRequest(ctx),
  ];

  return {
    assertions,
    spendUsd: spend ?? ZERO,
    anyFailed: assertions.some((a) => a.result === 'fail'),
  };
}
