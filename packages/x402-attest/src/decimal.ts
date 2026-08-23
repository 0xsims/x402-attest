/**
 * Exact decimal arithmetic for money.
 *
 * Budgets and price caps are compared, summed, and written into an audit record,
 * so binary floating point is not an option: `0.1 + 0.2 > 0.3` would be a genuine
 * policy violation on paper. Everything here is BigInt over a fixed scale.
 */

export type Decimal = { neg: boolean; units: bigint; scale: number };

const DECIMAL_RE = /^[+-]?(\d+(\.\d*)?|\.\d+)$/;

export function isDecimalString(s: string): boolean {
  return DECIMAL_RE.test(s.trim());
}

/** Parse a decimal string. Throws on anything that is not plainly numeric. */
export function parseDecimal(input: string): Decimal {
  const s = input.trim();
  if (!DECIMAL_RE.test(s)) throw new Error(`not a decimal number: ${JSON.stringify(input)}`);

  const neg = s.startsWith('-');
  const body = s.replace(/^[+-]/, '');
  const [intPart = '0', fracPart = ''] = body.split('.');
  const units = BigInt((intPart || '0') + fracPart);
  return { neg: neg && units !== 0n, units, scale: fracPart.length };
}

function align(a: Decimal, b: Decimal): [bigint, bigint] {
  const scale = Math.max(a.scale, b.scale);
  const av = a.units * 10n ** BigInt(scale - a.scale);
  const bv = b.units * 10n ** BigInt(scale - b.scale);
  return [a.neg ? -av : av, b.neg ? -bv : bv];
}

/** -1, 0, 1. */
export function compareDecimal(a: Decimal, b: Decimal): number {
  const [av, bv] = align(a, b);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

export function addDecimal(a: Decimal, b: Decimal): Decimal {
  const scale = Math.max(a.scale, b.scale);
  const [av, bv] = align(a, b);
  const sum = av + bv;
  return { neg: sum < 0n, units: sum < 0n ? -sum : sum, scale };
}

export function formatDecimal(d: Decimal): string {
  const digits = d.units.toString().padStart(d.scale + 1, '0');
  const cut = digits.length - d.scale;
  const intPart = digits.slice(0, cut);
  const fracPart = d.scale > 0 ? '.' + digits.slice(cut) : '';
  return (d.neg && d.units !== 0n ? '-' : '') + intPart + fracPart;
}

export const ZERO: Decimal = { neg: false, units: 0n, scale: 0 };

/**
 * Convert an atomic on-chain amount to its human decimal form.
 *
 * x402 quotes `maxAmountRequired` in the asset's smallest unit (6 decimals for
 * USDC), while policy caps are written in USD. Comparing the two without this
 * conversion is the bug that lets a $50 call pass a $0.05 cap.
 */
export function atomicToDecimal(atomic: string, decimals: number): Decimal {
  const s = atomic.trim();
  if (!/^[+-]?\d+$/.test(s)) throw new Error(`not an integer amount: ${JSON.stringify(atomic)}`);
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 36) {
    throw new Error(`implausible asset decimals: ${decimals}`);
  }
  const neg = s.startsWith('-');
  const units = BigInt(s.replace(/^[+-]/, ''));
  return { neg: neg && units !== 0n, units, scale: decimals };
}

/** `a <= b`, both as decimal strings. Returns null when either side is unparseable. */
export function lte(a: string, b: string): boolean | null {
  try {
    return compareDecimal(parseDecimal(a), parseDecimal(b)) <= 0;
  } catch {
    return null;
  }
}
