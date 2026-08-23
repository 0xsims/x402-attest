/**
 * JSON Canonicalization Scheme (RFC 8785).
 *
 * The leaf hash is the evidence, so serialization has to be byte-identical across
 * runs, machines, Node versions and languages. That rules out `JSON.stringify` on
 * its own: property order there follows insertion order, so two structurally equal
 * records built by different code paths hash differently.
 *
 * RFC 8785 pins three things and we implement each explicitly below:
 *   1. Property names sorted by UTF-16 code unit (§3.2.3).
 *   2. Numbers serialized per ECMAScript `Number::toString` (§3.2.2.3).
 *   3. Strings escaped with the minimal JSON escape set (§3.2.2.2).
 */

/** Values that survive canonicalization. `undefined` members are dropped. */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue | undefined };

export class JcsError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'JcsError';
  }
}

/**
 * Anything needing an escape: a quote, a backslash, or a C0 control.
 *
 * Almost every string in a call record — hex digests, hostnames, ISO timestamps,
 * CAIP-2 network ids — contains none of them, and string serialization is the
 * hottest thing in the leaf path. Testing once and wrapping in quotes is
 * byte-identical to walking the string, and measurably cheaper at the tail.
 */
const NEEDS_ESCAPE = /["\\\u0000-\u001f]/;

/**
 * RFC 8785 §3.2.2.2 — escape only what JSON requires, using the short forms where
 * they exist and lowercase `\u00xx` otherwise. A canonicalizer that also escaped,
 * say, the solidus would still emit valid JSON but would hash differently.
 */

function serializeString(s: string): string {
  if (!NEEDS_ESCAPE.test(s)) return '"' + s + '"';

  let out = '"';
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    switch (c) {
      case 0x08:
        out += '\\b';
        break;
      case 0x09:
        out += '\\t';
        break;
      case 0x0a:
        out += '\\n';
        break;
      case 0x0c:
        out += '\\f';
        break;
      case 0x0d:
        out += '\\r';
        break;
      case 0x22:
        out += '\\"';
        break;
      case 0x5c:
        out += '\\\\';
        break;
      default:
        if (c < 0x20) {
          out += '\\u' + c.toString(16).padStart(4, '0');
        } else {
          // Non-ASCII is emitted literally; the output is UTF-8 encoded at the end.
          out += s[i];
        }
    }
  }
  return out + '"';
}

/**
 * RFC 8785 §3.2.2.3 defers to ECMAScript number-to-string, which is exactly what
 * `String(n)` gives us — with two exceptions the RFC forbids outright, and the
 * `-0` case, which ECMAScript renders as `0`.
 */
function serializeNumber(n: number): string {
  if (!Number.isFinite(n)) {
    throw new JcsError(`non-finite number cannot be canonicalized: ${n}`);
  }
  if (n === 0) return '0'; // collapses -0
  return String(n);
}

/**
 * RFC 8785 §3.2.3 sorts on UTF-16 code units, which is precisely what JavaScript's
 * default string comparison does. This is deliberate on the RFC's part and means
 * we must NOT sort by code point (which differs for astral-plane keys).
 */
function compareKeys(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

function canonicalize(value: unknown, seen: Set<object>): string {
  if (value === null) return 'null';

  const t = typeof value;
  if (t === 'boolean') return value ? 'true' : 'false';
  if (t === 'number') return serializeNumber(value as number);
  if (t === 'string') return serializeString(value as string);
  if (t === 'bigint') {
    throw new JcsError('bigint cannot be canonicalized; convert to string first');
  }
  if (t === 'undefined' || t === 'function' || t === 'symbol') {
    throw new JcsError(`value of type ${t} cannot be canonicalized`);
  }

  const obj = value as object;
  if (seen.has(obj)) throw new JcsError('circular reference cannot be canonicalized');
  seen.add(obj);
  try {
    if (Array.isArray(obj)) {
      // Array order is meaningful and is preserved. `undefined` and non-serializable
      // holes become `null`, matching JSON.stringify.
      const parts = obj.map((v) =>
        v === undefined || typeof v === 'function' || typeof v === 'symbol'
          ? 'null'
          : canonicalize(v, seen),
      );
      return '[' + parts.join(',') + ']';
    }

    const rec = obj as Record<string, unknown>;
    const keys = Object.keys(rec)
      .filter((k) => {
        const v = rec[k];
        return v !== undefined && typeof v !== 'function' && typeof v !== 'symbol';
      })
      .sort(compareKeys);

    const parts = keys.map((k) => serializeString(k) + ':' + canonicalize(rec[k], seen));
    return '{' + parts.join(',') + '}';
  } finally {
    seen.delete(obj);
  }
}

/** Canonical JSON text (RFC 8785). */
export function jcs(value: unknown): string {
  return canonicalize(value, new Set());
}

/** Canonical JSON as UTF-8 bytes — the exact input to the leaf hash. */
export function jcsBytes(value: unknown): Buffer {
  return Buffer.from(jcs(value), 'utf8');
}
