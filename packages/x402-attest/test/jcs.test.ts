import { describe, expect, it } from 'vitest';
import { JcsError, jcs, jcsBytes } from '../src/jcs.js';
import { sha256Jcs } from '../src/hash.js';

describe('JCS (RFC 8785) canonicalization', () => {
  it('produces an identical hash regardless of key insertion order', () => {
    const a = { alpha: 1, beta: 2, gamma: { delta: 3, epsilon: 4 } };
    const b = { gamma: { epsilon: 4, delta: 3 }, beta: 2, alpha: 1 };
    const c = { beta: 2, gamma: { delta: 3, epsilon: 4 }, alpha: 1 };

    expect(jcs(a)).toBe(jcs(b));
    expect(jcs(b)).toBe(jcs(c));
    expect(sha256Jcs(a)).toBe(sha256Jcs(b));
    // JSON.stringify does NOT have this property, which is the whole reason JCS exists.
    expect(JSON.stringify(a)).not.toBe(JSON.stringify(b));
  });

  it('sorts keys by UTF-16 code unit, not by locale', () => {
    // Locale-aware sorting would order these differently in several locales.
    const obj = { b: 1, A: 2, a: 3, B: 4, '0': 5, _: 6 };
    expect(jcs(obj)).toBe('{"0":5,"A":2,"B":4,"_":6,"a":3,"b":1}');
  });

  it('handles non-ASCII keys and values deterministically', () => {
    const a = { '\u043a\u043b\u044e\u0447': '\u0437\u043d\u0430\u0447', '\u30ad\u30fc': '\u5024', 'emoji-\u{1f511}': '\u{1f389}', '\u00e4': 1, z: 2 };
    const b = { z: 2, '\u00e4': 1, 'emoji-\u{1f511}': '\u{1f389}', '\u30ad\u30fc': '\u5024', '\u043a\u043b\u044e\u0447': '\u0437\u043d\u0430\u0447' };
    expect(jcs(a)).toBe(jcs(b));
    // Non-ASCII is emitted literally and UTF-8 encoded, not backslash-u escaped.
    expect(jcsBytes(a).toString('utf8')).toContain('\u0437\u043d\u0430\u0447');
    expect(jcs(a)).not.toContain('\\u043a');
  });

  it('sorts astral-plane keys by UTF-16 code unit as the RFC requires', () => {
    // U+10000 is the surrogate pair D800 DC00, so by code UNIT it sorts before
    // U+FFFD. By code POINT it would sort after. RFC 8785 mandates code units,
    // and getting this backwards would make astral-keyed records unverifiable
    // against any conforming implementation.
    const obj: Record<string, number> = { '\u{10000}': 1, '\ufffd': 2 };
    const out = jcs(obj);
    expect(out.indexOf('\u{10000}')).toBeLessThan(out.indexOf('\ufffd'));
  });

  it('escapes only what JSON requires, with the short forms', () => {
    expect(jcs({ s: 'a"b\\c\nd\te\bf\fg\rh' })).toBe(
      '{"s":"a\\"b\\\\c\\nd\\te\\bf\\fg\\rh"}',
    );
    // Other control characters use lowercase backslash-u00xx.
    expect(jcs({ s: '\u0001' })).toBe('{"s":"\\u0001"}');
    expect(jcs({ s: '\u001f' })).toBe('{"s":"\\u001f"}');
    // Solidus is NOT escaped.
    expect(jcs({ s: 'a/b' })).toBe('{"s":"a/b"}');
  });

  it('serializes numbers per ECMAScript and collapses negative zero', () => {
    expect(jcs({ n: 1 })).toBe('{"n":1}');
    expect(jcs({ n: 1.5 })).toBe('{"n":1.5}');
    expect(jcs({ n: -0 })).toBe('{"n":0}');
    expect(jcs({ n: 1e21 })).toBe('{"n":1e+21}');
    expect(jcs({ n: 1e-7 })).toBe('{"n":1e-7}');
    expect(jcs({ n: Number.MAX_SAFE_INTEGER })).toBe('{"n":9007199254740991}');
  });

  it('preserves array order, because array order is meaningful', () => {
    expect(jcs([3, 1, 2])).toBe('[3,1,2]');
    expect(jcs([3, 1, 2])).not.toBe(jcs([1, 2, 3]));
  });

  it('drops undefined members and renders array holes as null', () => {
    expect(jcs({ a: 1, b: undefined })).toBe('{"a":1}');
    expect(jcs([1, undefined, 3])).toBe('[1,null,3]');
  });

  it('canonicalizes deeply nested structures identically', () => {
    const deep = (order: string[]) => {
      const leaf: Record<string, unknown> = {};
      for (const k of order) leaf[k] = { [k]: [1, { z: k, a: k }] };
      return { root: leaf, meta: { b: 2, a: 1 } };
    };
    expect(sha256Jcs(deep(['x', 'y', 'z']))).toBe(sha256Jcs(deep(['z', 'y', 'x'])));
  });

  it('is stable across repeated invocations', () => {
    const value = { a: [1, 2, { b: 'c' }], d: null, e: true };
    const first = sha256Jcs(value);
    for (let i = 0; i < 100; i++) expect(sha256Jcs(structuredClone(value))).toBe(first);
  });

  it('refuses values that have no canonical form', () => {
    expect(() => jcs({ n: NaN })).toThrow(JcsError);
    expect(() => jcs({ n: Infinity })).toThrow(JcsError);
    expect(() => jcs({ n: 1n })).toThrow(JcsError);
    const circular: Record<string, unknown> = {};
    circular['self'] = circular;
    expect(() => jcs(circular)).toThrow(/circular/);
  });

  it('matches the worked example from RFC 8785 appendix B', () => {
    const input: Record<string, string> = {
      '\u20ac': 'Euro Sign',
      '\r': 'Carriage Return',
      '\u{1f600}': 'Emoji: Grinning Face',
      '\u0001': 'Control',
      'a': 'LATIN SMALL LETTER A',
    };
    // Code-unit order: U+0001 < U+000D < 'a' < U+20AC < U+D83D (lead surrogate).
    expect(jcs(input)).toBe(
      '{"\\u0001":"Control","\\r":"Carriage Return",' +
        '"a":"LATIN SMALL LETTER A","\u20ac":"Euro Sign",' +
        '"\u{1f600}":"Emoji: Grinning Face"}',
    );
  });
});
