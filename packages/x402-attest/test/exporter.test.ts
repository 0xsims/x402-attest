import { describe, expect, it } from 'vitest';
import { filterReceipts, toCsv, toJsonl } from '../src/exporter.js';
import { REQUIRED_ASSERTIONS, type AnyReceipt, type CallRecord } from '../src/types.js';

/**
 * The export is what goes to finance and audit, so it is a flat table with one
 * row per call and one column per check. Nested JSON in a spreadsheet cell is a
 * non-answer.
 */

function receipt(over: Partial<CallRecord> = {}, anchored = true): AnyReceipt {
  const callRecord: CallRecord = {
    v: 1,
    callId: '018f0000-0000-7000-8000-000000000001',
    subjectId: 'agent-alpha',
    policyId: 'trading-desk-v2',
    sessionId: 'run-1',
    startedAt: '2026-08-23T10:00:00.000Z',
    endedAt: '2026-08-23T10:00:00.250Z',
    durationMs: 250,
    request: {
      method: 'POST',
      host: 'seller.example',
      path: '/v1/chat/completions',
      bodyHash: 'a'.repeat(64),
      bodyBytes: 120,
    },
    challenge: {
      scheme: 'exact',
      network: 'eip155:8453',
      maxAmountRequired: '1000',
      payTo: '0x1111111111111111111111111111111111111111',
      asset: 'usdc',
      rawHash: 'd'.repeat(64),
    },
    payment: {
      scheme: 'exact',
      network: 'eip155:8453',
      amountAuthorized: '1000',
      asset: 'usdc',
      payTo: '0x1111111111111111111111111111111111111111',
      xPaymentHash: 'e'.repeat(64),
    },
    settlement: { success: true, txHash: '0xtx', source: 'x-payment-response' },
    response: { status: 200, bodyHash: 'b'.repeat(64), bodyBytes: 300, headers: {} },
    outcome: 'ok',
    assertions: REQUIRED_ASSERTIONS.map((id) => ({ id, result: 'pass' as const })),
    ...over,
  };

  return anchored
    ? {
        callRecord,
        leafHash: 'c'.repeat(64),
        proof: [{ hash: 'f'.repeat(64), side: 'right' }],
        root: '9'.repeat(64),
        attestationId: 'att-1',
        verifyUrl: 'https://rubric-protocol.com/v1/verify/att-1',
      }
    : {
        callRecord,
        leafHash: 'c'.repeat(64),
        proof: null,
        root: null,
        attestationId: null,
        verifyUrl: null,
      };
}

describe('exportReceipts', () => {
  it('emits one JSON object per line in jsonl', () => {
    const out = toJsonl([receipt(), receipt({ callId: '018f0000-0000-7000-8000-000000000002' })]);
    const lines = out.trim().split('\n');
    expect(lines).toHaveLength(2);
    expect(JSON.parse(lines[0]!).callRecord.callId).toBe('018f0000-0000-7000-8000-000000000001');
    expect(out.endsWith('\n')).toBe(true);
  });

  it('returns an empty string for no receipts rather than a stray newline', () => {
    expect(toJsonl([])).toBe('');
  });

  it('emits one CSV row per call with a column per assertion', () => {
    const csv = toCsv([receipt()]);
    const [header, row] = csv.trim().split('\n');
    const cols = header!.split(',');

    for (const id of REQUIRED_ASSERTIONS) expect(cols).toContain(`assert.${id}`);
    expect(cols).toContain('callId');
    expect(cols).toContain('outcome');
    expect(cols).toContain('amountAuthorized');
    expect(cols).toContain('attestationId');
    expect(cols).toContain('anchorState');

    const cells = row!.split(',');
    expect(cells).toHaveLength(cols.length);
    expect(cells[cols.indexOf('outcome')]).toBe('ok');
    expect(cells[cols.indexOf('anchorState')]).toBe('anchored');
    expect(cells[cols.indexOf('assert.settled')]).toBe('pass');
  });

  it('reports a pending receipt as pending, with empty anchor columns', () => {
    const csv = toCsv([receipt({}, false)]);
    const [header, row] = csv.trim().split('\n');
    const cols = header!.split(',');
    const cells = row!.split(',');
    expect(cells[cols.indexOf('anchorState')]).toBe('pending');
    expect(cells[cols.indexOf('attestationId')]).toBe('');
  });

  it('fills unknown for an assertion the record does not carry', () => {
    const csv = toCsv([receipt({ assertions: [] })]);
    const [header, row] = csv.trim().split('\n');
    const cols = header!.split(',');
    const cells = row!.split(',');
    // A missing assertion reads as unknown, never as a blank that a reader might
    // mistake for a pass.
    expect(cells[cols.indexOf('assert.price_within_policy')]).toBe('unknown');
  });

  it('quotes cells per RFC 4180', () => {
    const csv = toCsv([
      receipt({ request: { ...receipt().callRecord.request, path: '/a,b"c\nd' } }),
    ]);
    expect(csv).toContain('"/a,b""c\nd"');
  });

  it('neutralizes spreadsheet formula injection', () => {
    // payTo is attacker-influenced content heading into a finance workbook.
    const csv = toCsv([
      receipt({
        payment: { ...receipt().callRecord.payment!, payTo: '=HYPERLINK("http://evil")' },
      }),
    ]);
    expect(csv).toContain("'=HYPERLINK");
    expect(csv).not.toMatch(/,=HYPERLINK/);
  });

  it('filters by time range on startedAt, inclusive', () => {
    const early = receipt({
      callId: '018f0000-0000-7000-8000-00000000000a',
      startedAt: '2026-08-01T00:00:00.000Z',
    });
    const late = receipt({
      callId: '018f0000-0000-7000-8000-00000000000b',
      startedAt: '2026-09-01T00:00:00.000Z',
    });
    const all = [early, late];

    expect(filterReceipts(all, { from: '2026-08-15T00:00:00.000Z' })).toHaveLength(1);
    expect(filterReceipts(all, { to: '2026-08-15T00:00:00.000Z' })).toHaveLength(1);
    expect(filterReceipts(all, { from: new Date('2026-07-01'), to: new Date('2026-10-01') })).toHaveLength(2);
    expect(filterReceipts(all, { from: Date.parse('2026-08-01T00:00:00.000Z') })).toHaveLength(2);
    expect(filterReceipts(all, {})).toHaveLength(2);
    expect(filterReceipts(all, { from: 'not-a-date' })).toHaveLength(2);
  });

  it('sorts rows by callId, which is time-ordered', () => {
    const b = receipt({ callId: '018f0000-0000-7000-8000-0000000000bb' });
    const a = receipt({ callId: '018f0000-0000-7000-8000-0000000000aa' });
    const sorted = filterReceipts([b, a], {});
    expect(sorted.map((r) => r.callRecord.callId)).toEqual([
      '018f0000-0000-7000-8000-0000000000aa',
      '018f0000-0000-7000-8000-0000000000bb',
    ]);
  });
});
