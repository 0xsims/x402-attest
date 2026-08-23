import { REQUIRED_ASSERTIONS, isAnchored, type AnyReceipt, type ExportOptions } from './types.js';

/**
 * Export for finance and audit.
 *
 * One row per call, assertion results as columns. The audience is a spreadsheet
 * and a control tester, not a program, so the CSV is flat with no nesting and no
 * JSON blobs in cells.
 */

function toMillis(v: string | number | Date | undefined): number | undefined {
  if (v === undefined) return undefined;
  if (v instanceof Date) return v.getTime();
  if (typeof v === 'number') return v;
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : t;
}

export function filterReceipts(receipts: AnyReceipt[], opts: ExportOptions): AnyReceipt[] {
  const from = toMillis(opts.from);
  const to = toMillis(opts.to);
  return receipts
    .filter((r) => {
      const t = Date.parse(r.callRecord.startedAt);
      if (Number.isNaN(t)) return true;
      if (from !== undefined && t < from) return false;
      if (to !== undefined && t > to) return false;
      return true;
    })
    .sort((a, b) => (a.callRecord.callId < b.callRecord.callId ? -1 : 1));
}

/** Full fidelity: the entire receipt, one JSON object per line. */
export function toJsonl(receipts: AnyReceipt[], opts: ExportOptions = {}): string {
  const rows = filterReceipts(receipts, opts);
  return rows.map((r) => JSON.stringify(r)).join('\n') + (rows.length ? '\n' : '');
}

const BASE_COLUMNS = [
  'callId',
  'startedAt',
  'endedAt',
  'durationMs',
  'subjectId',
  'policyId',
  'sessionId',
  'method',
  'host',
  'path',
  'status',
  'outcome',
  'scheme',
  'network',
  'payTo',
  'asset',
  'amountAuthorized',
  'maxAmountRequired',
  'settled',
  'txHash',
  'servedModel',
  'leafHash',
  'root',
  'attestationId',
  'anchorState',
  'verifyUrl',
] as const;

/**
 * RFC 4180 quoting.
 *
 * A leading `=`, `+`, `-` or `@` is prefixed with a single quote: spreadsheet
 * applications interpret those as formulas, and a `payTo` field is attacker-
 * influenced content landing in a finance workbook.
 */
function csvCell(value: unknown): string {
  if (value === undefined || value === null) return '';
  let s = String(value);
  if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
  if (/[",\n\r]/.test(s)) s = '"' + s.replace(/"/g, '""') + '"';
  return s;
}

export function toCsv(receipts: AnyReceipt[], opts: ExportOptions = {}): string {
  const rows = filterReceipts(receipts, opts);
  const header = [...BASE_COLUMNS, ...REQUIRED_ASSERTIONS.map((a) => `assert.${a}`)];
  const lines = [header.join(',')];

  for (const r of rows) {
    const c = r.callRecord;
    const byId = new Map(c.assertions.map((a) => [a.id, a.result]));
    const cells: unknown[] = [
      c.callId,
      c.startedAt,
      c.endedAt,
      c.durationMs,
      c.subjectId,
      c.policyId,
      c.sessionId,
      c.request.method,
      c.request.host,
      c.request.path,
      c.response.status,
      c.outcome,
      c.payment?.scheme ?? c.challenge?.scheme,
      c.payment?.network ?? c.challenge?.network,
      c.payment?.payTo ?? c.challenge?.payTo,
      c.payment?.asset ?? c.challenge?.asset,
      c.payment?.amountAuthorized,
      c.challenge?.maxAmountRequired,
      c.settlement?.success ?? false,
      c.settlement?.txHash,
      c.response.servedModel,
      r.leafHash,
      r.root,
      r.attestationId,
      isAnchored(r) ? 'anchored' : 'pending',
      r.verifyUrl,
    ];
    for (const id of REQUIRED_ASSERTIONS) cells.push(byId.get(id) ?? 'unknown');
    lines.push(cells.map(csvCell).join(','));
  }

  return lines.join('\n') + '\n';
}
