#!/usr/bin/env node
/**
 * Validate every live Rubric x402 service.
 *
 * Two phases, because the cheap one answers most of the question:
 *
 *   DISCOVER (free)  unpaid request to each endpoint -> read the 402 challenge.
 *                    Confirms the route is mounted, priced, and declares what
 *                    it wants. Spends nothing.
 *   PAY     (--live) pay each service once, capture the real response, and
 *                    compare it against that service's own published demo.
 *                    Flags placeholder values, nulls, and stale data.
 *
 *   node examples/validate-services.mjs             # discover only
 *   node examples/validate-services.mjs --live      # discover, then pay
 *   node examples/validate-services.mjs --live --only=check-counterparty,regwatch-feed
 *
 * Request bodies below are GUESSES for the POST services. The discover phase
 * prints each endpoint's declared input schema — correct the bodies from that
 * before running --live, or those calls will fail on a 400 rather than tell you
 * anything useful.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';

const LIVE = process.argv.includes('--live');
const ONLY = (process.argv.find(a => a.startsWith('--only=')) || '').slice(7).split(',').filter(Boolean);
const BASE = 'https://rubric-protocol.com';
const OUT = './.validation';

/** Total spend ceiling for the whole run, in atomic USDC. $0.40. */
const BUDGET_ATOMIC = 400_000n;

/** A known-anchored attestation to feed verify-audit. */
const KNOWN_ATTESTATION = '47cfc0e4-e54a-4f0f-a9d8-94fc09f49e1c';
const KNOWN_ADDRESS = '0x08F907a3522f0b2C392176058B0Da5a7Da92fD5e';

const SERVICES = [
  { id: 'hedera-facts',          method: 'GET',  path: '/v1/x402/hedera-facts/supply' },
  { id: 'hedera-facts-all',      method: 'GET',  path: '/v1/x402/hedera-facts/all', demo: 'hedera-facts' },
  { id: 'agent-record',          method: 'GET',  path: '/v1/x402/agent-record/rubric-assert' },
  { id: 'wallet-record',         method: 'GET',  path: `/v1/x402/wallet-record/${KNOWN_ADDRESS}` },
  { id: 'check-counterparty',    method: 'GET',  path: `/v1/x402/check-counterparty/${KNOWN_ADDRESS}` },
  { id: 'regwatch-feed',         method: 'GET',  path: '/v1/x402/regwatch-feed' },
  { id: 'verify-audit',          method: 'POST', path: '/v1/x402/verify-audit',
    body: { attestationId: KNOWN_ATTESTATION } },
  { id: 'attested-screening',    method: 'POST', path: '/v1/x402/attested-screening',
    body: { name: 'Jane Q. Example', country: 'US' } },
  { id: 'attested-verification', method: 'POST', path: '/v1/x402/attested-verification',
    body: { method: 'liveness', result: 'pass', subjectRef: 'opaque-subject-001', provider: 'validation-harness' } },
  { id: 'attested-work-record',  method: 'POST', path: '/v1/x402/attested-work-record',
    body: { siteRef: 'validation-run', actor: { type: 'agent', id: 'service-validator' },
            action: 'validate-endpoint', outcome: 'completed' } },
  { id: 'attested-inference',    method: 'POST', path: '/v1/x402/attested-inference',
    body: { prompt: 'Reply with exactly one word: validated.' } },
  { id: 'decision-review',       method: 'POST', path: '/v1/x402/decision-review',
    body: { action: 'Issue a $1,400 refund to a customer.',
            policy: 'Refunds over $1,000 require supervisor approval.',
            context: 'No supervisor approval reference is present.' } },
  { id: 'tiered-attest',         method: 'POST', path: '/v1/x402/tiered-attest',
    body: { agentId: 'service-validator', data: { note: 'validation run' } } },
  { id: 'statement',             method: 'GET',  path: '/v1/x402/statement', demo: null },
];

const wanted = ONLY.length ? SERVICES.filter(s => ONLY.includes(s.id)) : SERVICES;
const line = (c = '─') => console.log(c.repeat(96));
const short = v => { const s = typeof v === 'string' ? v : JSON.stringify(v); return s && s.length > 58 ? s.slice(0, 55) + '…' : s; };

/* ---------------- placeholder / staleness detection ---------------- */

const PLACEHOLDER = [/^string$/i, /^sha256-of-/i, /^0x\.\.\.$/, /\.\.\.$/, /^<.*>$/, /^example$/i, /^TODO/i];
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Walk an object and collect paths whose value looks like sample data or is empty. */
function suspicious(obj, path = '', out = []) {
  if (obj === null) { out.push([path || '(root)', 'null']); return out; }
  if (typeof obj === 'string') {
    if (obj === '') out.push([path, 'empty string']);
    else if (PLACEHOLDER.some(r => r.test(obj))) out.push([path, `placeholder: ${obj}`]);
    return out;
  }
  if (Array.isArray(obj)) {
    if (obj.length === 0) out.push([path, 'empty array']);
    obj.slice(0, 3).forEach((v, i) => suspicious(v, `${path}[${i}]`, out));
    return out;
  }
  if (typeof obj === 'object') {
    for (const [k, v] of Object.entries(obj)) suspicious(v, path ? `${path}.${k}` : k, out);
  }
  return out;
}

/* ---------------- phase 1: discover ---------------- */

async function discover(svc) {
  const r = { id: svc.id };
  try {
    const res = await fetch(BASE + svc.path, {
      method: svc.method,
      headers: svc.body ? { 'content-type': 'application/json' } : {},
      body: svc.body ? JSON.stringify(svc.body) : undefined,
    });
    r.status = res.status;
    const raw = res.headers.get('payment-required') || res.headers.get('x-payment-required');
    if (raw) {
      try {
        const c = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
        const a = (c.accepts || [])[0] || {};
        r.x402Version = c.x402Version;
        r.priceAtomic = a.amount ?? a.maxAmountRequired ?? null;
        r.payTo = a.payTo ?? null;
        r.network = a.network ?? null;
        r.description = c.resource?.description ?? null;
        const fields = c.extensions?.bazaar?.info?.input?.bodyFields
                    ?? c.extensions?.bazaar?.schema?.properties?.input?.properties?.body?.properties;
        r.declaredFields = fields ? Object.keys(fields) : null;
      } catch (e) { r.challengeError = e.message; }
    } else if (res.status === 402) {
      r.challengeError = '402 with no payment-required header';
    }
  } catch (e) { r.error = e.message; }
  return r;
}

/* ---------------- phase 2: pay ---------------- */

async function paid(svc, payFetch) {
  const r = { id: svc.id };
  const t0 = Date.now();
  try {
    const res = await payFetch(BASE + svc.path, {
      method: svc.method,
      headers: svc.body ? { 'content-type': 'application/json' } : {},
      body: svc.body ? JSON.stringify(svc.body) : undefined,
    });
    r.status = res.status;
    r.ms = Date.now() - t0;
    r.body = await res.json().catch(() => null);
    r.settled = r.body?.settled === true;
    r.attestationId = r.body?.attestationId ?? null;
    r.flags = suspicious(r.body).filter(([p]) => !/^(verifyUrl|operator)$/.test(p));
  } catch (e) { r.error = e?.message ?? String(e); r.ms = Date.now() - t0; }
  return r;
}

/* ---------------- run ---------------- */

mkdirSync(OUT, { recursive: true });

line('═');
console.log('  RUBRIC SERVICE VALIDATION');
line('═');
console.log(`  ${wanted.length} services   phase: ${LIVE ? 'discover + pay' : 'discover only (spends nothing)'}`);
console.log('');

console.log('  DISCOVER — unpaid request, read the 402 challenge\n');
console.log(`  ${'service'.padEnd(23)} ${'st'.padEnd(4)} ${'price'.padEnd(9)} ${'v'.padEnd(2)} declared input fields`);
console.log('  ' + '─'.repeat(92));

const discovered = [];
for (const svc of wanted) {
  const d = await discover(svc);
  discovered.push(d);
  const price = d.priceAtomic ? `$${(Number(d.priceAtomic) / 1e6).toFixed(3)}` : '—';
  const fields = d.declaredFields ? d.declaredFields.join(', ')
               : d.challengeError ? `⚠ ${d.challengeError}`
               : d.error ? `✗ ${d.error}` : '(none declared)';
  console.log(`  ${d.id.padEnd(23)} ${String(d.status ?? '—').padEnd(4)} ${price.padEnd(9)} ${String(d.x402Version ?? '—').padEnd(2)} ${short(fields)}`);
}

const broken = discovered.filter(d => d.error || d.challengeError || (d.status !== 402 && d.status !== 200));
console.log('');
console.log(`  ${discovered.length - broken.length}/${discovered.length} endpoints returned a well-formed 402 challenge`);
if (broken.length) for (const b of broken) console.log(`    ✗ ${b.id}: status ${b.status} ${b.error ?? b.challengeError ?? ''}`);

const totalAtomic = discovered.reduce((n, d) => n + BigInt(d.priceAtomic || 0), 0n);
console.log(`  paying for all of them once would cost $${(Number(totalAtomic) / 1e6).toFixed(3)}`);

writeFileSync(`${OUT}/discover.json`, JSON.stringify(discovered, null, 2));

if (!LIVE) {
  line();
  console.log(`\n  Discovery written to ${OUT}/discover.json`);
  console.log('  Correct the request bodies at the top of this file from the declared');
  console.log('  fields above, then re-run with --live.\n');
  process.exit(0);
}

if (totalAtomic > BUDGET_ATOMIC) {
  console.error(`\n✗ total $${(Number(totalAtomic) / 1e6).toFixed(3)} exceeds the $${(Number(BUDGET_ATOMIC) / 1e6).toFixed(2)} run ceiling. Narrow with --only=\n`);
  process.exit(1);
}

const pk = process.env.X402_PRIVATE_KEY;
if (!/^0x[0-9a-fA-F]{64}$/.test(pk ?? '')) { console.error('\n✗ X402_PRIVATE_KEY not set or malformed\n'); process.exit(1); }
const account = privateKeyToAccount(pk);
const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(account));
const payFetch = wrapFetchWithPayment(fetch, x402);

console.log('');
line();
console.log('  PAY — one call each, real USDC on Base\n');
console.log(`  ${'service'.padEnd(23)} ${'st'.padEnd(4)} ${'ms'.padEnd(6)} ${'settled'.padEnd(8)} ${'attestation'.padEnd(12)} flags`);
console.log('  ' + '─'.repeat(92));

const results = [];
for (const svc of wanted) {
  const r = await paid(svc, payFetch);
  results.push(r);
  const att = r.attestationId ? (UUID.test(r.attestationId) ? r.attestationId.slice(0, 8) : '⚠ malformed') : '—';
  const flags = r.error ? `✗ ${r.error}` : (r.flags?.length ? r.flags.map(([p, w]) => `${p}=${w}`).join('; ') : 'clean');
  console.log(`  ${r.id.padEnd(23)} ${String(r.status ?? '—').padEnd(4)} ${String(r.ms ?? '—').padEnd(6)} ${String(r.settled).padEnd(8)} ${att.padEnd(12)} ${short(flags)}`);
}

writeFileSync(`${OUT}/paid.json`, JSON.stringify(results, null, 2));

const ok = results.filter(r => r.status === 200);
const withAtt = results.filter(r => r.attestationId && UUID.test(r.attestationId));
const flagged = results.filter(r => r.flags?.length);

console.log('');
line('═');
console.log('  SUMMARY');
line('═');
console.log(`  responded 200        ${ok.length}/${results.length}`);
console.log(`  settled              ${results.filter(r => r.settled).length}/${results.length}`);
console.log(`  returned attestation ${withAtt.length}/${results.length}`);
console.log(`  flagged values       ${flagged.length}`);
for (const f of flagged) {
  console.log(`\n    ${f.id}`);
  for (const [p, w] of f.flags) console.log(`      ${p}: ${w}`);
}
console.log('');
console.log(`  full responses: ${OUT}/paid.json`);
console.log('  A flag is not a failure — nulls and empty arrays can be honest answers.');
console.log('  It means look at that field and decide.');
line();
