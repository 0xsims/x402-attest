#!/usr/bin/env node
/**
 * Known-positive test for attested-screening.
 *
 * A screening service that misses a real hit is worse than no service: the
 * customer relies on it and gets fined. So the only test that matters is
 * whether names that ARE on the list come back as matches.
 *
 * Ground truth is OFAC's own published SDN list, fetched at run time. Positive
 * controls are drawn from it rather than from memory, so the test cannot drift
 * out of date and cannot be accidentally wrong about who is listed.
 *
 *   node examples/screening-test.mjs                 # fetch list, show plan, spend nothing
 *   node examples/screening-test.mjs --probe         # ONE paid call, print raw response
 *   node examples/screening-test.mjs --live          # full test
 *
 * The request body is a guess — attested-screening declares no input schema.
 * Run --probe first ($0.01) and read the response before committing to --live.
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';

const PROBE = process.argv.includes('--probe');
const LIVE  = process.argv.includes('--live');
const OUT   = './.screening-test';
const URL   = 'https://rubric-protocol.com/v1/x402/attested-screening';
const SDN   = 'https://www.treasury.gov/ofac/downloads/sdn.csv';

const N_POSITIVE = Number(process.env.N_POSITIVE ?? 5);

/** Names that should NOT match. If any of these flags, the matcher is too loose. */
const NEGATIVE_CONTROLS = [
  'Wilhelmina Ashcroft-Pemberton',
  'Quorvex Danforth Illingsworth',
];

const line = (c='─') => console.log(c.repeat(92));

/* ---------------- ground truth ---------------- */

/** Minimal CSV row splitter: handles quoted fields containing commas. */
function splitCsv(line) {
  const out=[]; let cur=''; let q=false;
  for (let i=0;i<line.length;i++){
    const ch=line[i];
    if (ch === '"') { if (q && line[i+1]==='"'){cur+='"';i++;} else q=!q; }
    else if (ch === ',' && !q) { out.push(cur); cur=''; }
    else cur+=ch;
  }
  out.push(cur); return out;
}

async function fetchSdn() {
  const res = await fetch(SDN, { headers: { 'user-agent': 'rubric-screening-validation' } });
  if (!res.ok) throw new Error(`OFAC SDN fetch failed: HTTP ${res.status}`);
  const text = await res.text();
  const rows = text.split('\n').map(l => l.trim()).filter(Boolean).map(splitCsv);
  // ent_num, SDN_Name, SDN_Type, Program, ...   "-0-" marks an empty field.
  const entries = rows
    .filter(r => r.length > 3 && r[1] && r[1] !== '-0-')
    .map(r => ({ entNum: r[0], name: r[1].replace(/^"|"$/g,''), type: (r[2]||'').replace(/^"|"$/g,''), program: (r[3]||'').replace(/^"|"$/g,'') }));
  return { entries, bytes: text.length };
}

/**
 * Deterministic spread across the list rather than the first N — the front of
 * the file is the oldest entries, and a matcher could pass on those alone.
 */
function pickControls(entries, n) {
  const step = Math.max(1, Math.floor(entries.length / (n + 1)));
  const out = [];
  for (let i = 1; i <= n; i++) out.push(entries[Math.min(i * step, entries.length - 1)]);
  return out;
}

/* ---------------- request ---------------- */

/**
 * attested-screening declares no input schema, so send several plausible
 * spellings at once and let a tolerant server pick the one it knows. Whichever
 * key it honours will be visible in the echoed query or queryHash.
 */
const bodyFor = name => ({ name, query: name, subject: name, entity: name, fullName: name });

async function screen(payFetch, name) {
  const t0 = Date.now();
  try {
    const res = await payFetch(URL, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(bodyFor(name)),
    });
    const body = await res.json().catch(() => null);
    return { name, status: res.status, ms: Date.now()-t0, body,
             matchCount: body?.matchCount ?? null,
             listVersion: body?.listVersion ?? null,
             attestationId: body?.attestationId ?? null };
  } catch (e) {
    return { name, error: e?.message ?? String(e), ms: Date.now()-t0 };
  }
}

/* ---------------- run ---------------- */

line('═');
console.log('  ATTESTED-SCREENING — known-positive test');
line('═');

console.log('  fetching OFAC SDN list …');
let sdn;
try { sdn = await fetchSdn(); }
catch (e) { console.error(`\n✗ ${e.message}\n  Without ground truth this test is meaningless. Aborting.\n`); process.exit(1); }

const controls = pickControls(sdn.entries, N_POSITIVE);
console.log(`  ${sdn.entries.length.toLocaleString()} SDN entries (${(sdn.bytes/1024/1024).toFixed(1)} MB)\n`);
console.log('  positive controls — these MUST match:');
for (const c of controls) console.log(`    #${c.entNum.padEnd(6)} ${c.type.padEnd(12)} ${c.program.padEnd(14)} ${c.name}`);
console.log('\n  negative controls — these must NOT match:');
for (const n of NEGATIVE_CONTROLS) console.log(`    ${n}`);

const total = (PROBE ? 1 : controls.length + NEGATIVE_CONTROLS.length) * 0.01;
console.log(`\n  cost: $${total.toFixed(2)}`);
line();

if (!PROBE && !LIVE) {
  console.log('\n  Dry run. --probe for one paid call, --live for the full test.\n');
  process.exit(0);
}

const pk = process.env.X402_PRIVATE_KEY;
if (!/^0x[0-9a-fA-F]{64}$/.test(pk ?? '')) { console.error('\n✗ X402_PRIVATE_KEY not set or malformed\n'); process.exit(1); }
const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(privateKeyToAccount(pk)));
const payFetch = wrapFetchWithPayment(fetch, x402);

mkdirSync(OUT, { recursive: true });
const stamp = new Date().toISOString().replace(/[:.]/g,'-');

if (PROBE) {
  const r = await screen(payFetch, controls[0].name);
  console.log(`\n  PROBE — ${controls[0].name}\n`);
  console.log(JSON.stringify(r.body, null, 2));
  writeFileSync(`${OUT}/probe-${stamp}.json`, JSON.stringify({ control: controls[0], result: r }, null, 2));
  console.log(`\n  Check which key it honoured, then run --live.\n`);
  process.exit(0);
}

console.log('\n  POSITIVE CONTROLS\n');
console.log(`  ${'matches'.padEnd(9)} ${'ms'.padEnd(6)} ${'attestation'.padEnd(12)} name`);
console.log('  ' + '─'.repeat(88));
const pos = [];
for (const c of controls) {
  const r = await screen(payFetch, c.name);
  pos.push({ control: c, ...r });
  const m = r.error ? `ERR` : String(r.matchCount ?? '?');
  const mark = r.matchCount > 0 ? '✓' : '✗ MISS';
  console.log(`  ${(m+' '+mark).padEnd(9)} ${String(r.ms).padEnd(6)} ${String(r.attestationId ?? '—').slice(0,8).padEnd(12)} ${c.name.slice(0,50)}`);
}

console.log('\n  NEGATIVE CONTROLS\n');
const neg = [];
for (const n of NEGATIVE_CONTROLS) {
  const r = await screen(payFetch, n);
  neg.push(r);
  const mark = r.matchCount === 0 ? '✓' : '✗ FALSE POSITIVE';
  console.log(`  ${(String(r.matchCount ?? '?')+' '+mark).padEnd(20)} ${String(r.ms).padEnd(6)} ${n}`);
}

const misses = pos.filter(r => !(r.matchCount > 0));
const falsePos = neg.filter(r => r.matchCount > 0);
const versions = [...new Set(pos.concat(neg).map(r => r.listVersion).filter(Boolean))];

writeFileSync(`${OUT}/result-${stamp}.json`,
  JSON.stringify({ sdnEntries: sdn.entries.length, controls, positives: pos, negatives: neg }, null, 2));

line('═');
console.log('  RESULT');
line('═');
console.log(`  positive controls   ${pos.length - misses.length}/${pos.length} matched`);
console.log(`  negative controls   ${neg.length - falsePos.length}/${neg.length} correctly clear`);
console.log(`  listVersion         ${versions.join(', ') || '(not reported)'}`);
if (misses.length) {
  console.log(`\n  ✗ ${misses.length} FALSE NEGATIVE${misses.length>1?'S':''} — names on the current SDN list that did not match:`);
  for (const m of misses) console.log(`      #${m.control.entNum}  ${m.control.program}  ${m.control.name}`);
  console.log('\n  This is the failure mode that matters. A customer screening against this');
  console.log('  service would have cleared a listed party. Do not sell it until this is zero.');
} else {
  console.log('\n  ✓ no false negatives in this sample.');
  console.log('    Note the sample is small and drawn deterministically — a clean run is');
  console.log('    evidence the matcher works, not proof it never misses.');
}
if (falsePos.length) console.log(`\n  ⚠ ${falsePos.length} false positive(s) — invented names matched. Matcher is too loose.`);
console.log(`\n  ${OUT}/result-${stamp}.json`);
line();
