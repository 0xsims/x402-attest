#!/usr/bin/env node
/**
 * Does attested-screening catch the same person written differently?
 *
 * Exact-match screening passes any test built from the list itself, because the
 * query and the record are byte-identical. Real data is not like that. Sanctioned
 * individuals appear reordered, transliterated, abbreviated and lowercased, and a
 * screen that only catches the canonical spelling clears them.
 *
 * This takes one name confirmed present on the current OFAC SDN list and asks
 * the service about the same person written the ways a customer's data would
 * actually hold them. Every miss is a person who would have been cleared.
 *
 *   node examples/screening-variants.mjs              # plan + cost, spends nothing
 *   node examples/screening-variants.mjs --live
 *
 *   TARGET="LAST, First Middle"   to test a different listed name
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';

const LIVE = process.argv.includes('--live');
const OUT  = './.screening-test';
const URL  = 'https://rubric-protocol.com/v1/x402/attested-screening';
const SDN  = 'https://www.treasury.gov/ofac/downloads/sdn.csv';
const PRICE = 0.01;

const TARGET = process.env.TARGET ?? 'IVAKIN, Yuriy Vladimirovich';

const line = (c='─') => console.log(c.repeat(92));

/* ---------------- variants ---------------- */

/**
 * Transliteration alternates common in Cyrillic->Latin renderings. Mechanical
 * and rule-based on purpose: a hand-picked variant proves nothing, since it can
 * be chosen to fail.
 */
const TRANSLIT = [
  ['iy',  'y',   'iy->y'],
  ['iy',  'i',   'iy->i'],
  ['ich', 'ych', 'ich->ych'],
  ['kh',  'h',   'kh->h'],
  ['ye',  'e',   'ye->e'],
];

function variantsOf(full) {
  const [surname, rest = ''] = full.split(',').map(s => s.trim());
  const given = rest.split(/\s+/).filter(Boolean);
  const first = given[0] ?? '';
  const middle = given.slice(1).join(' ');
  const v = [];

  v.push({ label: 'exact',      note: 'as published — control',            value: full });
  v.push({ label: 'lowercase',  note: 'case folded',                        value: full.toLowerCase() });
  v.push({ label: 'no-comma',   note: 'comma removed',                      value: `${surname} ${rest}`.trim() });
  v.push({ label: 'reordered',  note: 'given name first, as a person writes it', value: `${rest} ${surname}`.trim() });
  if (middle) v.push({ label: 'partial', note: 'first + surname, middle dropped', value: `${first} ${surname}` });
  if (middle) v.push({ label: 'initial', note: 'middle name abbreviated',   value: `${first} ${middle[0]}. ${surname}` });

  for (const [from, to, label] of TRANSLIT) {
    const low = full.toLowerCase();
    if (!low.includes(from)) continue;
    const swapped = full.replace(new RegExp(from, 'gi'), to);
    if (swapped.toLowerCase() === low) continue;
    v.push({ label: `translit ${label}`, note: 'transliteration alternate', value: swapped });
  }

  v.push({ label: 'unlisted',   note: 'invented name — must NOT match',     value: 'Quorvex Danforth Illingsworth', negative: true });
  return v;
}

/* ---------------- ground truth ---------------- */

function splitCsv(l) {
  const out=[]; let cur=''; let q=false;
  for (let i=0;i<l.length;i++){ const ch=l[i];
    if (ch==='"'){ if(q&&l[i+1]==='"'){cur+='"';i++;} else q=!q; }
    else if (ch===','&&!q){ out.push(cur); cur=''; } else cur+=ch; }
  out.push(cur); return out;
}

async function confirmListed(name) {
  const res = await fetch(SDN, { headers: { 'user-agent': 'rubric-screening-validation' } });
  if (!res.ok) throw new Error(`OFAC SDN fetch failed: HTTP ${res.status}`);
  const text = await res.text();
  const hit = text.split('\n').map(l => splitCsv(l.trim()))
    .find(r => r.length > 3 && (r[1]||'').replace(/^"|"$/g,'').toLowerCase() === name.toLowerCase());
  return hit ? { entNum: hit[0], type: (hit[2]||'').replace(/^"|"$/g,''), program: (hit[3]||'').replace(/^"|"$/g,'') } : null;
}

/* ---------------- run ---------------- */

const bodyFor = name => ({ name, query: name, subject: name, entity: name, fullName: name });

async function screen(payFetch, name) {
  const t0 = Date.now();
  try {
    const res = await payFetch(URL, { method: 'POST',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(bodyFor(name)) });
    const body = await res.json().catch(() => null);
    return { ms: Date.now()-t0, status: res.status, matchCount: body?.matchCount ?? null,
             perList: body?.perList ?? null, attestationId: body?.attestationId ?? null, body };
  } catch (e) { return { ms: Date.now()-t0, error: e?.message ?? String(e) }; }
}

line('═');
console.log('  ATTESTED-SCREENING — name-variant coverage');
line('═');
console.log(`  target: ${TARGET}\n`);

console.log('  confirming the target is on the current SDN list …');
let listed;
try { listed = await confirmListed(TARGET); }
catch (e) { console.error(`\n✗ ${e.message}\n`); process.exit(1); }
if (!listed) {
  console.error(`\n✗ "${TARGET}" is not an exact SDN_Name in the current list.`);
  console.error('  The test is meaningless unless the target is genuinely listed.\n');
  process.exit(1);
}
console.log(`  ✓ #${listed.entNum}  ${listed.type}  ${listed.program}\n`);

const variants = variantsOf(TARGET);
console.log(`  ${'variant'.padEnd(20)} ${'note'.padEnd(34)} value`);
console.log('  ' + '─'.repeat(88));
for (const v of variants) console.log(`  ${v.label.padEnd(20)} ${v.note.padEnd(34)} ${v.value}`);
console.log(`\n  ${variants.length} calls · $${(variants.length*PRICE).toFixed(2)}`);
line();

if (!LIVE) { console.log('\n  Dry run. Re-run with --live.\n'); process.exit(0); }

const pk = process.env.X402_PRIVATE_KEY;
if (!/^0x[0-9a-fA-F]{64}$/.test(pk ?? '')) { console.error('\n✗ X402_PRIVATE_KEY not set or malformed\n'); process.exit(1); }
const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(privateKeyToAccount(pk)));
const payFetch = wrapFetchWithPayment(fetch, x402);

mkdirSync(OUT, { recursive: true });
console.log('');
console.log(`  ${'variant'.padEnd(20)} ${'hits'.padEnd(5)} ${'ms'.padEnd(6)} ${'verdict'.padEnd(16)} value`);
console.log('  ' + '─'.repeat(88));

const results = [];
for (const v of variants) {
  const r = await screen(payFetch, v.value);
  const hit = (r.matchCount ?? 0) > 0;
  const verdict = r.error ? 'ERROR'
    : v.negative ? (hit ? '✗ FALSE POSITIVE' : '✓ clear')
    : (hit ? '✓ caught' : '✗ MISSED');
  results.push({ ...v, ...r, hit, verdict });
  console.log(`  ${v.label.padEnd(20)} ${String(r.matchCount ?? '—').padEnd(5)} ${String(r.ms).padEnd(6)} ${verdict.padEnd(16)} ${v.value.slice(0,34)}`);
}

const stamp = new Date().toISOString().replace(/[:.]/g,'-');
writeFileSync(`${OUT}/variants-${stamp}.json`, JSON.stringify({ target: TARGET, listed, results }, null, 2));

const positives = results.filter(r => !r.negative);
const missed = positives.filter(r => !r.hit && !r.error);
const falsePos = results.filter(r => r.negative && r.hit);

line('═');
console.log('  RESULT');
line('═');
console.log(`  same listed person, written ${positives.length} ways`);
console.log(`  caught  ${positives.length - missed.length}`);
console.log(`  missed  ${missed.length}`);
if (positives.length) console.log(`  miss rate ${((missed.length / positives.length) * 100).toFixed(0)}%`);
if (falsePos.length) console.log(`\n  ⚠ invented name matched — the matcher is too loose as well as too tight.`);

if (missed.length) {
  console.log('\n  Cleared despite being the same listed individual:');
  for (const m of missed) console.log(`    ${m.label.padEnd(20)} ${m.value}`);
  console.log('\n  Each of these is a customer screening a sanctioned party and being told');
  console.log('  they are clear. screen-match-v2.2 permits one inexact token pair inside a');
  console.log('  length-based edit budget; a spelling further than that from every listed');
  console.log('  form falls outside the rule. The response discloses the rule in full — but');
  console.log('  a disclosure the buyer must read is not the same as a buyer who understood.');
} else {
  console.log('\n  ✓ every variant caught — the service behaves as its disclosed rule says.');
  console.log('    This is conformance, not surplus: the rule is published in every response');
  console.log('    and in the signed evidence, so a buyer can reproduce this result.');
}
console.log(`\n  ${OUT}/variants-${stamp}.json`);
line();
