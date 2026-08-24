#!/usr/bin/env node
/**
 * Substitution study — 12-call beta.
 *
 * One fixed prompt, identical bytes on every call, so `prompt_tokens` is
 * comparable across models. Rotates a model list; a bad model id is recorded as
 * data, not an abort. All 12 leaves anchor under ONE attestation.
 *
 *   export X402_PRIVATE_KEY=0x...
 *   node examples/beta-12.mjs              # dry run, spends nothing
 *   node examples/beta-12.mjs --live
 *
 * Optional:
 *   MODELS="openai/gpt-5.5,openai/gpt-4o-mini"   # comma separated
 *   N=12
 */
import { createPublicClient, http, formatUnits } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { createTap, withAttestation } from '@tempus1/x402-attest';
import { mkdirSync, writeFileSync } from 'node:fs';

const LIVE = process.argv.includes('--live');
const OUT = './.beta-12';
const ENDPOINT = 'https://blockrun.ai/api/v1/chat/completions';
const USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

const MODELS = (process.env.MODELS ??
  'openai/gpt-5.5,openai/gpt-4o-mini,anthropic/claude-haiku-4.5,google/gemini-2.5-flash'
).split(',').map(s => s.trim()).filter(Boolean);
const N = Number(process.env.N ?? 12);

/** Fixed bytes on every call. Identical input is the whole point — it makes
 *  prompt_tokens comparable, which is the only independent signal available. */
const PROMPT = 'Reply with exactly one word: attested. Do not explain.';

const die = m => { console.error(`\n✗ ${m}\n`); process.exit(1); };
const line = () => console.log('─'.repeat(78));

const pk = process.env.X402_PRIVATE_KEY;
if (!pk) die('X402_PRIVATE_KEY is not set.');
if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) die('X402_PRIVATE_KEY must be 0x + 64 hex chars.');

const account = privateKeyToAccount(pk);
const pub = createPublicClient({ chain: base, transport: http() });
const balance = await pub.readContract({
  address: USDC,
  abi: [{ name: 'balanceOf', type: 'function', stateMutability: 'view',
    inputs: [{ name: 'a', type: 'address' }], outputs: [{ type: 'uint256' }] }],
  functionName: 'balanceOf', args: [account.address],
});

line();
console.log('  BETA — 12 calls, one anchor');
line();
console.log(`  wallet        ${account.address}`);
console.log(`  USDC          $${formatUnits(balance, 6)}`);
console.log(`  calls         ${N} across ${MODELS.length} models`);
console.log(`  models        ${MODELS.join(', ')}`);
console.log(`  prompt        ${JSON.stringify(PROMPT)}`);
console.log(`  caps          $0.05/call, $0.50 session`);
line();

if (!LIVE) { console.log('\n  Dry run. Re-run with --live.\n'); process.exit(0); }
if (balance < 50_000n) die('Balance too low — fund the wallet.');

mkdirSync(`${OUT}/wal`, { recursive: true });

const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(account));
const tap = createTap();
const paid = wrapFetchWithPayment(tap.wrapFetch(fetch), x402);
const anchorFetch = wrapFetchWithPayment(fetch, x402);

const rows = [];
const fetchAndPay = withAttestation(paid, {
  subjectId: 'substitution-beta',
  sessionId: `beta-${MODELS.length}x`,
  mode: 'batch',
  batch: { maxLeaves: 256, maxAgeMs: 3_600_000 },   // hold everything for one anchor
  walPath: `${OUT}/wal`,
  tap,
  anchorFetch,
  policy: { maxPricePerCall: '0.05', allowedNetworks: ['eip155:8453'], budgetCap: '0.50' },
  onReceipt: r => { const i = rows.findIndex(x => x.callId === r.callRecord.callId);
                    if (i >= 0) rows[i].receipt = r; },
});

console.log('\n  #   requested                     served                        ptok  ctok   ms   $quoted  status');
console.log('  ' + '─'.repeat(74));

for (let i = 0; i < N; i++) {
  const model = MODELS[i % MODELS.length];
  const t0 = Date.now();
  let served = null, ptok = null, ctok = null, status = 0, err = null, body = null;
  try {
    const res = await fetchAndPay(ENDPOINT, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ model, messages: [{ role: 'user', content: PROMPT }],
                             max_tokens: 64, temperature: 0 }),
    });
    status = res.status;
    body = await res.json().catch(() => null);
    served = body?.model ?? null;
    ptok = body?.usage?.prompt_tokens ?? null;
    ctok = body?.usage?.completion_tokens ?? null;
  } catch (e) { err = e?.message ?? String(e); }

  const ms = Date.now() - t0;
  const rec = fetchAndPay.attestor?.batcher?.allReceipts?.().slice(-1)[0];
  const cr = rec?.callRecord;
  const quoted = cr?.challenge?.maxAmountRequired ?? null;

  rows.push({ i, model, served, ptok, ctok, ms, status, err, quoted,
              callId: cr?.callId ?? null,
              assertions: cr?.assertions ?? null,
              content: body?.choices?.[0]?.message?.content ?? null });

  const s = err ? `ERR ${err.slice(0, 22)}` : status;
  console.log(`  ${String(i).padStart(2)}  ${String(model).padEnd(28)}  ${String(served ?? '—').padEnd(28)}  ` +
              `${String(ptok ?? '—').padStart(4)}  ${String(ctok ?? '—').padStart(4)}  ${String(ms).padStart(5)}  ` +
              `${String(quoted ?? '—').padStart(7)}  ${s}`);
}

console.log('\n  Anchoring all leaves under one attestation …\n');
const flushed = await fetchAndPay.flush();

for (const r of rows) if (r.callId) r.receipt = fetchAndPay.getReceipt(r.callId);
const anchored = rows.filter(r => r.receipt?.attestationId).length;
const attId = rows.find(r => r.receipt?.attestationId)?.receipt?.attestationId ?? null;
const verifyUrl = rows.find(r => r.receipt?.verifyUrl)?.receipt?.verifyUrl ?? null;

writeFileSync(`${OUT}/rows.json`, JSON.stringify(rows, null, 2));
writeFileSync(`${OUT}/flush.json`, JSON.stringify(flushed, null, 2));

/* ---- summary ---- */
const ok = rows.filter(r => r.status === 200);
const byModel = {};
for (const r of ok) {
  const k = r.model;
  (byModel[k] ??= { n: 0, ptok: new Set(), served: new Set() });
  byModel[k].n++;
  if (r.ptok != null) byModel[k].ptok.add(r.ptok);
  if (r.served) byModel[k].served.add(r.served);
}

line();
console.log('  SUMMARY');
line();
console.log(`  calls            ${rows.length}   ok ${ok.length}   failed ${rows.length - ok.length}`);
console.log(`  leaves anchored  ${anchored} under ${attId ? '1 attestation' : 'none'}`);
if (attId) console.log(`  attestationId    ${attId}`);
if (verifyUrl) console.log(`  verifyUrl        ${verifyUrl}`);
console.log('');
console.log('  model                          n   prompt_tokens seen   served ids seen');
console.log('  ' + '─'.repeat(74));
for (const [m, v] of Object.entries(byModel)) {
  console.log(`  ${m.padEnd(28)}  ${String(v.n).padStart(2)}   ${[...v.ptok].join(',').padEnd(18)}   ${[...v.served].join(', ')}`);
}

const mismatches = ok.filter(r => {
  if (!r.served) return false;
  const a = r.model.toLowerCase(), b = r.served.toLowerCase();
  return !(a === b || b.startsWith(a + '-') || a.startsWith(b + '-'));
});
console.log('');
console.log(`  served ≠ requested (alias-tolerant):  ${mismatches.length} / ${ok.length}`);
for (const m of mismatches) console.log(`    #${m.i}  ${m.model}  →  ${m.served}`);

const unknownModel = ok.filter(r => !r.served).length;
console.log(`  served model not disclosed:           ${unknownModel} / ${ok.length}`);

line();
console.log(`  rows.json written to ${OUT}/rows.json`);
console.log('  NOTE: n=12 is a smoke test, not a rate. It shakes out model ids,');
console.log('        pricing, empty-content, and the one-anchor-per-batch economics.');
line();

await fetchAndPay.close();
