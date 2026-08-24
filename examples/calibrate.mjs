#!/usr/bin/env node
/**
 * Amendment 1 — probe string calibration.
 *
 * Registered selection criteria (PREREGISTRATION.md §5), in order:
 *   1. all study models pairwise distinct on prompt_tokens
 *   2. zero within-model variance across repetitions
 *   3. shortest string satisfying 1 and 2
 *
 * Runs two arms:
 *   CONTROL — each provider's native API. Ground truth per model.
 *   ROUTER  — the same content through BlockRun. The delta against control is
 *             the translation offset, NOT evidence of injection: Anthropic and
 *             Google do not speak OpenAI's schema, so the router re-templates
 *             the request and that costs tokens. Measuring the offset is what
 *             lets the study set a tolerance instead of pretending it is zero.
 *
 *   node examples/calibrate.mjs                 # plan + cost, spends nothing
 *   node examples/calibrate.mjs --live
 *   node examples/calibrate.mjs --live --control-only
 *   node examples/calibrate.mjs --live --router-only
 *
 * Keys (only those for the arms you run):
 *   OPENAI_API_KEY  ANTHROPIC_API_KEY  GOOGLE_API_KEY  DEEPSEEK_API_KEY
 *   X402_PRIVATE_KEY
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';

const LIVE = process.argv.includes('--live');
const CONTROL_ONLY = process.argv.includes('--control-only');
const ROUTER_ONLY = process.argv.includes('--router-only');
const OUT = './.calibration';

const CONTROL_REPS = Number(process.env.CONTROL_REPS ?? 5);
const ROUTER_REPS = Number(process.env.ROUTER_REPS ?? 3);
const ROUTER_URL = 'https://blockrun.ai/api/v1/chat/completions';

/* Five models, four tokenizer families. A fourth family makes pairwise
 * separation easier, not harder. */
const MODELS = [
  { key: 'gpt-5.5',      router: 'openai/gpt-5.5',              provider: 'openai',    native: 'gpt-5.5' },
  { key: 'gpt-4o-mini',  router: 'openai/gpt-4o-mini',          provider: 'openai',    native: 'gpt-4o-mini' },
  { key: 'haiku-4.5',    router: 'anthropic/claude-haiku-4.5',  provider: 'anthropic', native: 'claude-haiku-4-5-20251001' },
  { key: 'gemini-flash', router: 'google/gemini-2.5-flash',     provider: 'google',    native: 'gemini-2.5-flash' },
  { key: 'deepseek',     router: 'deepseek/deepseek-chat',      provider: 'deepseek',  native: 'deepseek-chat' },
];

/* One lever per candidate, so a winner can be explained rather than just
 * observed. `mixed` combines them as an upper bound on separation. */
const CANDIDATES = [
  { id: 'baseline', text: 'Reply with one word: ok.' },
  { id: 'digits',   text: 'Reply with one word: ok. Ref 4830271905566142.' },
  { id: 'cjk',      text: 'Reply with one word: ok. 参照番号は東京です。' },
  { id: 'emoji',    text: 'Reply with one word: ok. 🜂🝔🜛🝮' },
  { id: 'space',    text: 'Reply with one word: ok.     Ref     A     B.' },
  { id: 'mixed',    text: 'Reply with one word: ok. Ref 4830271905566142 · 東京 · 🜂 · ﬀﬁ.' },
];

const line = (c = '─') => console.log(c.repeat(84));
const key = n => process.env[n];

/* ---------------- provider adapters: prompt_tokens only ---------------- */

async function control(model, text) {
  const p = model.provider;
  if (p === 'openai' || p === 'deepseek') {
    const base = p === 'openai' ? 'https://api.openai.com/v1' : 'https://api.deepseek.com';
    const k = key(p === 'openai' ? 'OPENAI_API_KEY' : 'DEEPSEEK_API_KEY');
    if (!k) throw new Error(`${p.toUpperCase()}_API_KEY not set`);
    const send = async (capField) => {
      const r = await fetch(`${base}/chat/completions`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${k}` },
        body: JSON.stringify({ model: model.native, messages: [{ role: 'user', content: text }], [capField]: 1 }),
      });
      return { ok: r.ok, status: r.status, body: await r.json().catch(() => null) };
    };
    // Newer OpenAI models reject `max_tokens`. Try it, fall back once.
    let r = await send('max_tokens');
    if (!r.ok) r = await send('max_completion_tokens');
    if (!r.ok) throw new Error(`HTTP ${r.status} ${JSON.stringify(r.body?.error?.message ?? r.body).slice(0, 120)}`);
    return r.body?.usage?.prompt_tokens ?? null;
  }
  if (p === 'anthropic') {
    const k = key('ANTHROPIC_API_KEY');
    if (!k) throw new Error('ANTHROPIC_API_KEY not set');
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-api-key': k, 'anthropic-version': '2023-06-01' },
      body: JSON.stringify({ model: model.native, max_tokens: 1, messages: [{ role: 'user', content: text }] }),
    });
    const b = await r.json().catch(() => null);
    if (!r.ok) throw new Error(`HTTP ${r.status} ${JSON.stringify(b?.error?.message ?? b).slice(0, 120)}`);
    return b?.usage?.input_tokens ?? null;          // NB: input_tokens, not prompt_tokens
  }
  if (p === 'google') {
    const k = key('GOOGLE_API_KEY');
    if (!k) throw new Error('GOOGLE_API_KEY not set');
    const r = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${model.native}:generateContent?key=${k}`,
      { method: 'POST', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text }] }], generationConfig: { maxOutputTokens: 1 } }) });
    const b = await r.json().catch(() => null);
    if (!r.ok) throw new Error(`HTTP ${r.status} ${JSON.stringify(b?.error?.message ?? b).slice(0, 120)}`);
    return b?.usageMetadata?.promptTokenCount ?? null;
  }
  throw new Error(`no adapter for provider ${p}`);
}

async function router(paidFetch, model, text) {
  const r = await paidFetch(ROUTER_URL, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ model: model.router, messages: [{ role: 'user', content: text }], max_tokens: 1 }),
  });
  const b = await r.json().catch(() => null);
  if (!r.ok) throw new Error(`HTTP ${r.status} ${JSON.stringify(b).slice(0, 120)}`);
  return { ptok: b?.usage?.prompt_tokens ?? null, served: b?.model ?? null };
}

/* ---------------- plan ---------------- */

const arms = CONTROL_ONLY ? ['control'] : ROUTER_ONLY ? ['router'] : ['control', 'router'];
const nControl = arms.includes('control') ? CANDIDATES.length * MODELS.length * CONTROL_REPS : 0;
const nRouter = arms.includes('router') ? CANDIDATES.length * MODELS.length * ROUTER_REPS : 0;

line();
console.log('  CALIBRATION — Amendment 1');
line();
console.log(`  candidates   ${CANDIDATES.length}   models ${MODELS.length}   arms ${arms.join(' + ')}`);
console.log(`  control      ${nControl} calls  (provider APIs, billed to your keys)`);
console.log(`  router       ${nRouter} calls  ≈ $${(nRouter * 0.002).toFixed(2)} over x402`);
console.log('');
for (const c of CANDIDATES) console.log(`  ${c.id.padEnd(9)} ${JSON.stringify(c.text)}`);
line();
if (!LIVE) { console.log('\n  Dry run. Re-run with --live.\n'); process.exit(0); }

mkdirSync(OUT, { recursive: true });

let paidFetch = null;
if (arms.includes('router')) {
  const pk = process.env.X402_PRIVATE_KEY;
  if (!/^0x[0-9a-fA-F]{64}$/.test(pk ?? '')) { console.error('\n✗ X402_PRIVATE_KEY not set or malformed\n'); process.exit(1); }
  const x402 = new x402Client();
  x402.register('eip155:*', new ExactEvmScheme(privateKeyToAccount(pk)));
  paidFetch = wrapFetchWithPayment(fetch, x402);
}

/* ---------------- run ---------------- */

const data = {};   // data[candidate][model] = { control: [], router: [], served: Set, errors: [] }

for (const cand of CANDIDATES) {
  data[cand.id] = {};
  console.log(`\n  ── ${cand.id} ──`);
  for (const m of MODELS) {
    const cell = { control: [], router: [], served: [], errors: [] };
    data[cand.id][m.key] = cell;

    if (arms.includes('control')) {
      for (let i = 0; i < CONTROL_REPS; i++) {
        try { cell.control.push(await control(m, cand.text)); }
        catch (e) { cell.errors.push(`control: ${e.message}`); break; }
      }
    }
    if (arms.includes('router')) {
      for (let i = 0; i < ROUTER_REPS; i++) {
        try { const r = await router(paidFetch, m, cand.text);
              cell.router.push(r.ptok); if (r.served) cell.served.push(r.served); }
        catch (e) { cell.errors.push(`router: ${e.message}`); break; }
      }
    }

    const u = a => [...new Set(a.filter(v => v != null))];
    const cu = u(cell.control), ru = u(cell.router);
    const off = (cu.length === 1 && ru.length === 1) ? ru[0] - cu[0] : null;
    console.log(`  ${m.key.padEnd(14)} control ${String(cu.join(',') || '—').padEnd(10)} ` +
                `router ${String(ru.join(',') || '—').padEnd(10)} offset ${off ?? '—'}` +
                (cell.errors.length ? `   ${cell.errors[0].slice(0, 60)}` : ''));
  }
}

/* ---------------- score against the registered criteria ---------------- */

const uniq = a => [...new Set(a.filter(v => v != null))];
const score = [];
for (const cand of CANDIDATES) {
  const per = MODELS.map(m => {
    const c = data[cand.id][m.key];
    const arm = arms.includes('control') ? c.control : c.router;
    return { model: m.key, values: uniq(arm) };
  });
  const usable = per.filter(p => p.values.length === 1);
  const stable = usable.length === MODELS.length;            // criterion 2
  const counts = usable.map(p => p.values[0]);
  const distinct = new Set(counts).size;
  const collisions = [];
  for (let i = 0; i < usable.length; i++)
    for (let j = i + 1; j < usable.length; j++)
      if (usable[i].values[0] === usable[j].values[0]) collisions.push(`${usable[i].model}=${usable[j].model}`);
  score.push({ id: cand.id, len: cand.text.length, measured: usable.length, stable,
               distinct, collisions, counts: Object.fromEntries(usable.map(p => [p.model, p.values[0]])) });
}

// criterion 1 (max distinct) → 2 (stable) → 3 (shortest)
const ranked = [...score].sort((a, b) =>
  b.distinct - a.distinct || (b.stable === a.stable ? 0 : b.stable ? 1 : -1) || a.len - b.len);
const winner = ranked[0];

line('═');
console.log('  SELECTION — registered criteria: distinct → stable → shortest');
line('═');
console.log('  candidate   len  measured  stable  distinct  collisions');
for (const s of ranked) {
  console.log(`  ${s.id.padEnd(10)}  ${String(s.len).padStart(3)}  ${String(s.measured).padStart(8)}  ` +
              `${String(s.stable).padStart(6)}  ${String(s.distinct).padStart(8)}  ${s.collisions.join(' ') || '—'}`);
}
console.log('');
console.log(`  WINNER: ${winner.id}`);
console.log(`  text:   ${JSON.stringify(CANDIDATES.find(c => c.id === winner.id).text)}`);
console.log(`  counts: ${JSON.stringify(winner.counts)}`);
if (winner.collisions.length)
  console.log(`  ⚠ unresolved collisions: ${winner.collisions.join(', ')} — §5 requires these be documented explicitly in Amendment 1`);
if (!winner.stable)
  console.log(`  ⚠ criterion 2 not met — a model varied across reps. Do not proceed without explaining why.`);

const offsets = {};
if (arms.length === 2) {
  for (const m of MODELS) {
    const c = data[winner.id][m.key];
    const cu = uniq(c.control), ru = uniq(c.router);
    offsets[m.key] = (cu.length === 1 && ru.length === 1) ? ru[0] - cu[0] : null;
  }
  const vals = Object.values(offsets).filter(v => v != null);
  console.log('');
  console.log(`  translation offsets (router − control): ${JSON.stringify(offsets)}`);
  if (vals.length) console.log(`  suggested tolerance: ±${Math.max(...vals.map(Math.abs)) + 1} tokens`);
}

writeFileSync(`${OUT}/results.json`,
  JSON.stringify({ candidates: CANDIDATES, models: MODELS, arms,
                   reps: { control: CONTROL_REPS, router: ROUTER_REPS },
                   data, score: ranked, winner, offsets }, null, 2));
line();
console.log(`  ${OUT}/results.json written — this is the evidence Amendment 1 cites.`);
console.log('  Calibration data is NOT study data (§5). Report it separately.');
line();
