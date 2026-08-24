#!/usr/bin/env node
/**
 * LIVE MAINNET DEMO — spends real USDC on Base.
 *
 * Makes one x402-paid call to BlockRun's chat completions API, attests it, and
 * anchors the batch on Hedera via Rubric's KEYLESS path (the attestation is
 * itself bought over x402). Prints a public verify URL anyone can check without
 * an account.
 *
 *   export X402_PRIVATE_KEY=0x...        # Base wallet, funded with a little USDC
 *   node examples/live-mainnet.mjs                 # preflight only, spends nothing
 *   node examples/live-mainnet.mjs --live          # actually spends
 *
 * Optional:
 *   MODEL=openai/gpt-5.5                 # what to request
 *   PROMPT="..."                         # what to ask
 */
import { createPublicClient, http, formatUnits } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';
// x402 v2. `x402-fetch` (v1) is deprecated and cannot read BlockRun's
// header-delivered challenge — it looks for `accepts` in the response body.
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { createTap, withAttestation, verifyReceipt } from '@tempus1/x402-attest';
import { mkdirSync, writeFileSync } from 'node:fs';

const LIVE = process.argv.includes('--live');
const OUT = './.live-run';
const WAL = `${OUT}/wal`;

const ENDPOINT = 'https://blockrun.ai/api/v1/chat/completions';
const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const BASE_CAIP2 = 'eip155:8453';

const MODEL = process.env.MODEL ?? 'openai/gpt-5.5';
const PROMPT = process.env.PROMPT ?? 'Reply with exactly one word: attested';

/** BlockRun quotes 2000 atomic USDC ($0.002) for a small completion. */
const EXPECTED_ATOMIC = 2_000n;

const die = (msg) => { console.error(`\n✗ ${msg}\n`); process.exit(1); };
const line = () => console.log('─'.repeat(64));

/* ------------------------------------------------------------------ *
 * Preflight — never spends.
 * ------------------------------------------------------------------ */
const pk = process.env.X402_PRIVATE_KEY;
if (!pk) die('X402_PRIVATE_KEY is not set. Use a throwaway wallet, not your main one.');
if (!/^0x[0-9a-fA-F]{64}$/.test(pk)) die('X402_PRIVATE_KEY must be a 0x-prefixed 32-byte hex key.');

const account = privateKeyToAccount(pk);
const publicClient = createPublicClient({ chain: base, transport: http() });

const balance = await publicClient.readContract({
  address: USDC_BASE,
  abi: [{
    name: 'balanceOf', type: 'function', stateMutability: 'view',
    inputs: [{ name: 'a', type: 'address' }], outputs: [{ type: 'uint256' }],
  }],
  functionName: 'balanceOf',
  args: [account.address],
});

line();
console.log('  PREFLIGHT');
line();
console.log(`  wallet        ${account.address}`);
console.log(`  network       Base mainnet (${BASE_CAIP2})`);
console.log(`  USDC balance  $${formatUnits(balance, 6)}`);
console.log(`  endpoint      ${ENDPOINT}`);
console.log(`  model asked   ${MODEL}`);
console.log(`  quoted price  $${formatUnits(EXPECTED_ATOMIC, 6)} per call (x402 v2)`);
console.log(`  spend ceiling $0.10 policy cap, $1.00 session cap`);
console.log(`  anchoring     keyless — the attestation is itself paid over x402`);
line();

if (balance < 50_000n) {
  console.log('\n  ⚠  Balance is under $0.05. The call plus the $0.005 anchor need more than that.');
  console.log('     Send a dollar of USDC on Base to the address above.\n');
}

if (!LIVE) {
  console.log('\n  Dry run. Nothing was spent. Re-run with --live to make the call.\n');
  process.exit(0);
}
if (balance === 0n) die('Zero USDC balance — fund the wallet first.');

/* ------------------------------------------------------------------ *
 * Wiring.
 *
 * The tap observes the raw 402 challenge and the payment header so the
 * receipt can record what was advertised vs what was paid. The x402 client
 * wraps the tapped fetch; the attestor wraps that.
 *
 * anchorFetch is the RAW client — wrapping the attested one would make each
 * attestation attest itself, forever.
 * ------------------------------------------------------------------ */
mkdirSync(WAL, { recursive: true });

const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(account));

const tap = createTap();
const paidFetch = wrapFetchWithPayment(tap.wrapFetch(fetch), x402);
const anchorFetch = wrapFetchWithPayment(fetch, x402);

let callId = null;
const fetchAndPay = withAttestation(paidFetch, {
  subjectId: 'live-demo',
  sessionId: `live-${account.address.slice(0, 10)}`,
  mode: 'batch',
  walPath: WAL,
  tap,
  anchorFetch,
  policy: {
    maxPricePerCall: '0.10',
    allowedNetworks: [BASE_CAIP2],
    budgetCap: '1.00',
  },
  onReceipt: (r) => { callId ??= r.callRecord.callId; },
  onAnchorError: (e, n) => console.log(`  anchor attempt ${n} failed: ${e.message}`),
});

/* ------------------------------------------------------------------ *
 * 1. The paid call.
 * ------------------------------------------------------------------ */
console.log('\n  1. Paying for one LLM call over x402 …\n');

const res = await fetchAndPay(ENDPOINT, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({
    model: MODEL,
    messages: [{ role: 'user', content: PROMPT }],
    max_tokens: 16,
  }),
});

const body = await res.json().catch(() => ({}));
if (!res.ok) {
  console.log(`  HTTP ${res.status}`);
  console.log(`  ${JSON.stringify(body).slice(0, 400)}`);
}

console.log(`  status        ${res.status}`);
console.log(`  model served  ${body?.model ?? '(not reported)'}`);
console.log(`  answer        ${JSON.stringify(body?.choices?.[0]?.message?.content ?? null)}`);

/* ------------------------------------------------------------------ *
 * 2. Anchor.
 * ------------------------------------------------------------------ */
console.log('\n  2. Anchoring the batch on Hedera (paid over x402, no API key) …\n');

const flushed = await fetchAndPay.flush();
const receipt = callId ? fetchAndPay.getReceipt(callId) : undefined;

if (!receipt) {
  console.log('  No receipt produced. WAL retained at', WAL);
  console.log('  flush result:', JSON.stringify(flushed, null, 2));
  await fetchAndPay.close();
  process.exit(1);
}

mkdirSync(OUT, { recursive: true });
writeFileSync(`${OUT}/receipt.json`, JSON.stringify(receipt, null, 2));

console.log(`  attestationId ${receipt.attestationId ?? '(pending)'}`);
console.log(`  leafHash      ${receipt.leafHash}`);
console.log(`  root          ${receipt.root}`);
console.log(`  verifyUrl     ${receipt.verifyUrl ?? '(pending)'}      (human page)`);
console.log(`  verifyApiUrl  ${receipt.verifyApiUrl ?? '(pending)'}   (JSON API)`);

/* ------------------------------------------------------------------ *
 * 3. What was checked.
 * ------------------------------------------------------------------ */
console.log('\n  3. Assertions recorded at call time\n');
for (const a of receipt.callRecord.assertions) {
  const mark = a.result === 'pass' ? '✓' : a.result === 'fail' ? '✗' : '·';
  const detail = a.expected || a.observed ? `  (${a.expected ?? '?'} → ${a.observed ?? '?'})` : '';
  console.log(`  ${mark} ${a.id.padEnd(24)} ${a.result}${detail}`);
}

/* ------------------------------------------------------------------ *
 * 4. Verify it the way a stranger would.
 * ------------------------------------------------------------------ */
console.log('\n  4. Verifying against the public endpoint (no API key) …\n');

const v = await verifyReceipt(receipt);
console.log(`  ok            ${v.ok}`);
console.log(`  checks        ${JSON.stringify(v.checks)}`);
if (v.reason) console.log(`  reason        ${v.reason}`);

// Expect `anchored: pending` here. HCS anchoring happens at the next tier-2
// flush, 60-120s out, so verifying this soon is normal and is not a failure.
if (v.checks.anchored === 'pending') {
  console.log('\n  ↑ pending is expected this soon after anchoring — re-run the');
  console.log('    verify CLI in a couple of minutes and it becomes exit 0.');
}

line();
console.log('  Receipt written to', `${OUT}/receipt.json`);
if (receipt.verifyUrl) console.log('  Anyone can check it at', receipt.verifyUrl);
console.log('  Or from any machine:  npx @tempus1/x402-verify-cli', `${OUT}/receipt.json`);
line();

await fetchAndPay.close();
