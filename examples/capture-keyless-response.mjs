#!/usr/bin/env node
/**
 * Capture one live keyless anchor, response body and all.
 *
 * Exists because `test/mocks/rubric.ts` has twice returned fields the live server
 * does not (DEVIATIONS §4, §20), and a third instance would be a pattern rather
 * than bad luck. The mock's keyless route is built from the body this writes, not
 * from a guess at what the route "should" return.
 *
 *   export X402_PRIVATE_KEY=0x...
 *   node examples/capture-keyless-response.mjs           # dry run, no payment
 *   node examples/capture-keyless-response.mjs --live     # pays $0.005 USDC on Base
 *
 * Writes packages/x402-attest/test/fixtures/live-mainnet/x402-anchor-response.json
 * and prints the verification result for the receipt it produced.
 */
import { mkdirSync, writeFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { verifyReceipt, withAttestation } from '../packages/x402-attest/dist/index.js';

const LIVE = process.argv.includes('--live');
const OUT = './packages/x402-attest/test/fixtures/live-mainnet';
const WAL = './.tmp-capture/wal';

if (!LIVE) {
  console.log('\n  Dry run. Re-run with --live to anchor. This pays $0.005 USDC on Base mainnet.\n');
  process.exit(0);
}

const pk = process.env.X402_PRIVATE_KEY;
if (!/^0x[0-9a-fA-F]{64}$/.test(pk ?? '')) {
  console.error('\n  X402_PRIVATE_KEY not set or malformed\n');
  process.exit(1);
}

const account = privateKeyToAccount(pk);
const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(account));
const paidFetch = wrapFetchWithPayment(fetch, x402);

/** Sits under the x402 client and keeps the anchor request and response verbatim. */
const captured = { request: null, status: null, body: null };
const capturingFetch = async (url, init) => {
  const res = await paidFetch(url, init);
  if (String(url).includes('/v1/x402/tiered-attest') && res.status !== 402) {
    captured.request = init?.body ? JSON.parse(init.body) : null;
    captured.status = res.status;
    const text = await res.clone().text();
    try {
      captured.body = JSON.parse(text);
    } catch {
      captured.body = { _nonJsonBody: text.slice(0, 512) };
    }
  }
  return res;
};

mkdirSync(WAL, { recursive: true });
mkdirSync(OUT, { recursive: true });

// One synthetic call. No seller involved: this run is about the anchor response,
// not about attesting anything in particular.
const attest = withAttestation(
  async () =>
    new Response(JSON.stringify({ capture: 'keyless-anchor-response', at: new Date().toISOString() }), {
      status: 200,
      headers: { 'content-type': 'application/json' },
    }),
  {
    subjectId: 'keyless-response-capture',
    sessionId: 'x402Payment-reconstruction',
    mode: 'batch',
    walPath: WAL,
    anchorFetch: capturingFetch,
    installSignalHandlers: false,
    policy: { maxPricePerCall: '0.05', allowedNetworks: ['eip155:8453'], budgetCap: '0.10' },
  },
);

await attest('https://capture.local/keyless', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ capture: true }),
});

const [flush] = await attest.flush();
console.log(`\n  anchor: ${flush.status}  attestation ${flush.attestationId ?? '-'}  ${flush.error ?? ''}`);

const receipt = attest.attestor.batcher.allReceipts()[0];
await attest.close();

writeFileSync(
  `${OUT}/x402-anchor-response.json`,
  JSON.stringify({ request: captured.request, status: captured.status, body: captured.body }, null, 2) + '\n',
);
console.log(`\n  wrote ${OUT}/x402-anchor-response.json`);
console.log('\n  response body:\n' + JSON.stringify(captured.body, null, 2));

writeFileSync('./.tmp-capture/receipt.json', JSON.stringify(receipt, null, 2) + '\n');

// Offline first: this is the check that the recorded envelope opens its own
// commitment, and it needs no network at all.
const offline = await verifyReceipt(receipt, { offline: true });
console.log(`\n  offline verify: exit ${offline.code}  binding ${offline.binding}  commitment ${offline.checks.commitment}`);
console.log(`    ${offline.reason}`);

const online = await verifyReceipt(receipt);
console.log(`\n  online verify:  exit ${online.code}  binding ${online.binding}  checks ${JSON.stringify(online.checks)}`);
console.log(`    ${online.reason}\n`);
