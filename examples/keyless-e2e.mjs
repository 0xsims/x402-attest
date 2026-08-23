#!/usr/bin/env node
/**
 * End-to-end demo: paid x402 calls -> batched Merkle anchor -> verifiable receipt.
 *
 * Runs entirely against in-process mock servers. No live network, no API key, no
 * wallet, no Rubric account. The anchoring path used here is the KEYLESS one: the
 * attestation is itself bought over x402, the same way the calls it attests were.
 *
 *   node examples/keyless-e2e.mjs
 */
import { createServer } from 'node:http';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { createTap, isAnchored, verifyReceipt, withAttestation } from '../packages/x402-attest/dist/index.js';

const WAL = './.tmp-example/wal';
const OUT = './.tmp-example';
rmSync(OUT, { recursive: true, force: true });
mkdirSync(WAL, { recursive: true });

const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64');
const listen = (server) =>
  new Promise((res) => server.listen(0, '127.0.0.1', () => res(`http://127.0.0.1:${server.address().port}`)));
const readBody = async (req) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
};

const SELLER_PAYEE = '0x1111111111111111111111111111111111111111';
const RUBRIC_PAYEE = '0x9999999999999999999999999999999999999999';

/* ------------------------------------------------------------------ *
 * 1. A mock x402 seller: an LLM route that quietly substitutes models.
 * ------------------------------------------------------------------ */
const sellerServer = createServer(async (req, res) => {
  await readBody(req);
  const payment = req.headers['payment-signature'];

  if (!payment) {
    res.writeHead(402, { 'content-type': 'application/json' });
    res.end(
      JSON.stringify({
        x402Version: 1,
        error: 'PAYMENT-SIGNATURE header is required',
        accepts: [
          {
            scheme: 'exact',
            network: 'eip155:8453',
            maxAmountRequired: '3000', // 3000 atomic USDC == $0.003
            payTo: SELLER_PAYEE,
            asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
            resource: `http://${req.headers.host}${req.url}`,
            maxTimeoutSeconds: 60,
          },
        ],
      }),
    );
    return;
  }

  res.writeHead(200, {
    'content-type': 'application/json',
    // The router announces what it actually served. This is the evidence behind
    // the proof-of-routing check.
    'x-clawrouter-model': 'google/gemini-2.5-flash',
    'x-clawrouter-tier': 'SIMPLE',
    'payment-response': b64({
      success: true,
      transaction: '0x' + 'ab'.repeat(32),
      network: 'eip155:8453',
      payer: '0x2222222222222222222222222222222222222222',
    }),
    // Deliberately sensitive, and deliberately dropped by the header allowlist.
    'set-cookie': 'session=do-not-record-me',
  });
  res.end(
    JSON.stringify({
      id: 'chatcmpl-demo',
      model: 'google/gemini-2.5-flash',
      choices: [{ message: { role: 'assistant', content: 'confidential completion text' } }],
      usage: { prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 },
    }),
  );
});

/* ------------------------------------------------------------------ *
 * 2. A mock Rubric node: x402-paid attestation plus a public verify GET.
 * ------------------------------------------------------------------ */
const anchored = new Map();
const rubricServer = createServer(async (req, res) => {
  const body = await readBody(req);
  const path = (req.url ?? '').split('?')[0];
  const json = (status, payload) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(payload));
  };

  if (path.startsWith('/v1/verify/')) {
    const id = decodeURIComponent(path.slice('/v1/verify/'.length));
    const record = anchored.get(id);
    if (!record) return json(200, { found: false, status: 'unknown' });
    // Mirrors the live node: a commitment, not the payload.
    return json(200, {
      found: true,
      status: 'anchored',
      verified: true,
      payloadHashMatch: true,
      source: 'warm-store',
      sequenceNumber: 291514,
      hcsExplorerUrl: 'https://hashscan.io/mainnet/topic/0.0.10416909',
      mirrorNodeUrl:
        'https://mainnet-public.mirrornode.hedera.com/api/v1/topics/0.0.10416909/messages?sequencenumber=291514&limit=1',
      attestation: {
        attestation_id: id,
        attestation_type: 'tiered',
        algorithm: 'ML-DSA-65',
        payload: { payload_commitment: record.commitment },
      },
    });
  }

  if (path !== '/v1/x402/tiered-attest') return json(404, { error: 'not found' });

  // The attestation endpoint charges for itself, over x402.
  if (!req.headers['payment-signature']) {
    return json(402, {
      x402Version: 1,
      accepts: [
        {
          scheme: 'exact',
          network: 'eip155:8453',
          maxAmountRequired: '5000', // $0.005 per attestation
          payTo: RUBRIC_PAYEE,
          asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913',
          maxTimeoutSeconds: 60,
        },
      ],
    });
  }

  const { data } = JSON.parse(body);
  const attestationId = randomUUID();
  // The node keeps a commitment, never the plaintext payload — tiered payloads
  // are encrypted at rest. This is the only handle /v1/verify gives back.
  const commitment = createHash('sha3-256').update(JSON.stringify(data)).digest('hex');
  anchored.set(attestationId, { commitment });
  return json(200, {
    success: true,
    paid: true,
    settled: true,
    settlement: { txHash: '0x' + 'cd'.repeat(32), network: 'base' },
    attestationId,
    payloadCommitment: commitment,
    algorithm: 'ML-DSA-65',
    topic: '0.0.10416909',
    verifyUrl: `http://127.0.0.1:${rubricServer.address().port}/v1/verify/${attestationId}`,
  });
});

/* ------------------------------------------------------------------ *
 * 3. A minimal x402 payment client: 402 -> sign -> retry.
 * ------------------------------------------------------------------ */
function x402Fetch(inner) {
  return async (input, init) => {
    const first = await inner(input, init);
    if (first.status !== 402) return first;

    const { accepts } = await first.clone().json();
    const req = accepts[0];
    const authorization = {
      from: '0x2222222222222222222222222222222222222222',
      to: req.payTo,
      value: req.maxAmountRequired,
      validAfter: '0',
      validBefore: '99999999999',
      nonce: '0x' + '11'.repeat(32),
    };
    const header = b64({
      x402Version: 1,
      scheme: req.scheme,
      network: req.network,
      asset: req.asset,
      payload: {
        signature: '0x' + createHash('sha256').update(JSON.stringify(authorization)).digest('hex'),
        authorization,
      },
    });
    const headers = new Headers(init?.headers);
    headers.set('PAYMENT-SIGNATURE', header);
    return inner(input, { ...init, headers });
  };
}

const sellerUrl = await listen(sellerServer);
const rubricUrl = await listen(rubricServer);

/* ------------------------------------------------------------------ *
 * 4. The one-line integration.
 * ------------------------------------------------------------------ */
const tap = createTap();
const baseX402Fetch = x402Fetch(tap.wrapFetch(fetch));

const fetchAndPay = withAttestation(baseX402Fetch, {
  // No rubricApiKey: the keyless path. Attestations are paid for over x402 using
  // the RAW client, never the attested wrapper — otherwise anchoring would attest
  // itself, forever.
  anchorFetch: x402Fetch(fetch),
  rubricBaseUrl: rubricUrl,

  subjectId: 'agent-alpha',
  policyId: 'trading-desk-v2',
  sessionId: 'run-2026-08-23-01',
  mode: 'batch',
  batch: { maxLeaves: 256, maxAgeMs: 60_000 },
  redact: 'hash-only',
  policy: {
    maxPricePerCall: '0.05',
    allowedNetworks: ['eip155:8453'],
    allowedPayTo: [SELLER_PAYEE],
    budgetCap: '25.00',
  },
  walPath: WAL,
  tap,
  installSignalHandlers: false,
  onReceipt: (r) => {
    // onReceipt fires twice per call: once as soon as the leaf is durable (so a
    // violation surfaces immediately, not 60s later when the batch anchors), and
    // again once the attestation id and inclusion proof exist. Log only the first.
    if (isAnchored(r)) return;
    const violations = r.callRecord.assertions.filter((a) => a.result === 'fail');
    if (violations.length > 0) {
      console.log(
        `  ! ${r.callRecord.callId.slice(0, 8)} policy violation: ` +
          violations.map((v) => v.id).join(', '),
      );
    }
  },
});

/* ------------------------------------------------------------------ *
 * 5. Make some paid calls.
 * ------------------------------------------------------------------ */
console.log('\n=== 1. Paying for three LLM calls over x402 ===\n');
for (let i = 0; i < 3; i++) {
  const res = await fetchAndPay(`${sellerUrl}/v1/chat/completions?trace=secret-token-${i}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      model: 'anthropic/claude-sonnet-4.6',
      messages: [{ role: 'user', content: 'confidential prompt text' }],
    }),
  });
  const body = await res.json();
  console.log(`  call ${i}: HTTP ${res.status}, served "${body.model}"`);
}
console.log(`\n  session spend: $${fetchAndPay.attestor.spendUsd}`);

/* ------------------------------------------------------------------ *
 * 6. Anchor the batch. One attestation for all three calls.
 * ------------------------------------------------------------------ */
console.log('\n=== 2. Anchoring the batch (paid over x402, no API key) ===\n');
const [flushResult] = await fetchAndPay.flush();
console.log(`  ${flushResult.leafCount} leaves -> 1 attestation`);
console.log(`  merkle root:    ${flushResult.root}`);
console.log(`  attestation id: ${flushResult.attestationId}`);
console.log(`  cost per call:  $${(0.005 / flushResult.leafCount).toFixed(8)} (attestation $0.005 / ${flushResult.leafCount})`);

/* ------------------------------------------------------------------ *
 * 7. A worked receipt.
 * ------------------------------------------------------------------ */
const receipts = fetchAndPay.attestor.batcher.allReceipts();
const receipt = receipts[0];

console.log('\n=== 3. A receipt ===\n');
console.log(JSON.stringify(receipt, null, 2));

console.log('\n  checks recorded:');
for (const a of receipt.callRecord.assertions) {
  const mark = a.result === 'pass' ? 'PASS' : a.result === 'fail' ? 'FAIL' : ' ?  ';
  console.log(`    [${mark}] ${a.id}${a.detail ? '  (' + a.detail + ')' : ''}`);
}

console.log('\n  privacy check on this receipt:');
const serialized = JSON.stringify(receipt);
for (const secret of ['confidential prompt text', 'confidential completion text', 'secret-token-0', 'do-not-record-me']) {
  console.log(`    ${serialized.includes(secret) ? 'LEAKED' : 'absent'}: "${secret}"`);
}

/* ------------------------------------------------------------------ *
 * 8. Verify it. No key, no cooperation from the agent or the seller.
 * ------------------------------------------------------------------ */
console.log('\n=== 4. Third-party verification ===\n');
const good = await verifyReceipt(receipt);
console.log(`  genuine receipt -> exit ${good.code} (${good.ok ? 'VALID' : 'INVALID'})`);
console.log(`    ${good.reason}`);
console.log(`    binding: ${good.binding}   checks: ${JSON.stringify(good.checks)}`);

const tampered = structuredClone(receipt);
tampered.callRecord.challenge.maxAmountRequired = '1';
const bad = await verifyReceipt(tampered);
console.log(`  one byte changed -> exit ${bad.code} (${bad.ok ? 'VALID' : 'INVALID'}): ${bad.reason}`);

/* ------------------------------------------------------------------ *
 * 9. Artifacts for audit.
 * ------------------------------------------------------------------ */
writeFileSync(`${OUT}/receipt.json`, JSON.stringify(receipt, null, 2));
writeFileSync(`${OUT}/tampered.json`, JSON.stringify(tampered, null, 2));
writeFileSync(`${OUT}/receipts.csv`, fetchAndPay.exportReceipts({ format: 'csv' }));

console.log('\n=== 5. Audit export ===\n');
console.log(
  fetchAndPay
    .exportReceipts({ format: 'csv' })
    .split('\n')
    .slice(0, 2)
    .map((l) => '  ' + l.slice(0, 160) + (l.length > 160 ? ' ...' : ''))
    .join('\n'),
);

console.log(`\n  wrote ${OUT}/receipt.json, ${OUT}/tampered.json, ${OUT}/receipts.csv`);
console.log('\n  verify from the shell:');
console.log(`    node packages/x402-attest/bin/x402-attest.js verify ${OUT}/receipt.json --offline   # exit 0`);
console.log(`    node packages/x402-attest/bin/x402-attest.js verify ${OUT}/tampered.json --offline  # exit 1`);
console.log(
  '\n  --offline is needed here only because this demo\'s Rubric node lives inside\n' +
    '  this process and its ephemeral port dies with it. Against a real node, drop\n' +
    '  the flag and the anchor state is checked too. Without --offline you will see\n' +
    '  exit 4 (fetch failed) rather than exit 0 — which is the correct answer:\n' +
    '  "unreachable" is not the same as "forged", and the CLI never conflates them.\n',
);

await fetchAndPay.close();
sellerServer.close();
rubricServer.close();
