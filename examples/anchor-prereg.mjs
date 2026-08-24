#!/usr/bin/env node
/**
 * Anchor the preregistration.
 *
 * Hashes PREREGISTRATION.md exactly as it sits on disk, attests the hash over
 * x402 (keyless), and prints the attestation id + verify url to paste back into
 * the document's footer.
 *
 *   export X402_PRIVATE_KEY=0x...
 *   node examples/anchor-prereg.mjs ./PREREGISTRATION.md          # dry run
 *   node examples/anchor-prereg.mjs ./PREREGISTRATION.md --live
 *
 * The file is NOT modified. Its hash is the commitment; editing it afterwards
 * breaks the commitment, which is the entire point.
 */
import { createHash } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { privateKeyToAccount } from 'viem/accounts';
import { wrapFetchWithPayment } from '@x402/fetch';
import { x402Client } from '@x402/core/client';
import { ExactEvmScheme } from '@x402/evm/exact/client';
import { withAttestation } from '@tempus1/x402-attest';

const path = process.argv[2];
const LIVE = process.argv.includes('--live');
if (!path) { console.error('usage: anchor-prereg.mjs <file> [--live]'); process.exit(1); }

const bytes = readFileSync(path);
const sha = createHash('sha256').update(bytes).digest('hex');

console.log('─'.repeat(72));
console.log('  PREREGISTRATION ANCHOR');
console.log('─'.repeat(72));
console.log(`  file    ${path}`);
console.log(`  bytes   ${bytes.length}`);
console.log(`  sha256  ${sha}`);
console.log('─'.repeat(72));

if (!LIVE) { console.log('\n  Dry run. Re-run with --live to anchor.\n'); process.exit(0); }

const pk = process.env.X402_PRIVATE_KEY;
if (!/^0x[0-9a-fA-F]{64}$/.test(pk ?? '')) { console.error('\n✗ X402_PRIVATE_KEY not set or malformed\n'); process.exit(1); }

const account = privateKeyToAccount(pk);
const x402 = new x402Client();
x402.register('eip155:*', new ExactEvmScheme(account));
const anchorFetch = wrapFetchWithPayment(fetch, x402);

mkdirSync('./.prereg/wal', { recursive: true });

// One synthetic call whose record IS the commitment. No seller involved.
const attest = withAttestation(
  async () => new Response(JSON.stringify({ document: path, sha256: sha, bytes: bytes.length }),
                           { status: 200, headers: { 'content-type': 'application/json' } }),
  { subjectId: 'rubric-substitution-study',
    sessionId: 'preregistration-v1',
    mode: 'batch',
    walPath: './.prereg/wal',
    anchorFetch,
    policy: { maxPricePerCall: '0.05', allowedNetworks: ['eip155:8453'], budgetCap: '0.10' } },
);

const res = await attest(`https://preregistration.local/${sha}`, {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ documentSha256: sha, filename: path.split('/').pop(), byteLength: bytes.length }),
});
await res.arrayBuffer();

console.log('\n  Anchoring …\n');
await attest.flush();

const receipt = attest.attestor.batcher.allReceipts().slice(-1)[0];
writeFileSync('./.prereg/receipt.json', JSON.stringify(receipt, null, 2));

console.log(`  attestationId  ${receipt?.attestationId ?? '(pending)'}`);
console.log(`  leafHash       ${receipt?.leafHash}`);
console.log(`  root           ${receipt?.root}`);
console.log(`  verifyUrl      ${receipt?.verifyUrl ?? '(pending)'}`);
console.log('\n  Receipt: ./.prereg/receipt.json');
console.log('\n  Paste the attestation id and, once anchored, the HCS sequence into');
console.log('  the footer of the document — as a SEPARATE commit. Do not edit the');
console.log('  bytes above that line; the hash is the commitment.\n');

await attest.close();
