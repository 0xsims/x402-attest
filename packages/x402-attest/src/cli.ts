import { readFileSync } from 'node:fs';
import { VERIFY_EXIT, verifyReceipt, type VerifyExitCode, type VerifyResult } from './verify.js';
import type { Receipt } from './types.js';

/**
 * Standalone verifier CLI.
 *
 * Exit codes are the interface — this is meant to be a CI gate, not something a
 * human reads. 0 valid, 1 hash mismatch, 2 proof mismatch, 3 not anchored,
 * 4 fetch failed, 5 pending anchor.
 */

/** Both `x402-attest` and `x402-verify` share this implementation. */
const usage = (bin: string): string => `${bin} — verify Rubric attestation receipts

Usage:
  ${bin} verify <receipt.json> [options]

Options:
  --offline          Check the hash and the inclusion proof only; skip the anchor fetch.
  --verify-url <url> Override the verify endpoint recorded in the receipt.
  --timeout <ms>     Anchor fetch timeout (default 15000).
  --json             Emit machine-readable results on stdout.
  --quiet            Suppress human-readable output.
  -h, --help         Show this message.

Exit codes:
  0  valid
  1  hash mismatch      the call record does not hash to its claimed leaf
  2  proof mismatch     the inclusion proof does not reach the anchored root
  3  not anchored       valid locally, but the batch is not on the ledger yet
  4  fetch failed       the public verify endpoint could not be reached
  5  pending anchor     signed and held by the node, HCS flush still in flight

The input may be a single receipt, a JSON array of receipts, or JSONL. When it
holds several, the exit code is the worst result across all of them.

Verification needs no API key and no cooperation from Rubric beyond a public GET.`;

export type CliIo = {
  out: (s: string) => void;
  err: (s: string) => void;
};

const DEFAULT_IO: CliIo = {
  out: (s) => process.stdout.write(s + '\n'),
  err: (s) => process.stderr.write(s + '\n'),
};

/** Accept a single receipt, a JSON array, or JSONL — all three occur in practice. */
export function parseReceiptFile(text: string): Receipt[] {
  const trimmed = text.trim();
  if (trimmed.length === 0) throw new Error('receipt file is empty');

  try {
    const parsed = JSON.parse(trimmed);
    if (Array.isArray(parsed)) return parsed as Receipt[];
    return [parsed as Receipt];
  } catch {
    // Fall through to JSONL.
  }

  const receipts: Receipt[] = [];
  trimmed.split('\n').forEach((line, i) => {
    if (line.trim().length === 0) return;
    try {
      receipts.push(JSON.parse(line) as Receipt);
    } catch {
      throw new Error(`line ${i + 1} is neither JSON nor part of a JSON document`);
    }
  });
  if (receipts.length === 0) throw new Error('no receipts found in file');
  return receipts;
}

type Args = {
  command?: string;
  file?: string;
  offline: boolean;
  json: boolean;
  quiet: boolean;
  help: boolean;
  verifyUrl?: string;
  timeoutMs?: number;
};

export function parseArgs(argv: string[]): Args {
  const args: Args = { offline: false, json: false, quiet: false, help: false };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (a === '-h' || a === '--help') args.help = true;
    else if (a === '--offline') args.offline = true;
    else if (a === '--json') args.json = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--verify-url') args.verifyUrl = argv[++i];
    else if (a.startsWith('--verify-url=')) args.verifyUrl = a.slice('--verify-url='.length);
    else if (a === '--timeout') args.timeoutMs = Number(argv[++i]);
    else if (a.startsWith('--timeout=')) args.timeoutMs = Number(a.slice('--timeout='.length));
    else if (!args.command) args.command = a;
    else if (!args.file) args.file = a;
  }
  return args;
}

function symbol(v: string): string {
  return v === 'pass' ? 'ok' : v === 'fail' ? 'FAIL' : v;
}

function render(io: CliIo, r: VerifyResult, label: string): void {
  // "INVALID" on a receipt whose only fault is that the ledger flush has not run
  // yet says the record was altered. It was not; say what is actually true.
  const verdict = r.ok
    ? 'VALID'
    : r.code === VERIFY_EXIT.PENDING_ANCHOR
      ? 'PENDING'
      : 'INVALID';
  io.out(`${verdict}  ${label}`);
  io.out(`  leaf hash      ${symbol(r.checks.leafHash)}  ${r.computed.leafHash}`);
  io.out(`  proof          ${symbol(r.checks.proof)}${r.computed.root ? '    ' + r.computed.root : ''}`);
  io.out(`  envelope root  ${symbol(r.checks.envelopeRoot)}`);
  // Say exactly which comparison happened. "skipped (recomputed)" reads as a
  // contradiction, and an offline pass must not read like the online one.
  const offline = r.checks.anchored === 'skipped';
  let bindingNote = '';
  if (r.checks.commitment === 'skipped') {
    // Recomputed, but with nothing available to compare it against.
    if (r.binding === 'recomputed') bindingNote = '  (recomputed locally, not compared — offline)';
  } else if (r.binding && r.binding !== 'none') {
    // An offline pass is a real result — the envelope opens the digest the
    // receipt records — but the node was never asked whether it holds that
    // digest. An offline FAIL needs no such caveat: it is decisive on its own.
    bindingNote =
      offline && r.checks.commitment === 'pass'
        ? '  (recomputed locally; the node was not asked)'
        : `  (${r.binding})`;
  }
  io.out(`  commitment     ${symbol(r.checks.commitment)}${bindingNote}`);
  io.out(`  anchored       ${symbol(r.checks.anchored)}${r.remote?.status ? '  (' + r.remote.status + ')' : ''}`);
  if (r.remote?.mirrorNodeUrl) io.out(`  independent    ${r.remote.mirrorNodeUrl}`);
  io.out(`  ${r.reason}`);
}

/** The worst outcome wins: a batch is only as trustworthy as its weakest receipt. */
function worst(codes: VerifyExitCode[]): VerifyExitCode {
  const severity: VerifyExitCode[] = [
    VERIFY_EXIT.VALID,
    // Least severe of the non-zero codes: the node has the record and everything
    // checkable checks out, so this resolves on its own within a minute or two.
    VERIFY_EXIT.PENDING_ANCHOR,
    VERIFY_EXIT.NOT_ANCHORED,
    VERIFY_EXIT.FETCH_FAILED,
    VERIFY_EXIT.PROOF_MISMATCH,
    VERIFY_EXIT.HASH_MISMATCH,
  ];
  let out: VerifyExitCode = VERIFY_EXIT.VALID;
  for (const c of codes) {
    if (severity.indexOf(c) > severity.indexOf(out)) out = c;
  }
  return out;
}

export async function runCli(
  argv: string[],
  io: CliIo = DEFAULT_IO,
  fetchImpl?: typeof fetch,
  binName = 'x402-attest',
): Promise<number> {
  const args = parseArgs(argv);
  const USAGE = usage(binName);

  if (args.help || !args.command) {
    io.out(USAGE);
    return args.help ? 0 : VERIFY_EXIT.FETCH_FAILED;
  }
  if (args.command !== 'verify') {
    io.err(`unknown command: ${args.command}`);
    io.err(USAGE);
    return VERIFY_EXIT.FETCH_FAILED;
  }
  if (!args.file) {
    io.err('verify needs a receipt file');
    return VERIFY_EXIT.FETCH_FAILED;
  }

  let receipts: Receipt[];
  try {
    receipts = parseReceiptFile(readFileSync(args.file, 'utf8'));
  } catch (e) {
    io.err(`cannot read ${args.file}: ${(e as Error).message}`);
    return VERIFY_EXIT.FETCH_FAILED;
  }

  const results: VerifyResult[] = [];
  for (const receipt of receipts) {
    const opts: Parameters<typeof verifyReceipt>[1] = { offline: args.offline };
    if (args.verifyUrl) opts.verifyUrl = args.verifyUrl;
    if (args.timeoutMs !== undefined && Number.isFinite(args.timeoutMs)) {
      opts.timeoutMs = args.timeoutMs;
    }
    if (fetchImpl) opts.fetchImpl = fetchImpl as never;
    results.push(await verifyReceipt(receipt, opts));
  }

  if (args.json) {
    io.out(JSON.stringify(receipts.length === 1 ? results[0] : results, null, 2));
  } else if (!args.quiet) {
    results.forEach((r, i) => {
      render(io, r, receipts[i]?.callRecord?.callId ?? `receipt[${i}]`);
    });
  }

  return worst(results.map((r) => r.code));
}
