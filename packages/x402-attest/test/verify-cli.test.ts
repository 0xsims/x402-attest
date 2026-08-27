import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { execFile } from 'node:child_process';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { promisify } from 'node:util';
import { withAttestation } from '../src/index.js';
import { VERIFY_EXIT, readCommitment, verifyReceipt } from '../src/verify.js';
import { parseArgs, parseReceiptFile, runCli } from '../src/cli.js';
import { isAnchored, type FetchLike, type Receipt } from '../src/types.js';
import { startMockRubric, tmpWal, type MockRubric } from './mocks/rubric.js';

const execFileAsync = promisify(execFile);
const PKG = resolve(__dirname, '..');
const BIN = join(PKG, 'bin', 'x402-attest.js');

/**
 * Verification is the product.
 *
 * Every one of these tests answers the same question from a different angle: can
 * a third party who trusts nobody — not the agent, not the seller, not Rubric —
 * tell a real receipt from a doctored one?
 */
describe('receipt verification', () => {
  let rubric: MockRubric;
  let walPath: string;
  let dir: string;

  beforeEach(async () => {
    rubric = await startMockRubric();
    walPath = tmpWal('verify');
    dir = tmpWal('verify-out');
    mkdirSync(dir, { recursive: true });
  });

  afterEach(async () => {
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  });

  /** Produce a genuine, anchored receipt through the real pipeline. */
  async function makeReceipt(count = 4): Promise<Receipt[]> {
    const upstream: FetchLike = async () =>
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    const wrapped = withAttestation(upstream, {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      sessionId: 'verify-session',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });
    for (let i = 0; i < count; i++) {
      const r = await wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' });
      await r.arrayBuffer();
    }
    await wrapped.flush();
    const out = wrapped.attestor.batcher.allReceipts().filter(isAnchored);
    await wrapped.close();
    return out;
  }

  it('accepts a genuine receipt (exit 0)', async () => {
    for (const receipt of await makeReceipt()) {
      const r = await verifyReceipt(receipt, { fetchImpl: fetch });
      expect(r.ok).toBe(true);
      expect(r.code).toBe(VERIFY_EXIT.VALID);
      expect(r.remote?.status).toBe('anchored');
    }
  });

  it('detects a single mutated byte in the call record (exit 1)', async () => {
    const [receipt] = await makeReceipt(1);
    const tampered: Receipt = structuredClone(receipt!);
    // Change one character of the host. The record no longer hashes to its leaf.
    tampered.callRecord.request.host = tampered.callRecord.request.host.replace(/.$/, 'X');

    const r = await verifyReceipt(tampered, { fetchImpl: fetch });
    expect(r.ok).toBe(false);
    expect(r.code).toBe(VERIFY_EXIT.HASH_MISMATCH);
    expect(r.checks.leafHash).toBe('fail');
    expect(r.reason).toMatch(/leaf hash mismatch/);
  });

  it('detects tampering in any field, including the assertions', async () => {
    const [receipt] = await makeReceipt(1);
    const cases: [string, (r: Receipt) => void][] = [
      ['outcome', (r) => (r.callRecord.outcome = 'timeout')],
      ['response.status', (r) => (r.callRecord.response.status = 500)],
      ['assertion result', (r) => (r.callRecord.assertions[0]!.result = 'pass')],
      ['durationMs', (r) => (r.callRecord.durationMs += 1000)],
      ['subjectId', (r) => (r.callRecord.subjectId = 'someone-else')],
      ['request.bodyHash', (r) => (r.callRecord.request.bodyHash = 'f'.repeat(64))],
      ['callId', (r) => (r.callRecord.callId = '018f0000-0000-7000-8000-00000000ffff')],
      ['added field', (r) => ((r.callRecord as Record<string, unknown>)['extra'] = 1)],
      ['removed field', (r) => delete (r.callRecord as Partial<Receipt['callRecord']>).sessionId],
    ];

    for (const [label, mutate] of cases) {
      const t: Receipt = structuredClone(receipt!);
      mutate(t);
      // Guard the test itself: a mutation that changed nothing would make this
      // suite pass for the wrong reason.
      expect(JSON.stringify(t.callRecord), `${label} was a no-op`).not.toBe(
        JSON.stringify(receipt!.callRecord),
      );
      const r = await verifyReceipt(t, { fetchImpl: fetch });
      expect(r.code, `tampering with ${label} was not detected`).toBe(
        VERIFY_EXIT.HASH_MISMATCH,
      );
    }
  });

  it('is insensitive to key order, because the hash is over canonical JSON', async () => {
    const [receipt] = await makeReceipt(1);

    // Rebuild every object in the record with its keys in reverse order. Same
    // data, different serialized bytes — which is exactly the case JCS exists to
    // make hash-identical, and the reason a plain JSON.stringify hash would break
    // whenever a record crossed a language or library boundary.
    const reverseKeys = (v: unknown): unknown => {
      if (Array.isArray(v)) return v.map(reverseKeys);
      if (v && typeof v === 'object') {
        const out: Record<string, unknown> = {};
        for (const k of Object.keys(v as object).reverse()) {
          out[k] = reverseKeys((v as Record<string, unknown>)[k]);
        }
        return out;
      }
      return v;
    };

    const reordered = { ...receipt!, callRecord: reverseKeys(receipt!.callRecord) } as Receipt;
    expect(JSON.stringify(reordered.callRecord)).not.toBe(JSON.stringify(receipt!.callRecord));

    const r = await verifyReceipt(reordered, { fetchImpl: fetch });
    expect(r.ok).toBe(true);
  });

  it('detects a swapped or forged inclusion proof (exit 2)', async () => {
    const receipts = await makeReceipt(4);
    // Give leaf 0 the proof that belongs to leaf 1.
    const swapped: Receipt = { ...receipts[0]!, proof: receipts[1]!.proof };
    const r = await verifyReceipt(swapped, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.PROOF_MISMATCH);
    expect(r.checks.proof).toBe('fail');

    const emptied: Receipt = { ...receipts[0]!, proof: [] };
    expect((await verifyReceipt(emptied, { fetchImpl: fetch })).code).toBe(
      VERIFY_EXIT.PROOF_MISMATCH,
    );

    const malformed: Receipt = {
      ...receipts[0]!,
      proof: [{ hash: 'not-a-hash', side: 'left' }],
    };
    expect((await verifyReceipt(malformed, { fetchImpl: fetch })).code).toBe(
      VERIFY_EXIT.PROOF_MISMATCH,
    );

    const badRoot: Receipt = { ...receipts[0]!, root: 'zz' };
    expect((await verifyReceipt(badRoot, { fetchImpl: fetch })).code).toBe(
      VERIFY_EXIT.PROOF_MISMATCH,
    );
  });

  it('detects a receipt bound to a different payload than the node holds (exit 2)', async () => {
    const [receipt] = await makeReceipt(1);
    rubric.options.corruptCommitment = true; // node now serves a different commitment
    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.PROOF_MISMATCH);
    expect(r.checks.commitment).toBe('fail');
    expect(r.reason).toMatch(/bound to a different payload/);
  });

  it('detects an altered envelope locally, before any network call', async () => {
    const [receipt] = await makeReceipt(1);
    // Change the batch metadata; the commitment no longer opens.
    const tampered = {
      ...receipt!,
      envelope: { ...receipt!.envelope, leafCount: 999 },
    };
    const r = await verifyReceipt(tampered, { offline: true });
    expect(r.code).toBe(VERIFY_EXIT.PROOF_MISMATCH);
    expect(r.checks.commitment).toBe('fail');
    expect(r.reason).toMatch(/does not open its commitment/);
  });

  it('detects a root that was never the one submitted (exit 2)', async () => {
    const [receipt] = await makeReceipt(1);
    // Envelope says one root, the proof proves another.
    const swapped = {
      ...receipt!,
      envelope: { ...receipt!.envelope, root: 'b'.repeat(64) },
    };
    const r = await verifyReceipt(swapped, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.PROOF_MISMATCH);
    expect(r.checks.envelopeRoot).toBe('fail');
    expect(r.reason).toMatch(/envelope names root/);
  });

  it('reports the binding as unverifiable when nothing can bind the payload', async () => {
    const [receipt] = await makeReceipt(1);
    // A receipt from a node that returned neither a commitment nor a payload key —
    // e.g. an older server, or the direct /v1/attest path.
    const {
      payloadCommitment: _c,
      commitmentSalt: _s,
      ...noCommitment
    } = receipt!;
    const r = await verifyReceipt(noCommitment as typeof receipt, { fetchImpl: fetch });
    // The attestation is anchored and the receipt is internally sound, but
    // nothing ties them together — that must not read as a clean pass.
    expect(r.checks.commitment).toBe('unverifiable');
    expect(r.binding).toBe('none');
    expect(r.reason).toMatch(/no commitment available/);
  });

  it('falls back to a recorded binding when there is a commitment but no salt', async () => {
    const [receipt] = await makeReceipt(1);
    // What every keyless x402 receipt looks like: the node issued a commitment
    // but returned no payload key, so no opening salt could be derived. The
    // binding still holds — it just rests on the receipt's own word for what the
    // commitment was, which detects a receipt pointed at the wrong attestation
    // but not one whose commitment and root were fabricated together.
    const { commitmentSalt: _s, ...noSalt } = receipt!;
    const r = await verifyReceipt(noSalt as Receipt, { fetchImpl: fetch });

    expect(r.ok).toBe(true);
    expect(r.code).toBe(VERIFY_EXIT.VALID);
    expect(r.binding).toBe('recorded');
    expect(r.checks.commitment).toBe('pass');
    // ...and it says which of the two checks ran, rather than letting a clean
    // exit imply the stronger one.
    expect(r.reason).toMatch(/matched by recorded value/);
    expect(r.reason).not.toMatch(/recomputed/);
  });

  it('still verifies a real receipt anchored with no commitment material at all', async () => {
    // `.prereg/receipt.json` — the preregistration anchor, attestation
    // 47cfc0e4…, HCS sequence 291930. Real wire data, not a hand-built fixture:
    // it was produced over the keyless x402 path, which returns neither a
    // payload key nor a commitment, so it carries neither. A verifier that grew
    // a stronger check must keep accepting it rather than rejecting evidence it
    // simply cannot bind.
    const raw = readFileSync(resolve(PKG, '..', '..', '.prereg', 'receipt.json'), 'utf8');
    const receipt = JSON.parse(raw) as Receipt;
    expect(receipt.attestationId).toBe('47cfc0e4-e54a-4f0f-a9d8-94fc09f49e1c');
    expect(receipt.commitmentSalt).toBeUndefined();
    expect(receipt.payloadCommitment).toBeUndefined();

    // Offline: the local chain is the part that must not regress, and pinning a
    // test to a live mainnet GET would make the suite fail on a network blip.
    const r = await verifyReceipt(receipt, { offline: true });
    expect(r.ok).toBe(true);
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
    expect(r.checks.envelopeRoot).toBe('pass');
    // Unbound, and reported as unbound.
    expect(r.binding).toBe('none');
  });

  it('recomputes the commitment from the envelope and its opening salt', async () => {
    const [receipt] = await makeReceipt(1);
    // Fully trustless: nothing secret, nothing taken on the receipt's word.
    expect(receipt!.commitmentSalt).toMatch(/^[0-9a-f]{64}$/);

    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.ok).toBe(true);
    expect(r.binding).toBe('recomputed');
    expect(r.checks.commitment).toBe('pass');
    expect(r.computed.commitment).toBe(receipt!.payloadCommitment);

    // The salt is derived one-way from the payload key, so publishing it in a
    // receipt does not disclose the key that decrypts the payload at Rubric.
    expect(JSON.stringify(receipt)).not.toContain('a'.repeat(64));
  });

  it('passes the commitment offline when the envelope opens it', async () => {
    const [receipt] = await makeReceipt(1);
    const r = await verifyReceipt(receipt!, { offline: true });

    // Recomputing SHA-256(salt + jcs(envelope)) and finding the digest the
    // receipt records needs no network, and it is the same computation that
    // reports `fail` on a mismatch. Reporting only the failure and calling the
    // success `skipped` understates what was actually checked.
    expect(r.checks.commitment).toBe('pass');
    expect(r.binding).toBe('recomputed');
    expect(r.computed.commitment).toBe(receipt!.payloadCommitment);
    expect(r.ok).toBe(true);

    // ...and it does not overclaim: the node was never asked.
    expect(r.checks.anchored).toBe('skipped');
    expect(r.remote).toBeUndefined();
    expect(r.reason).toMatch(/whether the node holds that commitment is unchecked/);
  });

  it('tells a check it declined to run from one it had no material for', async () => {
    const [receipt] = await makeReceipt(1);

    // No salt: `binding: 'recorded'`. The only comparison available offline is
    // the receipt's commitment against itself, which proves nothing while
    // reading like a stronger result — so it stays unchecked until the node is
    // asked. This is the §20 argument, applied one link along. `skipped`, because
    // the comparison exists and one network call would settle it.
    const { commitmentSalt: _s, ...noSalt } = receipt!;
    const recorded = await verifyReceipt(noSalt as Receipt, { offline: true });
    expect(recorded.binding).toBe('recorded');
    expect(recorded.checks.commitment).toBe('skipped');

    // A salt but no recorded commitment: something was computed, and the node
    // holds the digest it would be compared against. Also `skipped`.
    const { payloadCommitment: _c, ...noCommitment } = receipt!;
    const noTarget = await verifyReceipt(noCommitment as Receipt, { offline: true });
    expect(noTarget.binding).toBe('recomputed');
    expect(noTarget.checks.commitment).toBe('skipped');

    // Neither. Nothing on this receipt could bind the payload to an attestation,
    // and no network call changes that — so `unverifiable`, exactly as the online
    // path reports the same receipt. Calling it `skipped` would imply the check
    // was merely deferred.
    const { commitmentSalt: _s2, payloadCommitment: _c2, ...bare } = receipt!;
    const none = await verifyReceipt(bare as Receipt, { offline: true });
    expect(none.binding).toBe('none');
    expect(none.checks.commitment).toBe('unverifiable');
    expect(none.reason).toMatch(/nothing that could bind the payload/);

    // Same receipt, same word, with the node in the loop.
    const online = await verifyReceipt(bare as Receipt, { fetchImpl: fetch });
    expect(online.checks.commitment).toBe('unverifiable');
  });

  it('reports a batch that has not reached the ledger yet as pending (exit 5)', async () => {
    rubric.options.verifyStatus = 'signed-pending-flush';
    const [receipt] = await makeReceipt(1);
    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.PENDING_ANCHOR);
    expect(r.checks.anchored).toBe('pending');
    // Hash, proof and commitment are fine; only the ledger flush is outstanding,
    // and the message says so rather than implying the receipt is forged.
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
    expect(r.checks.commitment).toBe('pass');
    expect(r.reason).toMatch(/still in flight/);
    expect(r.reason).not.toMatch(/not "anchored"/);
    // Here a commitment *was* compared, so the message may say so.
    expect(r.reason).toMatch(/the commitment all check out/);
  });

  it('still reports an unrecognized anchor state as not anchored (exit 3)', async () => {
    // `pending` is for states the node reports while it is still working. A
    // state we cannot place is not evidence of tampering either, but it does not
    // get the "this resolves itself in a minute" framing.
    rubric.options.verifyStatus = 'revoked';
    const [receipt] = await makeReceipt(1);
    const r = await verifyReceipt(receipt!, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.NOT_ANCHORED);
    expect(r.checks.anchored).toBe('fail');
    expect(r.reason).toMatch(/has not reached the ledger yet/);
  });

  it('reports an unknown attestation as not anchored (exit 3)', async () => {
    const [receipt] = await makeReceipt(1);
    const unknown: Receipt = {
      ...receipt!,
      verifyApiUrl: `${rubric.url}/v1/verify/does-not-exist`,
    };
    const r = await verifyReceipt(unknown, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.NOT_ANCHORED);
    expect(r.reason).toMatch(/not known to the verifier/);
  });

  it('reports an unreachable verifier as a fetch failure (exit 4)', async () => {
    const [receipt] = await makeReceipt(1);
    const dead: Receipt = { ...receipt!, verifyApiUrl: 'http://127.0.0.1:1/v1/verify/x' };
    const r = await verifyReceipt(dead, { fetchImpl: fetch });
    expect(r.code).toBe(VERIFY_EXIT.FETCH_FAILED);
    // Crucially NOT reported as invalid: unreachable is not the same as forged.
    expect(r.checks.leafHash).toBe('pass');
    expect(r.checks.proof).toBe('pass');
  });

  it('distinguishes an HTTP error from an unreachable host, both exit 4', async () => {
    const [receipt] = await makeReceipt(1);
    const erroring: FetchLike = async () => new Response('nope', { status: 500 });
    const r = await verifyReceipt(receipt!, { fetchImpl: erroring });
    expect(r.code).toBe(VERIFY_EXIT.FETCH_FAILED);
    expect(r.reason).toMatch(/HTTP 500/);
  });

  it('verifies hash and proof offline, with no network at all', async () => {
    const [receipt] = await makeReceipt(1);
    const r = await verifyReceipt(receipt!, { offline: true });
    expect(r.ok).toBe(true);
    expect(r.checks.anchored).toBe('skipped');
    expect(r.reason).toMatch(/offline/);
  });

  it('needs no API key: the verify request carries no credentials', async () => {
    const [receipt] = await makeReceipt(1);
    await verifyReceipt(receipt!, { fetchImpl: fetch });
    const verifyReq = rubric.requests.find((r) => r.path.startsWith('/v1/verify/'))!;
    expect(verifyReq.headers['x-api-key']).toBeUndefined();
    expect(verifyReq.headers['authorization']).toBeUndefined();
  });

  it('rejects a receipt with no call record', async () => {
    const r = await verifyReceipt({} as Receipt, { offline: true });
    expect(r.code).toBe(VERIFY_EXIT.HASH_MISMATCH);
    expect(r.reason).toMatch(/missing callRecord/);
  });

  describe('readCommitment', () => {
    it('reads the commitment from the shape the live node returns', () => {
      expect(
        readCommitment({ attestation: { payload: { payload_commitment: 'abc' } } }),
      ).toBe('abc');
    });

    it('tolerates alternative spellings and nestings', () => {
      expect(readCommitment({ attestation: { payload_commitment: 'x' } })).toBe('x');
      expect(readCommitment({ attestation: { payloadCommitment: 'y' } })).toBe('y');
      expect(readCommitment({ payloadCommitment: 'z' })).toBe('z');
      expect(readCommitment({ payload: { payload_commitment: 'w' } })).toBe('w');
    });

    it('returns undefined rather than guessing when absent', () => {
      // Degrading to `unverifiable` is correct; inventing a value would turn a
      // reshaped response into a false accusation of tampering.
      expect(readCommitment({ attestation: {} })).toBeUndefined();
      expect(readCommitment(null)).toBeUndefined();
      expect(readCommitment('nope')).toBeUndefined();
    });
  });
});

describe('verify CLI', () => {
  let rubric: MockRubric;
  let walPath: string;
  let dir: string;
  const out: string[] = [];
  const err: string[] = [];
  const io = { out: (s: string) => out.push(s), err: (s: string) => err.push(s) };

  beforeEach(async () => {
    rubric = await startMockRubric();
    walPath = tmpWal('cli');
    dir = tmpWal('cli-out');
    mkdirSync(dir, { recursive: true });
    out.length = 0;
    err.length = 0;
  });

  afterEach(async () => {
    await rubric.close();
    rmSync(walPath, { recursive: true, force: true });
    rmSync(dir, { recursive: true, force: true });
  });

  async function writeReceipts(count: number): Promise<{ receipts: Receipt[]; path: string }> {
    const wrapped = withAttestation(async () => new Response('{}', { status: 200 }), {
      rubricApiKey: 'test-key',
      subjectId: 'agent-alpha',
      walPath,
      rubricBaseUrl: rubric.url,
      installSignalHandlers: false,
    });
    for (let i = 0; i < count; i++) {
      await (await wrapped(`https://seller.example/${i}`, { method: 'POST', body: '{}' })).arrayBuffer();
    }
    await wrapped.flush();
    const receipts = wrapped.attestor.batcher.allReceipts().filter(isAnchored);
    await wrapped.close();

    const path = join(dir, 'receipt.json');
    writeFileSync(path, JSON.stringify(receipts[0], null, 2));
    return { receipts, path };
  }

  it('exits 0 on a valid receipt', async () => {
    const { path } = await writeReceipts(1);
    expect(await runCli(['verify', path], io)).toBe(0);
    expect(out.join('\n')).toContain('VALID');
  });

  it('exits nonzero when one byte of the call record is mutated', async () => {
    const { receipts } = await writeReceipts(1);
    const tampered = structuredClone(receipts[0]!);
    tampered.callRecord.request.path = '/tampered';
    const path = join(dir, 'tampered.json');
    writeFileSync(path, JSON.stringify(tampered));

    const code = await runCli(['verify', path], io);
    expect(code).not.toBe(0);
    expect(code).toBe(1);
    expect(out.join('\n')).toContain('INVALID');
  });

  it('exits 5 and prints PENDING, not INVALID, while the anchor is in flight', async () => {
    rubric.options.verifyStatus = 'signed-pending-hcs';
    const { path } = await writeReceipts(1);
    expect(await runCli(['verify', path], io)).toBe(VERIFY_EXIT.PENDING_ANCHOR);
    // The word on screen is the whole point: "INVALID" on a receipt whose only
    // fault is that the batch has not flushed yet reads as an accusation.
    expect(out.join('\n')).toContain('PENDING');
    expect(out.join('\n')).not.toContain('INVALID');
    expect(out.join('\n')).toContain('anchored       pending');
  });

  it('lets a real problem outrank a pending one across a batch', async () => {
    rubric.options.verifyStatus = 'signed-pending-hcs';
    const { receipts } = await writeReceipts(2);
    const tampered = structuredClone(receipts[1]!);
    tampered.callRecord.request.path = '/tampered';
    const path = join(dir, 'mixed.jsonl');
    writeFileSync(path, [receipts[0], tampered].map((r) => JSON.stringify(r)).join('\n'));

    expect(await runCli(['verify', path], io)).toBe(VERIFY_EXIT.HASH_MISMATCH);
  });

  it('runs the whole thing as a real subprocess and sets the exit code', async () => {
    const { receipts } = await writeReceipts(1);

    const goodPath = join(dir, 'good.json');
    writeFileSync(goodPath, JSON.stringify(receipts[0]));
    const ok = await execFileAsync(process.execPath, [BIN, 'verify', goodPath]);
    expect(ok.stdout).toContain('VALID');

    const tampered = structuredClone(receipts[0]!);
    tampered.callRecord.response.status = 999;
    const badPath = join(dir, 'bad.json');
    writeFileSync(badPath, JSON.stringify(tampered));

    await expect(
      execFileAsync(process.execPath, [BIN, 'verify', badPath]),
    ).rejects.toMatchObject({ code: 1 });
  });

  it('reports the worst result across a multi-receipt file', async () => {
    const { receipts } = await writeReceipts(3);
    const mixed = structuredClone(receipts);
    mixed[2]!.callRecord.subjectId = 'forged';

    const jsonlPath = join(dir, 'batch.jsonl');
    writeFileSync(jsonlPath, mixed.map((r) => JSON.stringify(r)).join('\n') + '\n');
    expect(await runCli(['verify', jsonlPath], io)).toBe(1);

    const arrayPath = join(dir, 'batch.json');
    writeFileSync(arrayPath, JSON.stringify(receipts));
    expect(await runCli(['verify', arrayPath], io)).toBe(0);
  });

  it('supports --offline, --json and --quiet', async () => {
    const { path } = await writeReceipts(1);

    expect(await runCli(['verify', path, '--offline'], io)).toBe(0);

    out.length = 0;
    expect(await runCli(['verify', path, '--json'], io)).toBe(0);
    const parsed = JSON.parse(out.join('\n'));
    expect(parsed.ok).toBe(true);
    expect(parsed.checks.proof).toBe('pass');

    out.length = 0;
    expect(await runCli(['verify', path, '--quiet'], io)).toBe(0);
    expect(out).toHaveLength(0);
  });

  it('honours --verify-url and --timeout', async () => {
    const { receipts } = await writeReceipts(1);
    const path = join(dir, 'r.json');
    writeFileSync(path, JSON.stringify(receipts[0]));

    const url = `${rubric.url}/v1/verify/${receipts[0]!.attestationId}`;
    expect(await runCli(['verify', path, '--verify-url', url, '--timeout', '5000'], io)).toBe(0);
    expect(await runCli([`verify`, path, `--verify-url=${url}`, `--timeout=5000`], io)).toBe(0);
  });

  it('prints usage and exits 4 on a bad invocation', async () => {
    expect(await runCli(['--help'], io)).toBe(0);
    expect(out.join('\n')).toContain('Usage:');

    expect(await runCli([], io)).toBe(4);
    expect(await runCli(['frobnicate', 'x'], io)).toBe(4);
    expect(await runCli(['verify'], io)).toBe(4);
    expect(await runCli(['verify', '/no/such/file.json'], io)).toBe(4);
    expect(err.join('\n')).toMatch(/cannot read/);
  });

  it('parses receipt files as JSON, arrays or JSONL', () => {
    expect(parseReceiptFile('{"a":1}')).toEqual([{ a: 1 }]);
    expect(parseReceiptFile('[{"a":1},{"b":2}]')).toEqual([{ a: 1 }, { b: 2 }]);
    expect(parseReceiptFile('{"a":1}\n{"b":2}\n')).toEqual([{ a: 1 }, { b: 2 }]);
    expect(() => parseReceiptFile('   ')).toThrow(/empty/);
    expect(() => parseReceiptFile('{"a":1}\nnot json')).toThrow(/line 2/);
  });

  it('parses arguments', () => {
    const a = parseArgs(['verify', 'f.json', '--offline', '--json', '--quiet']);
    expect(a).toMatchObject({
      command: 'verify',
      file: 'f.json',
      offline: true,
      json: true,
      quiet: true,
    });
  });
});
