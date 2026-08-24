import { computeCommitment } from './anchor.js';
import { jcs } from './jcs.js';
import { sha256Jcs } from './hash.js';
import { computeRootFromProof } from './merkle.js';
import type { FetchLike, Receipt } from './types.js';

/**
 * Receipt verification.
 *
 * This is the whole trust story, and it deliberately depends on nothing: no API
 * key, no cooperation from Rubric beyond a public GET, no cooperation from the
 * seller, and no trust in the agent that produced the receipt. Steps 1 and 2 are
 * pure local computation; step 3 is a single unauthenticated request.
 *
 *   1. sha256(jcs(callRecord)) must equal the claimed leafHash.
 *   2. Walking the proof from that leaf must reproduce the claimed root, and that
 *      root must be the one named in the batch envelope.
 *   3. GET /v1/verify/{attestationId} must report `anchored`, and the commitment
 *      it holds must equal the one recorded in the receipt.
 *
 * Step 3 is NOT a root comparison, though an earlier version of this file assumed
 * it was. Checked against the live mainnet node on 2026-08-23: tiered payloads are
 * encrypted at rest and `/v1/verify` returns only `payload.payload_commitment` and
 * `payload_hash` — the submitted payload, and therefore our root, is never echoed
 * back. Scanning the response for the root fails on every genuine receipt.
 *
 * What that costs, stated plainly: the chain runs
 *   callRecord -> leafHash -> proof -> root -> envelope -> commitment -> anchor.
 * Every link is checked locally except the last. Binding envelope to commitment
 * requires knowing how Rubric derives it, which is unconfirmed; until it is, the
 * verifier compares the commitment the receipt recorded against the one the node
 * holds, and reports that link as `recorded` rather than `recomputed`. Supply
 * `recomputeCommitment` to close it, and the result upgrades automatically.
 */

export const VERIFY_EXIT = {
  VALID: 0,
  HASH_MISMATCH: 1,
  PROOF_MISMATCH: 2,
  NOT_ANCHORED: 3,
  FETCH_FAILED: 4,
  /**
   * Signed and held by the node, ledger anchor still in flight.
   *
   * Distinct from NOT_ANCHORED because the difference matters to whoever reads
   * the exit code. HCS anchoring happens at the next tier-2 flush, typically
   * 60-120s after submission, so every receipt verified inside that window is in
   * this state. Reporting it as a failure in a tamper-evidence tool reads as
   * "this record was altered", which is both false and the most damaging thing
   * this library could say.
   */
  PENDING_ANCHOR: 5,
} as const;

export type VerifyExitCode = (typeof VERIFY_EXIT)[keyof typeof VERIFY_EXIT];

export type VerifyResult = {
  ok: boolean;
  code: VerifyExitCode;
  reason: string;
  checks: {
    leafHash: 'pass' | 'fail';
    proof: 'pass' | 'fail' | 'skipped';
    /** Does the proven root match the root named in the batch envelope? */
    envelopeRoot: 'pass' | 'fail' | 'skipped';
    /** Does the node hold the commitment this receipt recorded? */
    commitment: 'pass' | 'fail' | 'skipped' | 'unverifiable';
    /** `pending` — the node holds it, the ledger anchor has not landed yet. */
    anchored: 'pass' | 'fail' | 'pending' | 'skipped';
  };
  /**
   * How the envelope was bound to the anchored commitment.
   *
   * `recomputed` — derived from the envelope here; fully trustless.
   * `recorded`   — the receipt's stored commitment matched the node's. Detects a
   *                receipt pointed at the wrong attestation, but not one whose
   *                recorded commitment and root were fabricated together.
   * `none`       — no commitment available on either side.
   */
  binding?: 'recomputed' | 'recorded' | 'none';
  computed: { leafHash: string; root?: string; commitment?: string };
  remote?: {
    status?: string;
    found?: boolean;
    verified?: boolean;
    source?: string;
    commitment?: string;
    payloadHashMatch?: boolean;
    sequenceNumber?: number;
    mirrorNodeUrl?: string;
  };
};

export type VerifyOptions = {
  /** Skip the network step. Checks 1 and 2 only. */
  offline?: boolean;
  fetchImpl?: FetchLike;
  /**
   * Override the JSON verify endpoint; useful against a staging node.
   *
   * This must be the API, not the human audit page — it is used verbatim.
   */
  verifyUrl?: string;
  timeoutMs?: number;
  /**
   * Derive the commitment from the submitted envelope.
   *
   * Supply this once Rubric's derivation is confirmed and step 3 becomes fully
   * trustless. Without it the commitment is compared by recorded value.
   */
  recomputeCommitment?: (envelope: unknown) => string;
};

/**
 * Read the commitment the node holds for this attestation.
 *
 * Shape observed on the live node: `attestation.payload.payload_commitment`, with
 * `attestation.payload_hash` alongside. Both spellings and a couple of plausible
 * nestings are accepted so a response reshape degrades to `unverifiable` rather
 * than to a false accusation of tampering.
 */
export function readCommitment(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const o = body as Record<string, unknown>;
  const att = (o['attestation'] ?? o) as Record<string, unknown>;
  const payload = att['payload'];
  const candidates: unknown[] = [
    payload && typeof payload === 'object'
      ? (payload as Record<string, unknown>)['payload_commitment']
      : undefined,
    payload && typeof payload === 'object'
      ? (payload as Record<string, unknown>)['payloadCommitment']
      : undefined,
    att['payload_commitment'],
    att['payloadCommitment'],
    o['payloadCommitment'],
  ];
  for (const c of candidates) {
    if (typeof c === 'string' && c.length > 0) return c;
  }
  return undefined;
}

function readStatus(body: unknown): string | undefined {
  if (!body || typeof body !== 'object') return undefined;
  const o = body as Record<string, unknown>;
  const s = o['status'] ?? (o['attestation'] as Record<string, unknown>)?.['status'];
  return typeof s === 'string' ? s : undefined;
}

function looksLikeDigest(s: string): boolean {
  return /^[0-9a-f]{64}$/.test(s);
}

/**
 * Recover the JSON verify endpoint from a receipt that only carries a link for
 * humans.
 *
 * Rubric's keyless anchor returns `https://host/audit/{id}` — an HTML page. The
 * API for the same record is `https://host/v1/verify/{id}` on the same origin.
 * Keeping the origin matters: tiered attestations resolve from the store of the
 * node that issued them, so rebuilding the URL from a configured default would
 * ask the wrong node in a multi-region deployment.
 */
export function deriveVerifyApiUrl(
  verifyUrl: string | undefined,
  attestationId: string | undefined,
): string | undefined {
  if (!verifyUrl) return undefined;
  let parsed: URL;
  try {
    parsed = new URL(verifyUrl);
  } catch {
    return undefined;
  }
  if (parsed.pathname.includes('/v1/verify/')) return parsed.toString();
  if (!attestationId) return undefined;
  return `${parsed.origin}/v1/verify/${encodeURIComponent(attestationId)}`;
}

/**
 * States the verify API reports for a record it holds but has not yet flushed to
 * HCS. `signed-pending-hcs` is the one observed live; the pattern catches the
 * rest of the family so a renamed non-terminal state degrades to `pending`
 * rather than to a false accusation.
 */
function isPendingStatus(status: string | undefined): boolean {
  if (!status) return false;
  return /pending|buffer|queue|submitt|process/i.test(status);
}

/** Describe a non-JSON verify response without surfacing a raw parser error. */
function describeNonJson(url: string, contentType: string | null, text: string): string {
  const looksHtml = /^\s*<(?:!doctype|html)/i.test(text);
  const ct = contentType ?? 'no content-type';
  const hint = looksHtml
    ? '; this looks like the human audit page, not /v1/verify'
    : '';
  return `expected JSON from the verify API at ${url}, got ${ct}${hint}`;
}

export async function verifyReceipt(
  receipt: Receipt,
  options: VerifyOptions = {},
): Promise<VerifyResult> {
  const checks: VerifyResult['checks'] = {
    leafHash: 'fail',
    proof: 'skipped',
    envelopeRoot: 'skipped',
    commitment: 'skipped',
    anchored: 'skipped',
  };

  if (!receipt || typeof receipt !== 'object' || !receipt.callRecord) {
    return {
      ok: false,
      code: VERIFY_EXIT.HASH_MISMATCH,
      reason: 'receipt is missing callRecord',
      checks,
      computed: { leafHash: '' },
    };
  }

  // 1. The record hashes to what the receipt claims. Any mutation anywhere in the
  //    record — one byte, one reordered key that changes a value — fails here.
  const computedLeaf = sha256Jcs(receipt.callRecord);
  if (computedLeaf !== receipt.leafHash) {
    return {
      ok: false,
      code: VERIFY_EXIT.HASH_MISMATCH,
      reason: `leaf hash mismatch: record hashes to ${computedLeaf}, receipt claims ${receipt.leafHash}`,
      checks,
      computed: { leafHash: computedLeaf },
    };
  }
  checks.leafHash = 'pass';

  // 2. The proof reaches the claimed root.
  if (!Array.isArray(receipt.proof) || typeof receipt.root !== 'string') {
    checks.proof = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.PROOF_MISMATCH,
      reason: 'receipt has no inclusion proof or no root',
      checks,
      computed: { leafHash: computedLeaf },
    };
  }
  if (!looksLikeDigest(receipt.root)) {
    checks.proof = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.PROOF_MISMATCH,
      reason: `root is not a sha256 digest: ${receipt.root}`,
      checks,
      computed: { leafHash: computedLeaf },
    };
  }

  let computedRoot: string;
  try {
    computedRoot = computeRootFromProof(computedLeaf, receipt.proof);
  } catch (e) {
    checks.proof = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.PROOF_MISMATCH,
      reason: `proof is malformed: ${(e as Error).message}`,
      checks,
      computed: { leafHash: computedLeaf },
    };
  }

  if (computedRoot !== receipt.root) {
    checks.proof = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.PROOF_MISMATCH,
      reason: `proof reaches ${computedRoot}, receipt claims root ${receipt.root}`,
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
    };
  }
  checks.proof = 'pass';

  // 2b. The proven root must be the one actually submitted to Rubric. Without
  //     this, a receipt could carry a valid leaf and proof over a root that was
  //     never anchored at all.
  const envelope = receipt.envelope as { root?: string } | undefined;
  if (envelope && typeof envelope.root === 'string') {
    if (envelope.root !== computedRoot) {
      checks.envelopeRoot = 'fail';
      return {
        ok: false,
        code: VERIFY_EXIT.PROOF_MISMATCH,
        reason: `proof reaches ${computedRoot} but the submitted envelope names root ${envelope.root}`,
        checks,
        computed: { leafHash: computedLeaf, root: computedRoot },
      };
    }
    checks.envelopeRoot = 'pass';
  }

  // The commitment we expect the node to be holding.
  //
  // Preferred path: recompute it from the envelope and the opening salt, which
  // needs nothing from Rubric and nothing secret. Rubric derives
  //   commitment = SHA-256(salt + RFC8785(payload))
  // where salt is a one-way function of the payload key, so a receipt carrying
  // the salt is fully verifiable while the decryption key stays sealed.
  let expectedCommitment: string | undefined;
  let binding: VerifyResult['binding'];

  if (options.recomputeCommitment) {
    expectedCommitment = options.recomputeCommitment(receipt.envelope);
    binding = 'recomputed';
  } else if (receipt.commitmentSalt && receipt.envelope) {
    expectedCommitment = computeCommitment(receipt.commitmentSalt, jcs(receipt.envelope));
    binding = 'recomputed';
  } else if (receipt.payloadCommitment) {
    expectedCommitment = receipt.payloadCommitment;
    binding = 'recorded';
  } else {
    binding = 'none';
  }

  // A recomputed commitment that disagrees with the one the receipt recorded means
  // the envelope has been altered since anchoring — catch it before any network
  // call, and report it as tampering rather than as a mismatch with the node.
  if (
    binding === 'recomputed' &&
    receipt.payloadCommitment &&
    expectedCommitment !== receipt.payloadCommitment
  ) {
    checks.commitment = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.PROOF_MISMATCH,
      reason:
        `the envelope does not open its commitment: recomputes to ${expectedCommitment}, ` +
        `receipt records ${receipt.payloadCommitment}`,
      checks,
      binding,
      computed: { leafHash: computedLeaf, root: computedRoot, commitment: expectedCommitment },
    };
  }

  if (options.offline) {
    return {
      ok: true,
      code: VERIFY_EXIT.VALID,
      reason: 'hash and proof verified; anchor check skipped (offline)',
      checks,
      binding,
      computed: { leafHash: computedLeaf, root: computedRoot, commitment: expectedCommitment },
    };
  }

  // 3. The root is anchored. Public GET, no key.
  //
  // `verifyApiUrl` is the JSON endpoint; `verifyUrl` may be the human audit page,
  // which is HTML and cannot be parsed. Receipts written before 0.1.1 carry only
  // the latter, so derive the API path from its origin rather than refusing them.
  const url =
    options.verifyUrl ??
    receipt.verifyApiUrl ??
    deriveVerifyApiUrl(receipt.verifyUrl, receipt.attestationId);
  if (!url) {
    return {
      ok: false,
      code: VERIFY_EXIT.FETCH_FAILED,
      reason: 'receipt has no verifyUrl and none was supplied',
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
    };
  }

  const fetchImpl = options.fetchImpl ?? (globalThis.fetch as FetchLike);
  if (!fetchImpl) {
    return {
      ok: false,
      code: VERIFY_EXIT.FETCH_FAILED,
      reason: 'no fetch implementation available',
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
    };
  }

  let body: unknown;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), options.timeoutMs ?? 15_000);
    try {
      const res = await fetchImpl(url, { signal: controller.signal, headers: { accept: 'application/json' } });
      const text = await res.text();
      if (!res.ok) {
        return {
          ok: false,
          code: VERIFY_EXIT.FETCH_FAILED,
          reason: `verify endpoint returned HTTP ${res.status}`,
          checks,
          computed: { leafHash: computedLeaf, root: computedRoot },
        };
      }
      try {
        body = JSON.parse(text);
      } catch {
        // A parser error here ("Unexpected token '<'") tells the reader nothing
        // about what went wrong. Naming the endpoint and what came back does.
        return {
          ok: false,
          code: VERIFY_EXIT.FETCH_FAILED,
          reason: describeNonJson(url, res.headers.get('content-type'), text),
          checks,
          computed: { leafHash: computedLeaf, root: computedRoot },
        };
      }
    } finally {
      clearTimeout(timer);
    }
  } catch (e) {
    return {
      ok: false,
      code: VERIFY_EXIT.FETCH_FAILED,
      reason: `could not reach the verify endpoint: ${(e as Error).message}`,
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
    };
  }

  const o = (body ?? {}) as Record<string, unknown>;
  const remote: NonNullable<VerifyResult['remote']> = {
    status: readStatus(body),
    found: typeof o['found'] === 'boolean' ? (o['found'] as boolean) : undefined,
    verified: typeof o['verified'] === 'boolean' ? (o['verified'] as boolean) : undefined,
    source: typeof o['source'] === 'string' ? (o['source'] as string) : undefined,
    commitment: readCommitment(body),
    payloadHashMatch:
      typeof o['payloadHashMatch'] === 'boolean' ? (o['payloadHashMatch'] as boolean) : undefined,
    sequenceNumber:
      typeof o['sequenceNumber'] === 'number' ? (o['sequenceNumber'] as number) : undefined,
    mirrorNodeUrl: typeof o['mirrorNodeUrl'] === 'string' ? (o['mirrorNodeUrl'] as string) : undefined,
  };

  if (remote.found === false) {
    checks.anchored = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.NOT_ANCHORED,
      reason: `attestation ${receipt.attestationId} is not known to the verifier`,
      checks,
      binding,
      computed: { leafHash: computedLeaf, root: computedRoot },
      remote,
    };
  }

  // Commitment check runs before the anchor-state check: a record still buffering
  // but already bound to the wrong payload is tampering, not impatience.
  const remoteCommitment = remote.commitment;
  if (expectedCommitment && remoteCommitment) {
    if (expectedCommitment !== remoteCommitment) {
      checks.commitment = 'fail';
      return {
        ok: false,
        code: VERIFY_EXIT.PROOF_MISMATCH,
        reason:
          `attestation ${receipt.attestationId} is bound to a different payload: ` +
          `node holds ${remoteCommitment}, receipt expects ${expectedCommitment}`,
        checks,
        binding,
        computed: { leafHash: computedLeaf, root: computedRoot, commitment: expectedCommitment },
        remote,
      };
    }
    checks.commitment = 'pass';
  } else {
    // Neither side offered a commitment. The receipt is internally sound and the
    // attestation exists, but nothing ties one to the other — say so rather than
    // let a bare `anchored` imply a binding that was never checked.
    checks.commitment = 'unverifiable';
  }

  if (remote.status !== 'anchored') {
    // "Not yet" and "not so" are different claims, and only one of them is an
    // accusation. A record the node has signed and is holding for the next
    // tier-2 flush is pending, not failed — that flush lands 60-120s after
    // submission, so the pending window covers essentially every receipt
    // verified right after it was written.
    const pending = isPendingStatus(remote.status);
    checks.anchored = pending ? 'pending' : 'fail';
    return {
      ok: false,
      code: pending ? VERIFY_EXIT.PENDING_ANCHOR : VERIFY_EXIT.NOT_ANCHORED,
      reason: pending
        ? `attestation ${receipt.attestationId} is in state "${remote.status}": signed and held ` +
          'by the node, ledger anchor still in flight. Nothing is wrong with this receipt — ' +
          // Only claim the commitment where one was actually compared. Saying it
          // "checks out" when it read `unverifiable` would be the same species of
          // overstatement this exit code exists to avoid, pointed the other way.
          (checks.commitment === 'pass'
            ? 'the hash, the proof and the commitment all check out'
            : 'the hash and the proof check out, and the commitment is ' +
              `${checks.commitment}`) +
          '. HCS anchoring happens at the next batch flush, typically 60-120s after ' +
          'submission; verify again after that.'
        : `attestation ${receipt.attestationId} is in state "${remote.status ?? 'unknown'}", not "anchored". ` +
          'The hash and proof are valid; the batch has not reached the ledger yet.',
      checks,
      binding,
      computed: { leafHash: computedLeaf, root: computedRoot, commitment: expectedCommitment },
      remote,
    };
  }
  checks.anchored = 'pass';

  const bindingNote =
    binding === 'recomputed'
      ? 'commitment recomputed from the envelope and its opening salt'
      : binding === 'recorded'
        ? 'commitment matched by recorded value'
        : 'no commitment available to bind the payload';

  return {
    ok: true,
    code: VERIFY_EXIT.VALID,
    reason:
      'receipt is valid: record hashes to its leaf, proof reaches the submitted root, ' +
      `and the attestation is anchored (${bindingNote})`,
    checks,
    binding,
    computed: { leafHash: computedLeaf, root: computedRoot, commitment: expectedCommitment },
    remote,
  };
}
