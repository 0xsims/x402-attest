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
    anchored: 'pass' | 'fail' | 'skipped';
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
  /** Override the URL in the receipt; useful against a staging node. */
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
  const url = options.verifyUrl ?? receipt.verifyUrl;
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
      body = JSON.parse(text);
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
    checks.anchored = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.NOT_ANCHORED,
      reason:
        `attestation ${receipt.attestationId} is in state "${remote.status ?? 'unknown'}", not "anchored". ` +
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
