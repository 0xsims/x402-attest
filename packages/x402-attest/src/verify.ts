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
 *   2. Walking the proof from that leaf must reproduce the claimed root.
 *   3. GET /v1/verify/{attestationId} must report `anchored` and must carry the
 *      same root.
 *
 * Any one of those failing means the receipt does not say what it claims to say.
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
    anchored: 'pass' | 'fail' | 'skipped';
    rootMatch: 'pass' | 'fail' | 'skipped';
  };
  computed: { leafHash: string; root?: string };
  remote?: { status?: string; found?: boolean; verified?: boolean; source?: string };
};

export type VerifyOptions = {
  /** Skip the network step. Checks 1 and 2 only. */
  offline?: boolean;
  fetchImpl?: FetchLike;
  /** Override the URL in the receipt; useful against a staging node. */
  verifyUrl?: string;
  timeoutMs?: number;
};

/**
 * Locate our root anywhere in the verification response.
 *
 * Rubric's public verify endpoint returns the attestation record it holds, and the
 * exact nesting of the submitted payload under `attestation` is not pinned by the
 * published docs. Rather than hard-code one path and produce false negatives when
 * it moves, we check the documented shapes first and then scan. A root is a
 * 64-char hex digest, so a scan match is not a coincidence.
 */
export function findRoot(body: unknown, root: string): { found: boolean; path?: string } {
  const seen = new Set<unknown>();
  const walk = (node: unknown, path: string): string | undefined => {
    if (node === null || node === undefined) return undefined;
    if (typeof node === 'string') return node === root ? path : undefined;
    if (typeof node !== 'object') return undefined;
    if (seen.has(node)) return undefined;
    seen.add(node);
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const hit = walk(node[i], `${path}[${i}]`);
        if (hit) return hit;
      }
      return undefined;
    }
    for (const [k, v] of Object.entries(node as Record<string, unknown>)) {
      const hit = walk(v, path ? `${path}.${k}` : k);
      if (hit) return hit;
    }
    return undefined;
  };
  const path = walk(body, '');
  return path ? { found: true, path } : { found: false };
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
    anchored: 'skipped',
    rootMatch: 'skipped',
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

  if (options.offline) {
    return {
      ok: true,
      code: VERIFY_EXIT.VALID,
      reason: 'hash and proof verified; anchor check skipped (offline)',
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
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
  const remote = {
    status: readStatus(body),
    found: typeof o['found'] === 'boolean' ? (o['found'] as boolean) : undefined,
    verified: typeof o['verified'] === 'boolean' ? (o['verified'] as boolean) : undefined,
    source: typeof o['source'] === 'string' ? (o['source'] as string) : undefined,
  };

  if (remote.found === false) {
    checks.anchored = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.NOT_ANCHORED,
      reason: `attestation ${receipt.attestationId} is not known to the verifier`,
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
      remote,
    };
  }

  // Root check runs before the anchor-state check: a record that is still
  // buffering but already carries the wrong root is tampering, not impatience.
  const hit = findRoot(body, receipt.root);
  if (!hit.found) {
    checks.rootMatch = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.PROOF_MISMATCH,
      reason: `the anchored attestation does not contain root ${receipt.root}`,
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
      remote,
    };
  }
  checks.rootMatch = 'pass';

  if (remote.status !== 'anchored') {
    checks.anchored = 'fail';
    return {
      ok: false,
      code: VERIFY_EXIT.NOT_ANCHORED,
      reason:
        `attestation ${receipt.attestationId} is in state "${remote.status ?? 'unknown'}", not "anchored". ` +
        'The hash and proof are valid; the batch has not reached the ledger yet.',
      checks,
      computed: { leafHash: computedLeaf, root: computedRoot },
      remote,
    };
  }
  checks.anchored = 'pass';

  return {
    ok: true,
    code: VERIFY_EXIT.VALID,
    reason: 'receipt is valid: record hashes to its leaf, proof reaches the anchored root',
    checks,
    computed: { leafHash: computedLeaf, root: computedRoot },
    remote,
  };
}
