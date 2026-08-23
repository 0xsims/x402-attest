import { createHash } from 'node:crypto';
import type { ProofStep } from './types.js';

/**
 * Binary sha256 Merkle tree with domain separation and odd-node promotion.
 *
 * DOMAIN SEPARATION
 * Leaves are hashed as sha256(0x00 || leafHash), internal nodes as
 * sha256(0x01 || left || right). Without the distinct prefixes an attacker who
 * controls a leaf could submit a value that is itself a valid internal-node
 * preimage, and present a 64-byte "leaf" as if it were a subtree — the classic
 * Merkle second-preimage attack. The prefix makes the two hash domains disjoint.
 *
 * ODD NODE RULE — promotion, not duplication
 * When a level has an odd number of nodes the unpaired node is PROMOTED unchanged
 * to the next level. It is NOT duplicated and paired with itself.
 *
 * Duplication (the Bitcoin rule) is what makes CVE-2012-2459 possible: a tree over
 * [A, B, C] and a tree over [A, B, C, C] produce the same root, so two different
 * batches — one of which the submitter never actually made — become
 * indistinguishable. For an audit artifact that is fatal: it lets someone claim a
 * leaf was in a batch that never contained it. Promotion keeps the leaf count
 * bound to exactly one root.
 *
 * Note that promotion alone does not make the structure length-unambiguous in
 * general; the batch envelope submitted to Rubric therefore also carries
 * `leafCount`, and verification checks the proof length against it.
 */

const LEAF_PREFIX = Buffer.from([0x00]);
const NODE_PREFIX = Buffer.from([0x01]);

export const MERKLE_PARAMS = {
  hash: 'sha256',
  leafPrefix: '0x00',
  nodePrefix: '0x01',
  oddNode: 'promote',
} as const;

function hexToBuf(hex: string): Buffer {
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error(`expected a 32-byte lowercase hex digest, got: ${JSON.stringify(hex)}`);
  }
  return Buffer.from(hex, 'hex');
}

/** sha256(0x00 || leafHash) — the tree-level encoding of a call record's leaf hash. */
export function hashLeaf(leafHash: string): string {
  return createHash('sha256').update(LEAF_PREFIX).update(hexToBuf(leafHash)).digest('hex');
}

/** sha256(0x01 || left || right) — an internal node. */
export function hashNode(left: string, right: string): string {
  return createHash('sha256')
    .update(NODE_PREFIX)
    .update(hexToBuf(left))
    .update(hexToBuf(right))
    .digest('hex');
}

export type MerkleTree = {
  root: string;
  leafCount: number;
  /** levels[0] is the encoded leaf layer; the last level holds the single root. */
  levels: string[][];
};

/** Build the tree over already-computed leaf hashes, in batch order. */
export function buildMerkleTree(leafHashes: string[]): MerkleTree {
  if (leafHashes.length === 0) {
    throw new Error('cannot build a Merkle tree over zero leaves');
  }

  const levels: string[][] = [leafHashes.map(hashLeaf)];

  while (levels[levels.length - 1]!.length > 1) {
    const cur = levels[levels.length - 1]!;
    const next: string[] = [];
    for (let i = 0; i < cur.length; i += 2) {
      const left = cur[i]!;
      const right = cur[i + 1];
      // Promotion: an unpaired node moves up untouched. See the note above.
      next.push(right === undefined ? left : hashNode(left, right));
    }
    levels.push(next);
  }

  return { root: levels[levels.length - 1]![0]!, leafCount: leafHashes.length, levels };
}

/** Ordered sibling path from leaf `index` up to the root. */
export function buildProof(tree: MerkleTree, index: number): ProofStep[] {
  if (!Number.isInteger(index) || index < 0 || index >= tree.leafCount) {
    throw new Error(`leaf index ${index} out of range for a ${tree.leafCount}-leaf tree`);
  }

  const proof: ProofStep[] = [];
  let i = index;

  for (let level = 0; level < tree.levels.length - 1; level++) {
    const nodes = tree.levels[level]!;
    const siblingIndex = i ^ 1;
    const sibling = nodes[siblingIndex];
    if (sibling !== undefined) {
      // `side` names where the SIBLING sits, which is what the verifier needs to
      // know to reassemble the parent in the right order.
      proof.push({ hash: sibling, side: i % 2 === 0 ? 'right' : 'left' });
    }
    // A promoted node keeps its position semantics: parent index is floor(i / 2)
    // whether it was paired or promoted.
    i = i >> 1;
  }

  return proof;
}

/** Replay a proof from a leaf hash to a root. Pure function — the whole verifier. */
export function computeRootFromProof(leafHash: string, proof: ProofStep[]): string {
  let h = hashLeaf(leafHash);
  for (const step of proof) {
    h = step.side === 'left' ? hashNode(step.hash, h) : hashNode(h, step.hash);
  }
  return h;
}

/** Constant-time-ish equality on hex digests. Roots are public, but habits matter. */
export function verifyProof(leafHash: string, proof: ProofStep[], root: string): boolean {
  try {
    return computeRootFromProof(leafHash, proof) === root;
  } catch {
    return false;
  }
}

/** Upper bound on proof length for a given leaf count. Guards against padded proofs. */
export function maxProofLength(leafCount: number): number {
  return leafCount <= 1 ? 0 : Math.ceil(Math.log2(leafCount));
}
