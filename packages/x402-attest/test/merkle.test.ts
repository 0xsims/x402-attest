import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import {
  buildMerkleTree,
  buildProof,
  computeRootFromProof,
  hashLeaf,
  hashNode,
  maxProofLength,
  verifyProof,
} from '../src/merkle.js';
import { sha256 } from '../src/hash.js';

const leaf = (i: number): string => sha256(`leaf-${i}`);
const leaves = (n: number): string[] => Array.from({ length: n }, (_, i) => leaf(i));

describe('Merkle tree', () => {
  it('domain-separates leaves from internal nodes', () => {
    const h = leaf(0);
    const raw = createHash('sha256').update(Buffer.from(h, 'hex')).digest('hex');

    // The 0x00 / 0x01 prefixes make the leaf and node hash domains disjoint. That
    // is what blocks the second-preimage attack in which a 64-byte "leaf" is
    // presented as an internal node.
    expect(hashLeaf(h)).not.toBe(raw);
    expect(hashLeaf(h)).not.toBe(hashNode(h, h));

    expect(hashLeaf(h)).toBe(
      createHash('sha256')
        .update(Buffer.from([0x00]))
        .update(Buffer.from(h, 'hex'))
        .digest('hex'),
    );
    expect(hashNode(h, h)).toBe(
      createHash('sha256')
        .update(Buffer.from([0x01]))
        .update(Buffer.from(h, 'hex'))
        .update(Buffer.from(h, 'hex'))
        .digest('hex'),
    );
  });

  it.each([1, 2, 3, 7, 8, 256])(
    'round-trips an inclusion proof at every index for a %i-leaf batch',
    (n) => {
      const hashes = leaves(n);
      const tree = buildMerkleTree(hashes);
      expect(tree.leafCount).toBe(n);

      for (let i = 0; i < n; i++) {
        const proof = buildProof(tree, i);
        expect(verifyProof(hashes[i]!, proof, tree.root)).toBe(true);
        expect(computeRootFromProof(hashes[i]!, proof)).toBe(tree.root);
        expect(proof.length).toBeLessThanOrEqual(maxProofLength(n));
      }
    },
  );

  it('rejects a proof presented against the wrong leaf', () => {
    const hashes = leaves(8);
    const tree = buildMerkleTree(hashes);
    const proof = buildProof(tree, 3);
    expect(verifyProof(hashes[3]!, proof, tree.root)).toBe(true);
    expect(verifyProof(hashes[4]!, proof, tree.root)).toBe(false);
  });

  it('rejects a proof with a flipped sibling side', () => {
    const hashes = leaves(4);
    const tree = buildMerkleTree(hashes);
    const proof = buildProof(tree, 1).map((s) => ({
      ...s,
      side: s.side === 'left' ? ('right' as const) : ('left' as const),
    }));
    expect(verifyProof(hashes[1]!, proof, tree.root)).toBe(false);
  });

  it('rejects a proof with a mutated sibling hash', () => {
    const hashes = leaves(8);
    const tree = buildMerkleTree(hashes);
    const tampered = buildProof(tree, 5).map((s, i) =>
      i === 0 ? { ...s, hash: leaf(999) } : s,
    );
    expect(verifyProof(hashes[5]!, tampered, tree.root)).toBe(false);
  });

  it('gives a single-leaf batch an empty proof rooted at the encoded leaf', () => {
    const tree = buildMerkleTree([leaf(0)]);
    expect(tree.root).toBe(hashLeaf(leaf(0)));
    expect(buildProof(tree, 0)).toEqual([]);
    expect(verifyProof(leaf(0), [], tree.root)).toBe(true);
  });

  describe('odd-node promotion', () => {
    it('promotes the unpaired node unchanged rather than duplicating it', () => {
      const hashes = leaves(3);
      const tree = buildMerkleTree(hashes);

      // Level 0 is [L0, L1, L2]. L0+L1 pair; L2 moves up verbatim.
      expect(tree.levels[0]).toHaveLength(3);
      expect(tree.levels[1]).toHaveLength(2);
      expect(tree.levels[1]![1]).toBe(hashLeaf(hashes[2]!));
      expect(tree.levels[1]![1]).not.toBe(
        hashNode(hashLeaf(hashes[2]!), hashLeaf(hashes[2]!)),
      );
      expect(tree.root).toBe(hashNode(tree.levels[1]![0]!, tree.levels[1]![1]!));
    });

    it('gives the promoted leaf a shorter proof than its paired siblings', () => {
      const tree = buildMerkleTree(leaves(3));
      expect(buildProof(tree, 0)).toHaveLength(2);
      expect(buildProof(tree, 1)).toHaveLength(2);
      // Index 2 skips a level: it had no sibling to record there.
      expect(buildProof(tree, 2)).toHaveLength(1);
    });

    it('does not collide [A,B,C] with [A,B,C,C] — the duplication attack', () => {
      // Under the Bitcoin duplicate-the-last-node rule these produce the SAME
      // root (CVE-2012-2459), which would let someone claim a leaf was in a batch
      // that never held it. Promotion keeps them distinct.
      const three = buildMerkleTree([leaf(0), leaf(1), leaf(2)]);
      const fourWithDup = buildMerkleTree([leaf(0), leaf(1), leaf(2), leaf(2)]);
      expect(three.root).not.toBe(fourWithDup.root);
    });

    it('keeps roots distinct across every small leaf count', () => {
      const roots = new Set<string>();
      for (let n = 1; n <= 40; n++) roots.add(buildMerkleTree(leaves(n)).root);
      expect(roots.size).toBe(40);
    });

    it('promotes correctly across several consecutive odd levels', () => {
      // 7 leaves: 7 -> 4 -> 2 -> 1, with a promotion at the 7 and the 3 layers.
      const hashes = leaves(7);
      const tree = buildMerkleTree(hashes);
      expect(tree.levels.map((l) => l.length)).toEqual([7, 4, 2, 1]);
      expect(tree.levels[1]![3]).toBe(hashLeaf(hashes[6]!));
      for (let i = 0; i < 7; i++) {
        expect(verifyProof(hashes[i]!, buildProof(tree, i), tree.root)).toBe(true);
      }
    });
  });

  it('refuses to build over zero leaves', () => {
    expect(() => buildMerkleTree([])).toThrow(/zero leaves/);
  });

  it('refuses out-of-range leaf indices', () => {
    const tree = buildMerkleTree(leaves(4));
    expect(() => buildProof(tree, 4)).toThrow(/out of range/);
    expect(() => buildProof(tree, -1)).toThrow(/out of range/);
    expect(() => buildProof(tree, 1.5)).toThrow(/out of range/);
  });

  it('refuses malformed digests rather than silently hashing garbage', () => {
    expect(() => hashLeaf('not-a-digest')).toThrow(/lowercase hex/);
    expect(() => hashLeaf('ABC'.repeat(21) + 'A')).toThrow();
    expect(verifyProof('nope', [], 'x')).toBe(false);
  });
});
