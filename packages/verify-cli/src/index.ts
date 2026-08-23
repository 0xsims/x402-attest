/**
 * Standalone receipt verifier.
 *
 * A separate package on purpose. The point of a receipt is that a third party can
 * check it without trusting the agent that produced it, without an API key, and
 * without installing the SDK that produced it. Anyone shipping this to an auditor
 * should be able to say "this package only reads; it cannot write, pay, or phone
 * home except to one public GET".
 */
export {
  verifyReceipt,
  VERIFY_EXIT,
  jcs,
  jcsBytes,
  sha256,
  sha256Jcs,
  buildMerkleTree,
  buildProof,
  computeRootFromProof,
  hashLeaf,
  hashNode,
  verifyProof,
  MERKLE_PARAMS,
} from '@rubric-protocol/x402-attest';

export type {
  VerifyResult,
  VerifyOptions,
  Receipt,
  CallRecord,
  Assertion,
  ProofStep,
} from '@rubric-protocol/x402-attest';

export { runCli, parseReceiptFile, parseArgs } from '@rubric-protocol/x402-attest/cli';
