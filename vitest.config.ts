import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['packages/*/test/**/*.test.ts'],
    // The crash-recovery and latency suites spawn child processes / run loops.
    testTimeout: 30_000,
    hookTimeout: 30_000,
    // Attestation state is process-global (signal handlers, WAL dirs), so each
    // file gets its own worker.
    pool: 'forks',
    // Files run one at a time. The latency suite measures wall-clock overhead in
    // microseconds; running it alongside ten other suites that spawn HTTP servers,
    // fork child processes and fsync in a loop measures scheduler contention
    // rather than this library. The whole suite takes a few seconds either way.
    fileParallelism: false,
    coverage: {
      provider: 'v8',
      include: ['packages/x402-attest/src/**/*.ts'],
      exclude: ['packages/x402-attest/src/**/*.d.ts'],
      reporter: ['text', 'json-summary', 'html'],
      thresholds: {
        lines: 85,
        statements: 85,
        functions: 85,
        branches: 80,
      },
    },
  },
});
