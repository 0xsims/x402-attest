#!/usr/bin/env node
import { runCli } from '../dist/cli.js';

// The exit code is the product here, so set it explicitly rather than relying on
// an unhandled rejection to produce a nonzero status.
runCli(process.argv.slice(2))
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`x402-attest: ${err?.stack ?? err}\n`);
    process.exitCode = 4;
  });
