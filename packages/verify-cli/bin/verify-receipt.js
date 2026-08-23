#!/usr/bin/env node
import { runCli } from '@rubric-protocol/x402-attest/cli';

runCli(process.argv.slice(2), undefined, undefined, 'verify-receipt')
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`verify-receipt: ${err?.stack ?? err}\n`);
    process.exitCode = 4;
  });
