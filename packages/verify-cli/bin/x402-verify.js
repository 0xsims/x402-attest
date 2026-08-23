#!/usr/bin/env node
import { runCli } from '@0xsims/x402-attest/cli';

runCli(process.argv.slice(2), undefined, undefined, 'x402-verify')
  .then((code) => {
    process.exitCode = code;
  })
  .catch((err) => {
    process.stderr.write(`x402-verify: ${err?.stack ?? err}\n`);
    process.exitCode = 4;
  });
