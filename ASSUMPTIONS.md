# Assumptions

Things the spec and the live documentation left open, and what this implementation
decided. Each one is a place a reader could reasonably have expected something
else, so each says what would change if the assumption is wrong.

---

## Money

**Amounts with no decimal point are atomic units; amounts with one are already
USD.** x402 quotes `maxAmountRequired` in the asset's smallest unit, but some
facilitators echo the seller's configured `price` string, which is decimal. Atomic
amounts are integers by construction, so the presence of a `.` disambiguates.

**Unknown assets have 6 decimals.** USDC-shaped, since USDC on Base is the
overwhelmingly common x402 asset. Override per asset with
`assetDecimals: { '0x833589fc...': 6 }` or globally with `defaultAssetDecimals`.
Getting this wrong by a factor of 10^n is the difference between a call passing and
failing `price_within_policy`, so the value used is always visible in the
assertion's `observed` field.

**Stablecoin units are treated as USD 1:1.** `policy.maxPricePerCall` and
`budgetCap` are documented as USD strings; no FX conversion is attempted. A
non-USD-pegged asset would make those two assertions meaningless, so they are best
left unset in that case, which yields `unknown` rather than a wrong `pass`.

**All money arithmetic is exact.** BigInt over a fixed scale, never floating point:
`0.1 + 0.2 > 0.3` would otherwise be a recorded policy violation.

## Assertions

**A model alias resolving to a pinned build counts as a match.** `gpt-4o` served as
`gpt-4o-2026-05-13` is a `pass`; prefix matching in either direction. A router
substituting a different family (`claude-sonnet-4.6` → `gemini-2.5-flash`) is a
`fail`. If you need exact-string routing, treat `pass` with differing
`observed`/`expected` digests as suspicious.

**A routing header outranks the response body when reading the served model.** The
router is the party being audited and controls both, but the header is its explicit
declaration. Checked in order: `x-clawrouter-model`,
`x-clawrouter-served-model`, `x-clawrouter-upstream-model`, `x-served-model`,
`x-model`, then `body.model`. The source used is recorded in the assertion's
`detail`.

**A policy violation outranks every other outcome.** The spec says any `fail` sets
`outcome: 'policy_violation'`, so a call that both violated policy and returned 500
records `policy_violation`. The HTTP status is still in `response.status`, so
nothing is lost.

**Settlement claimed without a transaction hash is `unknown`, not `pass`.** A
facilitator asserting `success: true` with nothing to point at has not demonstrated
settlement.

**`budget_within_cap` reports `unknown` when the current call cannot be priced**,
even if the cumulative total is under the cap, and says so in `detail`. The figure
shown is a lower bound.

## Observation

**Without a tap, the 402 handshake is invisible.** `withAttestation` wraps a client
that resolves 402 → pay → retry internally, so from outside only the final 200 is
visible. Without `createTap()` installed beneath that client,
`price_matches_challenge`, `payto_matches_challenge` and the payment record are
`unknown`. This is a real limitation, it is not hidden, and it produces honest
`unknown`s rather than optimistic passes.

**Request bodies that are streams are recorded as `unhashable:stream`.** Consuming
the stream to hash it would break the caller's request. Recording the empty-string
digest instead would be an affirmative false claim about what was sent.

**One process per `walPath`.** The WAL is append-only and crash-safe, but it is not
multi-writer. Two processes sharing a directory would interleave lines and
double-anchor. Give each agent process its own directory.

**Session spend is rebuilt from leaves whose `sessionId` matches.** Set `sessionId`
if you want `budgetCap` to survive a restart; without it, spend restarts at zero
after a crash.

## Format

**`side` in a proof step names where the sibling sits**, not where the node being
proved sits. `{ hash, side: 'left' }` means `parent = H(0x01 || sibling || node)`.

**The batch envelope field is named `root`.** The spec says "the root" without
naming the field.

**Timestamps are ISO 8601 with millisecond precision, from `Date.now()`.** They are
descriptive, not a trusted time source — the ledger anchor is what establishes
"no later than". A clock skewed by an hour produces a receipt that is still fully
verifiable and whose `startedAt` is an hour off.

**`callId` ordering is monotonic within a process, not globally.** UUIDv7 with a
sub-millisecond counter; if the clock steps backwards the counter keeps ordering
stable, and `startedAt` carries the real wall clock.

## Environment

**Node >= 20.11, ESM only.** Uses `node:crypto`, `node:fs`, `AsyncLocalStorage`,
`TransformStream` and global `fetch`. No browser build: the WAL requires a
filesystem, and a browser-side attestor could not make the durability claim.

**The keyless path needs `anchorFetch`, and it must be the raw x402 client.**
Passing the attested wrapper would make anchoring attest itself recursively. There
is no way to detect this automatically, so it is documented at the option, in the
README, and in the example.

**Verification with no `verifyUrl` and no override is a fetch failure (exit 4).**
Not a validity failure — the receipt may be perfectly good.

**A receipt file may hold one receipt, a JSON array, or JSONL.** All three occur in
practice. With several, the CLI exits with the worst result.
