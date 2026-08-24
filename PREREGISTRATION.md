# Preregistration — Model Substitution in x402 LLM Routers

**Version** 1.0
**Status** Fixed prior to data collection
**Registrant** Rubric Protocol
**Instrument** `@tempus1/x402-attest` v0.1.1

This document fixes the hypotheses, methods, exclusion rules and analysis plan
before any study data is collected. It is anchored to Hedera Consensus Service via
Rubric so that its content and timestamp are independently verifiable. Any change
after anchoring is recorded as a numbered amendment and anchored separately; the
original is never edited.

The study asks whether routers' claims about themselves can be checked. A study
making that argument has an obligation to be checkable itself, which is the reason
for anchoring rather than merely publishing.

---

## 1. Question

When a buyer asks an LLM router for a **specific named model**, how often does a
different model serve the request?

This is descriptive. No directional hypothesis is registered — we do not predict a
rate, and a rate of zero is a result, not a failure.

## 2. What counts

Three categories, reported separately and never pooled.

| Category | Example | In headline? |
|---|---|---|
| **Alias resolution** | `gpt-4o` → `gpt-4o-2026-05-13` | No |
| **Disclosed routing** | `auto` / `eco` profile chooses | No — reported as its own line |
| **Silent substitution** | named `openai/gpt-5.5`, served something else | **Yes** |

Alias resolution is decided by the `model_matches_request` rule already shipped in
`@tempus1/x402-attest` v0.1.1: case-insensitive equality, or either string being a
prefix of the other followed by `-`. This rule is fixed by this registration and
will not be adjusted after seeing data.

## 3. Stated limitation

**This study measures disclosed substitution only.** The receipt records what the
router *claimed* to serve. A router that substitutes and misreports the `model`
field is indistinguishable from one that does not.

No result from this study may be framed as detecting dishonest routing. One partial
independent signal is collected (§5) and is reported as its own metric, never as
proof of substitution.

## 4. Design

**Arms.** Every x402-payable router reachable without an account, plus a
**direct-to-provider control arm** using provider APIs. The control establishes
ground-truth token counts and latency per model; without it §5 is uninterpretable.

**Conditions,** per router per hour:

1. **Named specific model** — one call for each of the 5 study models (primary)
2. **Named alias** — one call, measures alias resolution
3. **Auto profile** — one call, measures disclosed routing

= 7 calls per router per hour.

**Schedule.** Hourly, 24×7, for 7 consecutive days. Order randomised within each
hour. A single burst is explicitly rejected as a design: substitution plausibly
tracks load, time of day and upstream outages, and a burst measures one moment
while reporting a rate.

**Expected volume.** 7 × 24 × 7 = 1,176 calls per router; 840 in the primary
condition. Costs approximately $2–8 per router at observed pricing.

**Registered stopping rule.** The run ends after 168 scheduled hours regardless of
what the data shows. No early stop, no extension.

## 5. The tokenizer probe

Identical input bytes produce different `prompt_tokens` under different tokenizers.
The 12-call pilot (2026-08-24) confirmed the signal is usable: three distinct counts
across four models, with **zero within-model variance** across repetitions.

| model | prompt_tokens (3 reps) |
|---|---|
| `openai/gpt-5.5` | 19, 19, 19 |
| `openai/gpt-4o-mini` | 20, 20, 20 |
| `anthropic/claude-haiku-4.5` | 20, 20, 20 |
| `google/gemini-2.5-flash` | 13, 13, 13 |

The pilot also exposed the defect this registration corrects: two of the four models
collide at 20 tokens, so the pilot's probe cannot separate them.

**Calibration step, registered in advance.** Before the main run, candidate probe
strings are evaluated against the control arm. The selected string is the one
maximising the number of pairwise-distinct `prompt_tokens` across the 5 study
models. Selection criteria, in order:

1. All 5 models pairwise distinct. If unachievable, minimise collisions and
   **document every remaining collision explicitly**.
2. Within-model variance of zero across 5 repetitions.
3. Shortest string satisfying 1 and 2.

The chosen string, the candidates tested, and the resulting counts are published as
**Amendment 1** and anchored **before the first study call**. Calibration data is
not study data and is reported separately.

**Interpretation.** A `prompt_tokens` deviation from the control baseline means one
of three things, all reportable, none individually conclusive:
- a different model served the request
- the router injected content into the request
- usage is reported from a different accounting path

The middle possibility is a finding in its own right and must be reported, not
absorbed into the substitution number.

## 6. Fixed parameters

- `temperature: 0`
- `max_tokens: 64` — the pilot showed 16 returns empty content on reasoning models
- Identical request bytes across every router, so token counts are comparable
- 5 study models, fixed at Amendment 1, unchanged thereafter

## 7. Recorded per call

Requested model; served model from the response body **and** from every `x-*`
routing header; `prompt_tokens`; `completion_tokens`; latency; quoted price from the
402 challenge; charged price; settlement transaction; and the attestation id, leaf
hash and inclusion proof.

Every call is attested through `@tempus1/x402-attest` in batch mode with hourly
anchoring, so each data point carries a receipt verifiable without trusting the
study authors.

## 8. Analysis plan

**Primary.** Silent substitution rate per router, primary condition, with 95%
**Wilson score intervals** — counts will be small and near zero, where the normal
approximation misbehaves.

**Secondary.** Tokenizer deviation rate per router versus the control arm.

**Tertiary — added after the pilot.** Quoted price versus token usage. The pilot
observed a flat 2000 atomic ($0.002) quote across all four models despite published
per-model rates, indicating a price floor. Reported per router as quoted price
against realised usage.

**Reasoning-model cost variance — added after the pilot.** `openai/gpt-5.5` returned
completion_tokens of 21, 6 and 19 at `temperature: 0` for a one-word prompt while
the other three models were exactly stable. Completion-token variance is therefore
reported per model, separately, and is **not** treated as a substitution signal.

**Registered reporting rules.**
- `unknown` is its own category. A router that discloses no served model is a
  finding; collapsing it into "no substitution" would flatter exactly the behaviour
  under study.
- Per-model rates are reported with intervals even where wide.
- Raw data, all receipts, and the analysis code are published together. A reader
  must be able to recompute the headline number from the receipts alone.

## 9. Publication commitments

Registered now, because both are harder to honour later:

1. **A null result is published with equal prominence.** If routers substitute
   rarely or never, that is a real contribution — nobody currently knows either way
   — and it is published in full.
2. **Responsible disclosure.** Each router receives its own results before
   publication with a 10 working-day response window. Replies are published
   alongside the data, unedited.

## 10. Threats to validity

Carried into the write-up as a section, not a footnote:

- Detects disclosed substitution only (§3)
- A router injecting content confounds the tokenizer probe and is itself a finding
- Provider-side A/B tests can move behaviour independently of the router
- Per-model cells are small; intervals will be wide even where the pooled rate is not
- A steady hourly probe from one wallet is identifiable. If a router treats it
  differently once noticed, the study measures that rather than normal traffic.
  Wallet rotation, and whether it was used, is disclosed in the write-up.
- The authors build and sell attestation tooling. This conflict is disclosed on the
  study's first page, and is the reason the preregistration is anchored and the raw
  receipts published.

## 11. Amendments

Numbered, dated, anchored separately, appended to this document. The original text
is never edited. Amendment 1 (the calibration result and final model list) is
expected before the first study call.

---

**Anchoring.** The SHA-256 of this file, in the exact bytes published, is submitted
to Rubric; the attestation id and Hedera sequence number are added below once
confirmed, and the file is not modified before that submission.

```
sha256(PREREGISTRATION.md) = <computed at anchoring>
attestationId              = <returned at anchoring>
hcs sequence               = <returned at anchoring>
```
