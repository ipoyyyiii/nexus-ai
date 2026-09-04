# Nexus Persistent Context Memory

> Canonical context for continuing Nexus work. Read this file before planning,
> reviewing, upgrading, or testing the project. This file contains no secrets.

**Last verified:** 2026-09-03  
**Project:** Nexus AI  
**Scope:** AI-native autonomous web/API penetration testing for authorized targets

## Product vision

Nexus is intended to become an AI-native web/API pentesting agent. The AI should
reason over observations, form hypotheses, choose useful tools, adapt when
results change or tools fail, pursue attack chains, and produce reproducible
evidence and reports. The goal is meaningful autonomous pentesting capability,
not merely a tool runner, smoke-test wrapper, or hardcoded checklist.

The target scope is web, REST/API, browser workflows, authentication and
sessions, access control, injection, SSRF/OOB, business logic, evidence, and
reporting. Mobile, AD, cloud compromise, malware, C2, phishing, and full
enterprise red-team operations are outside the current product scope.

## Canonical phase plan

These are the official phases. Do not rename them, reorder them, or turn their
sub-phases into top-level phases without an explicit decision from the owner.

### Phase 0 — Create and freeze the scorecard baseline

Freeze the baseline, evaluation rules, scorecard, upgrade ledger, and handoff
context before architecture changes. Phase 0 is complete. It is governance and
measurement work; it does not increase the capability rating.

### Phase 1 — Change the architecture to AI-native

This is the major architecture phase. It contains five sub-phases:

1. **Execution Foundation** — transport/scope, dynamic execution, tool failure
   semantics, recovery, and durable execution state.
2. **AI-Native Agent Loop** — AI reasoning, hypothesis generation, tool
   selection, adaptation, and retest decisions become part of the live loop.
3. **Full Pentest Coverage** — recon, auth, vulnerability analysis,
   exploitation/impact, OOB, and evidence work as one coordinated workflow.
4. **Finding & Evidence Engine** — candidates and validated findings are based
   on reproducible request/response and impact evidence.
5. **Live Evaluation** — the architecture is tested against a controlled lab
   using an objective scorecard.

Current position: **Phase 1 → Execution Foundation**. Phase 1 is not complete
until its implementation and live acceptance criteria are both proven.

### Phase 2 — Test recon

Evaluate recon breadth, surface discovery, technology and contract mapping,
identity/workflow intelligence, recon-to-hypothesis usefulness, coverage, and
failure recovery. A recon run is not a full pentest and does not prove
vulnerability recall by itself.

### Phase 3 — Test vulnerability analysis

Evaluate hypothesis quality, vulnerability test selection, detection depth,
candidate quality, validation precision/recall, false positives, and the
ability to use recon observations creatively and adaptively.

### Phase 4 — Test exploitation/impact

Evaluate authorized exploit execution, multi-step chains, authentication and
authorization differentials, business logic, OOB correlation, impact proof,
retest, and cleanup. Destructive actions require an explicitly authorized lab
scope and must remain auditable.

### Phase 5 — Test final report

Evaluate evidence-grounded findings, severity/context accuracy, reproduction
steps, limitations, deduplication, export formats, report consistency, and
senior-pentester review quality.

### Phase 6 — Compare with the frozen baseline

Compare each phase against the immutable Phase 0 baseline using actual test
artifacts. Code volume, job completion, tool count, candidate count, or a
successful smoke test is not enough to raise the score.

## Evaluation decisions that are currently locked

- The primary autonomous capability test is **crAPI**, because it exercises API
  auth, ownership, access control, workflows, and multi-step behavior.
- **OWASP Benchmark** is the calibration test for structured precision/recall
  and vulnerability detection metrics; it is not a substitute for the broader
  autonomous pentest evaluation.
- Gold labels and expected outcomes stay hidden from the Nexus runtime and are
  used only by the evaluator.
- Shadow/strict terminology must not be used to redefine the phase structure.
  Runtime modes are implementation details, not top-level phases.
- A capability score changes only after the relevant phase exit criteria and
  live evidence pass. An implementation change alone does not raise the score.
- Partial, inconclusive, skipped, failed, and unproven results must remain
  visible. Do not convert them into success merely because the job reached
  `done`.
- Every meaningful upgrade must update `PROJECT_HANDOFF.md`,
  `NEXUS_UPGRADE_LEDGER.md`, and `NEXUS_SCORECARD.yaml` after testing.
- Every run/testing session, upgrade, bug, discovered gap, fix, decision, and
  verification must also receive an append-only entry in
  `NEXUS_EVENT_LOG.md`. Include the phase/sub-phase, environment, command or
  endpoint, result, evidence, rating impact, and remaining work.

## Current known status

- Phase 0: **complete**.
- Phase 1 / Execution Foundation: **implemented in part, live acceptance not
  fully passed**.
- Local authorized targets can be admitted with an explicit scope rule carrying
  `allow_private: true`; this is not permission to bypass scope checks.
- The old fixed action ceiling was replaced by dynamic/config-driven execution.
- The remaining foundation proof must demonstrate that real tool failures are
  durably represented as `failed` or `partial`, with actionable diagnostics,
  rather than disappearing, becoming an unexplained skip, or producing a false
  success.
- Previous crAPI runs with zero candidates/validated findings did **not** prove
  that crAPI was clean; execution-integrity and tool-contract failures prevented
  a valid capability conclusion.
- No rating increase is justified until the relevant live gate proves it.

## Live acceptance checkpoint — 2026-09-02

Phase 1 → Execution Foundation live acceptance was rerun against the local
OWASP Benchmark bridge with `dolphin3-cyber` online, `full` preset, autopilot,
and an explicit session scope rule carrying `allow_private: true`.

The first launch path (`POST /pentest` without a setup session) failed with
`Session scope context not found`; this was a correct fail-closed scope result.
The official session-setup path then passed the private-lab transport gate and
completed its workflow, but the acceptance gate failed closed because
`browser_find_open_redirect` produced a retryable `tool_timeout`.

Durable evidence from the valid run:

- 16 tool runs: 15 succeeded and 1 failed; no private-IP rejection.
- 5 reasoning cycles: 1 succeeded and 4 provider/protocol failures.
- 5 model calls: 1 succeeded and 4 failed (`JSONDecodeError` once,
  `_GatewayProtocolError` three times).
- 3 reasoning actions and 3 model traces; 2 valid traces, 1 invalid trace;
  one AI-expected action still lacked a dispatch outcome.
- 14 candidates: 1 validated and 13 inconclusive. The validated candidate had
  a durable validated V2 row with linked evidence, but the job-level gate did
  not pass.
- No ready report or export was produced because execution-integrity failed
  before final reporting.

Decision: **Execution Foundation live acceptance failed; rating unchanged.**
The next required fixes are reliable browser timeout recovery/closure,
provider response reliability under the real Dolphin model, and elimination of
AI-expected actions without dispatch outcomes. Do not relabel this target as
clean or treat the single validated candidate as a Phase 1 pass.

## Resume protocol

When work resumes:

1. Read this file first.
2. Read the latest matching entries in `PROJECT_HANDOFF.md`,
   `NEXUS_UPGRADE_LEDGER.md`, `NEXUS_SCORECARD.yaml`, and
   `NEXUS_EVENT_LOG.md`.
3. Identify the exact current phase and sub-phase before proposing work.
4. Do not silently import historical “Phase 1/2/3” labels that conflict with
   this canonical plan.
5. Report what is proven, unproven, blocked, and changed separately.

## Live acceptance after 1C–1F hardening — 2026-09-02

Implemented and verified in the Docker runtime:

- `tools/playwright_tools.py`: open-redirect probing has a cooperative inner
  budget, asynchronous rate-limit wait, and structured `partial` output on
  navigation/budget timeout.
- `api.py`: a retryable failure is reconciled only by a later successful run
  for the same tool and target; recovery is exposed in the summary.
- `core/autonomous_web_pentest.py`: missing AI dispatch callbacks become an
  explicit failed `dispatch_outcome_missing` record instead of disappearing.

Regression passed **113 tests**. API/worker were rebuilt/recreated;
`/health/ready` and the local Benchmark bridge returned HTTP 200.

Fresh full/autopilot live run: session
`757b4e8b-3914-4b36-b079-60d83c731ebd`, job
`10394abf-8111-41da-9f2c-3a66f2c28f93`, terminal `done` after 925.36 seconds.
The session contained 64 non-narrative structured runs: 47 succeeded, 1
partial (`browser_find_open_redirect`), 0 failed, and 16 skipped; no
`private_ip_rejected`. Six candidates were persisted, five V2-validated with
linked evidence, and Markdown/PDF/DOCX exports all returned HTTP 200.

The AI provider was not actually reachable: the configured Dolphin ngrok URL
returned HTML HTTP 404 for `/health`, `/v1/models`, and
`/v1/chat/completions`. Two reasoning cycles/model calls failed with
`NotFoundError`; zero AI actions/traces were produced and deterministic
fallback ran the scan. Therefore 1C/1E hardening is proven, but 1F and the
overall Execution Foundation remain failed; rating unchanged. Reconnect the
provider, pass health/models/completion preflight, and rerun the same gate.

## Latest live acceptance — 2026-09-02

The fresh run used the corrected live-provider preflight and then full/autopilot
against the authorized local OWASP Benchmark bridge. Provider `/health`,
`/v1/models`, and `/v1/chat/completions` all returned HTTP 200; API readiness,
worker health, and target availability also passed.

The authoritative run was session
`f05255e6-d7a3-45de-8e6f-6faddb28d2f2`, job
`c1a01b11-09b4-4581-8eeb-d2ba3a1c8b6f`. It failed closed on a durable
retryable timeout from `browser_find_open_redirect`. The run recorded 69
tool-runs (46 succeeded, 4 partial, 1 failed, 18 skipped), no private-IP
rejection, 5 reasoning cycles, 5 model calls (all `_GatewayProtocolError`),
and zero successful AI hypotheses/actions/model traces. It persisted 12
candidates: 5 validated and 7 inconclusive. A workflow report was durable
with 5 finding IDs, 10 grounded claims, and zero redaction leaks, but job-level
exports returned 409 because the job status was `error`.

Decision: **Execution Foundation 1F failed; rating unchanged.** A passing
simple provider smoke call is not enough: full Nexus reasoning output still
violates the gateway JSON contract. The next blockers are full-prompt provider
protocol compatibility and browser timeout recovery. Do not call the target
clean or call this an AI-native acceptance pass.

## Latest corrected-provider live acceptance — 2026-09-02

The canonical 1F gate was rerun against the authorized local OWASP Benchmark
bridge after the operator updated the Dolphin3-Cyber provider URL and recreated
the API/worker containers. API readiness, worker health, target HTTP 200, and
provider preflight/post-run completion HTTP 200 were verified.

Session 247d5603-95b2-46bf-b4cf-c560372cc55c and job
13d7e512-7282-4820-936a-2c4b232c7b0a completed durably in 1625.30 seconds.
The run recorded 70 endpoint rows (68 structured tool runs plus phase
markers): 47 succeeded, 5 partial, 0 failed, and 18 skipped. There were no
private-IP rejections, missing AI dispatch outcomes, or validation persistence
errors.

Six reasoning cycles and six model calls succeeded durably. The execution
trace contains 13 actions and 4 blocked actions; three model-action traces
were persisted. Twelve candidates were created: five validated with linked
evidence and seven inconclusive. The structured report was ready with five
finding IDs, ten grounded claims, quality score 1.0, and zero redaction leaks.
Job Markdown report/export returned HTTP 200. Three repeated report reads left
ten durable claim rows, so report idempotency passed this run. Full regression
after the run was 363 passed with nine warnings.

Decision: **partial live acceptance; 1F not passed; rating unchanged.** 1A,
1B, 1D, 1E, and report durability are evidenced. 1C is mostly evidenced by
typed partial/skip outcomes, but five browser partials had no successful
same-target retry, and one mixed-content skip had an empty error list. The
legacy/CrewAI assessor also logged two ngrok gateway errors, although the
structured report completed. Hidden-label recall/precision and later-phase
auth, business logic, retest, and impact proof remain unmeasured. Do not
interpret the validated header/server-disclosure records as Benchmark recall
or as proof that the target is clean.

## Latest implementation checkpoint — 2026-09-02

The planned Execution Foundation 1C–1F hardening is implemented and verified
without the AI provider running. The source now has typed tool failure/partial/
skip semantics, adaptive browser redirect handling, durable read-only retry
recovery links, canonical ReasoningGateway assessment, a fail-closed 1F
evaluator, and `auto` preservation of valid model hypotheses/actions within
explicit resource envelopes.

Verification is reproducible in Docker: **60 focused tests passed**, **377 full
regression tests passed with 10 warnings**, API/worker images built, and the
recreated API returned `/health/live` 200 and `/health/ready` 200 with
autonomous mode and all schema checks healthy.

This does not pass 1F by itself. Live provider preflight, full authorized target
execution, durable AI participation, retry recovery, report/export, and the
machine acceptance gate are still required before rating changes. When work
resumes, start the local Dolphin3-Cyber provider and run the planned live 1F
acceptance; do not count this implementation checkpoint as a live capability
score.

## Latest live acceptance result — 2026-09-02

The local Dolphin3-Cyber provider was active through Google Colab/ngrok and the
corrected authorized run was executed against OWASP Benchmark. Session:
`234e2969-265b-4f02-a238-7bd1084e39b8`; job:
`c356fb34-722b-4bae-b6df-5dcb88fd7644`. The corrected scope used
`allow_private: true`, so it had zero private-IP rejections.

Live facts: 66 authoritative tool rows (47 succeeded, 1 partial, 2 failed,
18 skipped), 3 reasoning cycles, 3 model calls, 2 model action traces, and 11
trace actions. There were 9 candidates: 5 validated and 4 inconclusive; all 5
validated records had durable evidence IDs. Validation-trace persistence errors
were zero. The report endpoint returned HTTP 200 with quality `ready`, score
`1.0`, 9 grounded claims, and zero redaction leaks; export returned HTTP 409
because the job ended in error.

The machine 1F evaluator returned **FAIL**, not pass. Blockers: two
`legacy_tool_failed` parameter-discovery proxy failures; one retryable browser
open-redirect partial timeout; three coverage-required skipped tools; one
failed reasoning cycle/model call; and no durable `recovered_from_run_id` from
a recovery fixture. The validated records are observed header/server
disclosure results and do not measure hidden-label recall/precision or prove
the Benchmark target clean. Rating remains unchanged.

## Full code review and Execution Foundation hardening — 2026-09-03

The repository was reviewed as a system, from API/worker entrypoints through
configuration, scope and safety, transport facades, tool registry, recon and
autonomous loop, browser/human recon, reasoning gateway, durable repositories,
validation/evidence, report export, frontend, migrations, and tests. The
inventory at review time contained **247 code files** (**240 Python** and **7
TypeScript/JavaScript-family files**) and **58 test files**. ECC subagent audits
from Carson, Kant, and Volta were used as independent checks of the execution,
transport, browser, AI, and persistence paths.

The important architectural conclusion is that Nexus now has one canonical
AI-first runtime for `full` and `recon-only` presets:

```text
durable session/config snapshot
  -> ReasoningGateway (model proposals + typed telemetry)
  -> admission/scope/approval checks
  -> StructuredToolRunner + guarded transport
  -> typed result/error/skip + durable evidence
  -> recovery/replan feedback
  -> deterministic validation/report
```

The legacy CrewAI path remains only as an explicit compatibility path for a
noncanonical preset or when autonomous execution is disabled. It is no longer
constructed on the canonical `full`/`recon-only` path.

Implemented from the review:

- Guarded HTTP transport disables ambient proxy inheritance and accepts only
  the exact configured operator proxy. Session-level `proxies=None` no longer
  becomes a legacy proxy failure.
- Parameter discovery preserves typed `failed`/`partial` diagnostics instead
  of returning a misleading legacy JSON error observation.
- Recon uses the same typed read-only retry contract as the autonomous loop;
  R2-disabled and circuit-breaker skips are explicit capability/operational
  skips rather than false required-coverage debt.
- Browser open-redirect scheduling derives its deadline from actual case
  workload and reports cooperative timeout/partial evidence with case metrics.
- The reasoning gateway retries a transient provider timeout/connection error
  once by default, with configurable backoff. Invalid JSON/schema output is
  not retried. Retry attempts and fallback-provider attempts are distinguishable
  in telemetry.
- Nested configuration is merged recursively and a deep per-job config
  snapshot is passed into execution, preventing one override from dropping
  sibling defaults.
- The 1F evaluator validates real recovery links, cycle/call lineage, model
  action trace ownership, dispatch outcomes, typed skips, report quality, and
  legacy-provider errors fail-closed.

Verification after the final patch:

- Syntax compilation for `api.py`, `worker.py`, all `core/*.py`, and all
  `tools/*.py`: passed.
- Latest focused Execution Foundation suite: **75 passed**.
- Full repository regression: **387 passed, 9 warnings** in 167.83 seconds.
- `git diff --check`: clean.
- YAML parse check for runtime config and scorecard: passed.
- Static transport check found no raw `requests`/`httpx` import in tool/engine
  source outside the designated boundary modules.

This is an implementation/regression result, not a live 1F pass. The rating is
unchanged until a fresh provider-backed OWASP Benchmark run proves the durable
gate, including recovery. Remaining architectural limitations outside this
sub-phase include the worker's historical API import/process-local compatibility
state and all Phase 2–5 hidden-label, authenticated, business-logic, impact,
and report-quality capability measurements.

## Execution Foundation gap closure and local verification — 2026-09-03

The operator explicitly paused live testing because the local AI provider was
offline. This checkpoint therefore performed code hardening and local-only
verification; no provider inference, target request, or live pentest workflow
was executed.

The follow-up fixes addressed the concrete 1C–1F runtime gaps found by the
full code review and ECC audits:

- worker recovery and heartbeat telemetry now use bounded retries and do not
  terminate the worker when a transient Supabase/RPC telemetry call fails;
- legacy cancellation and raw command failures are normalized into typed
  `cancelled`/`failed` results with retryable diagnostics instead of false
  successful observations;
- `partial` actions now make the mission outcome non-successful;
- candidate promotion requires canonical V2 validation and pending V2 batches
  are session-scoped, preventing cross-run leakage;
- acceptance validation requires an explicit durable same-session evidence
  verification map for validated candidates;
- `/health/ready` is synchronous because the Supabase client is synchronous,
  preventing readiness checks from blocking the Uvicorn event loop;
- browser local-lab access is authorized only for the exact configured origin,
  and browser request/response/byte accounting is installed without blocking
  the Playwright event loop;
- local-lab coverage defaults include the authorized read-only discovery tools
  that were previously reported as required skips.

Verification performed after rebuilding both Docker images:

- focused Execution Foundation and related regression: **83 passed**;
- full repository regression: **398 passed, 9 warnings**;
- Python syntax compilation, runtime/scorecard YAML parsing, and
  `git diff --check`: passed;
- API import boundary: 64.31 seconds in the isolated container, with
  `crewai`, `langchain`, and `core.model_registry` not loaded eagerly;
- recreated runtime: API `/health/live` HTTP 200, `/health/ready` HTTP 200;
  API and worker both healthy; readiness checks reported config, Supabase,
  durable schema, and Phase 1 acceptance schema as `ok`.

Decision: **1C–1E implementation and regression are verified; 1F live
acceptance remains unproven.** The rating is unchanged. A fresh provider-backed
authorized run is still required to prove durable AI participation, real retry
recovery, complete tool outcomes, report/export completion, and the machine 1F
gate. Phase 2–5 capability measurements remain outside this checkpoint.
