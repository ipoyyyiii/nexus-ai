# Nexus Event Log

Append-only operational memory for Nexus. Add an entry after every meaningful
run, live test, upgrade, bug, gap discovery, fix, decision, or verification.
Do not rewrite history to make a result look better. This file must never
contain API keys, tokens, passwords, cookies, credentials, private raw
responses, or other secrets.

## Entry format

```text
## EVENT-YYYY-MM-DD-NNN — short title

- Date/time:
- Type: run | upgrade | bug | gap | fix | decision | verification
- Phase/sub-phase:
- Objective:
- Environment/target:
- Exact command or endpoint:
- Change or observation:
- Result: proven | passed | failed | partial | inconclusive | blocked | unproven
- Evidence/artifact IDs:
- Impact on rating: increased | decreased | unchanged | not rated
- Remaining work:
```

## EVENT-2026-09-01-001 — Persistent context and event memory created

- Date/time: 2026-09-01
- Type: upgrade
- Phase/sub-phase: Phase 0 governance; Phase 1 planning context
- Objective: Preserve the official roadmap and project context across resumed
  sessions, including every run, upgrade, bug, and known gap.
- Environment/target: Local repository
- Exact command or endpoint: Documentation-only change
- Change or observation: Added `NEXUS_CONTEXT_MEMORY.md` and this append-only
  `NEXUS_EVENT_LOG.md`; linked both from `PROJECT_HANDOFF.md` and recorded the
  maintenance rule in the ledger and scorecard.
- Result: passed
- Evidence/artifact IDs: `NEXUS_CONTEXT_MEMORY.md`, `NEXUS_EVENT_LOG.md`
- Impact on rating: unchanged
- Remaining work: Append a new entry whenever a qualifying project event
  occurs.

## EVENT-2026-09-01-002 — Phase 1 execution-foundation gap map confirmed

- Date/time: 2026-09-01
- Type: gap | decision
- Phase/sub-phase: Phase 1 — AI-native architecture; Execution Foundation
- Objective: Keep the official 1A–1F execution-foundation breakdown aligned
  with the actual acceptance evidence.
- Environment/target: Local Docker Compose runtime and authorized local lab
- Exact command or endpoint: Review of the latest live acceptance artifacts
- Change or observation: 1A transport/scope and 1B dynamic execution are
  proven. 1C failure semantics/recovery remains unproven. 1D durable AI
  observability is partial: durable cycles/calls/traces exist, but provider
  failures, invalid action traces, and adaptation quality remain open. 1E
  validation/evidence is partial: candidate validation integrity is improved,
  but report-claim idempotency and complete evidence closure remain open. 1F
  live acceptance has not passed.
- Result: partial
- Evidence/artifact IDs: `PHASE1-LIVE-AI-ACCEPTANCE-2026-09-01`,
  `NEXUS_CONTEXT_MEMORY.md`
- Impact on rating: unchanged
- Remaining work: Close 1C–1E, then rerun the full Phase 1 live acceptance
  gate and score only from objective evidence.

## EVENT-2026-09-01-003 — Plan to close Phase 1C–1F

- Date/time: 2026-09-01
- Type: decision
- Phase/sub-phase: Phase 1 — AI-native architecture; Execution Foundation
- Objective: Close 1C through 1F and perform live acceptance after the local AI
  provider is brought online.
- Environment/target: Local Docker Compose runtime; authorized crAPI primary
  evaluation target
- Exact command or endpoint: Pending provider activation
- Change or observation: Work will proceed through tool failure semantics,
  durable AI observability and adaptation, validation/evidence integrity, then
  the full live acceptance gate. AI is required for 1D and 1F; 1C and most of
  1E can be verified without it.
- Result: pending
- Evidence/artifact IDs: `NEXUS_CONTEXT_MEMORY.md`
- Impact on rating: unchanged
- Remaining work: Activate the AI provider, implement the fixes, run the live
  tests, and record objective results.

## EVENT-2026-09-02-001 — Execution Foundation regression and rebuild

- Date/time: 2026-09-02
- Type: verification | run
- Phase/sub-phase: Phase 1 — AI-native architecture; Execution Foundation 1C–1F
- Objective: Verify the landed tool-contract, AI telemetry, validation, and
  report-integrity changes before live acceptance.
- Environment/target: Local macOS Docker Compose runtime; authorized local
  OWASP Benchmark bridge
- Exact command or endpoint: Five targeted pytest groups covering 110 tests;
  `docker compose build pentest-ai-backend nexus-worker`; forced recreate;
  `/health/ready`; container-to-lab HTTP preflight
- Change or observation: All 110 tests passed. API and worker rebuilt and
  became healthy; readiness returned HTTP 200; lab preflight returned HTTP 200.
- Result: passed
- Evidence/artifact IDs: `tests/test_structured_contract.py`,
  `tests/test_reasoning_gateway.py`, `tests/test_execution_integrity.py`,
  `tests/test_autonomous_web_pentest.py`, `NEXUS_CONTEXT_MEMORY.md`
- Impact on rating: unchanged
- Remaining work: Prove the behavior in the integrated live acceptance gate.

## EVENT-2026-09-02-002 — Legacy pentest entry path rejected without session context

- Date/time: 2026-09-02
- Type: bug | verification
- Phase/sub-phase: Phase 1 — Execution Foundation 1A/1F preflight
- Objective: Start the authorized local OWASP Benchmark acceptance job.
- Environment/target: Local OWASP Benchmark bridge
- Exact command or endpoint: `POST /pentest` using job
  `f99961fd-3d68-40ff-a281-be82f88d2f3a`
- Change or observation: The legacy path created a session row without the
  required `session_context`; Nexus correctly rejected it with
  `Session scope context not found` before any tool ran.
- Result: blocked
- Evidence/artifact IDs: job `f99961fd-3d68-40ff-a281-be82f88d2f3a`
- Impact on rating: unchanged
- Remaining work: Use the official session setup path or fix the legacy path
  before relying on it for future acceptance runs.

## EVENT-2026-09-02-003 — Full Execution Foundation live acceptance failed closed

- Date/time: 2026-09-02
- Type: run | gap
- Phase/sub-phase: Phase 1 — Execution Foundation 1F
- Objective: Exercise the complete 1A–1E foundation with the AI provider live.
- Environment/target: Authorized local OWASP Benchmark bridge; Dolphin3-Cyber
  provider; full preset; autopilot; explicit private-lab session scope
- Exact command or endpoint: `POST /sessions`, then `POST /pentest`, followed by
  `/job/{job_id}`, `/sessions/{session_id}/tool-runs`, reasoning cycles,
  execution trace, candidates, validation, report, and export endpoints
- Change or observation: Private transport passed. The job recorded 16 tool
  runs (15 succeeded, 1 failed), 5 model calls (1 succeeded, 4 failed), 5
  cycles (1 succeeded, 4 failed), 14 candidates (1 validated, 13
  inconclusive), and no report/export acceptance. The authoritative browser
  tool timed out and triggered the execution-integrity gate.
- Result: failed
- Evidence/artifact IDs: job `616a8efb-ab44-4da1-af67-437e9bd5fe3e`, session
  `ccaa00a9-f119-4143-ac8c-5f2222f9baa6`, tool run
  `run_64f3f2001ad74b15a3ad73f482b12c2f`
- Impact on rating: unchanged
- Remaining work: Make browser timeout recovery close the failed attempt when
a retry succeeds, stabilize Dolphin JSON/protocol output, ensure every
AI-expected action receives a durable dispatch outcome, then rerun 1F.

## EVENT-2026-09-02-004 — Execution Foundation hardening regression

- Date/time: 2026-09-02
- Type: fix | verification
- Phase/sub-phase: Phase 1 — Execution Foundation 1C–1F
- Change: Added cooperative browser partial-timeout handling, strict
  same-tool/same-target later-success reconciliation, and durable
  `dispatch_outcome_missing` records for missing AI callbacks.
- Environment: macOS Docker Compose; authorized local OWASP Benchmark bridge.
- Verification: Docker regression **113 passed**; browser behavioral test
  passed; API/worker recreated; readiness and target returned HTTP 200.
- Result: code-level hardening passed; rating unchanged.
- Remaining work: Prove the paths with a live AI provider.

## EVENT-2026-09-02-005 — Fresh live run completed with provider blocker

- Date/time: 2026-09-02
- Type: run | gap
- Phase/sub-phase: Phase 1 — Execution Foundation 1F
- Evidence: Session `757b4e8b-3914-4b36-b079-60d83c731ebd`; job
  `10394abf-8111-41da-9f2c-3a66f2c28f93`; terminal `done`; 64 non-narrative
  runs (47 succeeded, 1 partial, 0 failed, 16 skipped); zero private-IP
  rejections; five V2 validated evidence-linked candidates; md/pdf/docx
  exports HTTP 200.
- Provider result: configured Dolphin ngrok routes returned HTML HTTP 404;
  two reasoning cycles/model calls failed `NotFoundError`; zero AI
  actions/traces; deterministic fallback executed.
- Result: 1F failed despite job completion; `done` is not AI acceptance.
- Impact on rating: unchanged.
- Remaining work: Reconnect provider, pass health/models/completion preflight,
  and rerun the identical live gate.

## EVENT-2026-09-02-006 — Fresh live AI acceptance failed on protocol and timeout

- Date/time: 2026-09-02
- Type: run | gap
- Phase/sub-phase: Phase 1 — Execution Foundation 1A–1F
- Objective: Test the complete execution foundation against the authorized
  local OWASP Benchmark with Dolphin3-Cyber active.
- Environment/target: macOS Docker Compose; API/worker healthy; local
  Benchmark bridge; explicit `host.docker.internal` scope with
  `allow_private: true`; full/autopilot.
- Exact command or endpoint: Direct provider `/health`, `/v1/models`, and
  `/v1/chat/completions` preflight; `POST /sessions`; `POST /pentest`; durable
  audits through `/job/{job_id}`, tool-runs, execution trace, reasoning cycles,
  candidate validation, workflow report, and export endpoints.
- Evidence/artifact IDs: session
  `f05255e6-d7a3-45de-8e6f-6faddb28d2f2`; job
  `c1a01b11-09b4-4581-8eeb-d2ba3a1c8b6f`; failed tool-run
  `run_80d7f1930d5e4be6a85ad95b40172c3e`; report
  `report_a9652bfea40e174ec4bdfb93a9760f13`.
- Change or observation: Preflight and transport passed. The run produced 69
  durable tool-runs (46 succeeded, 4 partial, 1 failed, 18 skipped), 5
  reasoning cycles/model calls (all failed `_GatewayProtocolError`), 12
  candidates (5 validated, 7 inconclusive), and an evidence-grounded workflow
  report. The authoritative browser open-redirect call still timed out and
  failed the job gate. Job export returned 409 because the terminal job was
  `error`.
- Result: failed; this is not evidence that the Benchmark target is clean.
- Impact on rating: unchanged.
- Remaining work: Fix full-prompt Dolphin JSON/protocol compatibility; make
  retryable browser timeout recovery close or reconcile the failed attempt;
  rerun 1F and require successful AI action traces plus report/export readiness.

## EVENT-2026-09-02-007 — Corrected-provider Execution Foundation acceptance

- Date/time: 2026-09-02
- Type: run | verification | gap
- Phase/sub-phase: Phase 1 — Execution Foundation 1F
- Objective: Run the complete authorized 1A–1F live acceptance with the updated
  Dolphin3-Cyber provider and verify durable AI, execution, validation, and
  report behavior.
- Environment/target: macOS Docker Compose; local OWASP Benchmark bridge;
  full/autopilot; explicit 'host.docker.internal' private scope;
  'allow_private=true'.
- Evidence/artifact IDs: session
  '247d5603-95b2-46bf-b4cf-c560372cc55c'; job
  '13d7e512-7282-4820-936a-2c4b232c7b0a'; report artifact
  '/app/reports/247d5603-95b2-46bf-b4cf-c560372cc55c_13d7e512.md'.
- Observation: API/worker/target/provider preflight passed. The job completed
  durably in 1625.30s. Audit found 70 endpoint rows (68 structured), with
  47 succeeded, 5 typed partial, 0 failed, and 18 typed skips. Six reasoning
  cycles/model calls succeeded; 13 actions and 4 blocked actions were traced;
  12 candidates produced 5 evidence-linked validated records and 7
  inconclusive records. No private-IP rejection, dispatch-missing, or
  validation-persistence error occurred.
- Report verification: workflow report quality 1.0, 10 grounded claims, five
  finding IDs, zero redaction leaks; job report/export HTTP 200. Three repeated
  report reads left 10 durable claims, so the earlier duplication issue did
  not reproduce.
- Gap: five browser open-redirect runs stayed partial with no later successful
  same-target retry; one mixed-content skip lacked a typed reason; the legacy
  assessor logged two ngrok gateway errors that were caught before structured
  report persistence.
- Result: partial live acceptance; 1F not passed. This is not evidence that
  the Benchmark target is clean and does not measure hidden-label recall.
- Impact on rating: unchanged.
- Remaining work: Add a typed reason for every skipped tool, run a dedicated
  retry-recovery acceptance, and stabilize/remove the legacy assessor gateway
  dependency before calling the whole foundation reliability-clean.

## EVENT-2026-09-02-008 — Execution Foundation 1C–1F implementation hardening

- Date/time: 2026-09-02
- Type: upgrade | regression verification
- Phase/sub-phase: Phase 1 — Execution Foundation 1C–1F
- Objective: Close the known tool-contract, browser, recovery, AI-assessment,
  and acceptance-gate gaps before the next provider-backed live run.
- Environment: macOS Docker Compose; rebuilt API/worker images; AI provider
  intentionally offline; no live target workflow executed.
- Changes: typed failure/partial/skip normalization; explicit recon skip
  metadata; adaptive encoded browser redirect observation; durable retry
  recovery linkage; canonical ReasoningGateway assessor; fail-closed 1F
  evaluator; removal of hidden default hypothesis/action count ceilings.
- Verification: focused **60 passed**; full worker-image regression **377
  passed, 10 warnings**; Docker build passed; recreated API/worker;
  `/health/live` HTTP 200 and `/health/ready` HTTP 200 with autonomous mode,
  Supabase, durable schema, and Phase 1 schema healthy.
- Result: implementation/regression verified; live acceptance pending.
- Evidence: test commands run in the rebuilt `nexus-worker` image; readiness
  response recorded from `http://127.0.0.1:8000/health/ready`.
- Impact on rating: unchanged.
- Remaining work: Start Dolphin3-Cyber, run the full authorized 1F live gate,
  verify durable AI calls/actions, recovery, report/export, and update the
  scorecard only from those live results.

## EVENT-2026-09-02-009 — Execution Foundation 1F live acceptance

- Date/time: 2026-09-02
- Type: run | verification | gap
- Phase/sub-phase: Phase 1 — Execution Foundation — 1F
- Objective: Execute the full authorized OWASP Benchmark workflow with the
  active local Dolphin3-Cyber provider and evaluate the durable 1F gate.
- Environment/target: macOS Docker Compose; provider via Google Colab/ngrok;
  `http://host.docker.internal:8446/benchmark/`; session
  `234e2969-265b-4f02-a238-7bd1084e39b8`; job
  `c356fb34-722b-4bae-b6df-5dcb88fd7644`.
- Exact command or endpoint: `POST /sessions`, `POST /pentest`, poll
  `GET /job/{job_id}`, then durable tool-run/trace/cycle/candidate/report
  endpoints and `core.phase1_acceptance.evaluate_phase1_acceptance`.
- Change or observation: The corrected authorized scope had
  `allow_private: true`; no private-IP rejection occurred. The run persisted
  66 authoritative rows: 47 succeeded, 1 partial, 2 failed, 18 skipped; 3
  reasoning cycles, 3 model calls, 2 model-action traces, 11 trace actions,
  9 candidates, 5 validated candidates, and zero validation persistence errors.
- Result: failed
- Evidence/artifact IDs: `run_94b926cf2be84d239492c5648fcb5763`,
  `run_033b1198a1e244b890fe8e86f0bbbcb4`,
  `run_fe215e2d73984c78a2d0bd478ca6138f`,
  `cand_41e65bb6a437424a9a656d6914e5686c`,
  `cand_5c1d250b665146cf87af12ffb6e6f62d`.
- Impact on rating: unchanged
- Remaining work: Fix or replace the two legacy parameter-discovery proxy
  paths, make the redirect timeout recover durably, resolve required-coverage
  skips or classify the local-lab contract explicitly, add a dedicated retry
  recovery fixture, and rerun 1F. Report quality passed, but job/export
  durability did not because the job ended in error.

## EVENT-2026-09-03-010 — Full code review and Execution Foundation hardening

- Date/time: 2026-09-03
- Type: code review | upgrade | fix | verification
- Phase/sub-phase: Phase 1 — AI-native architecture; Execution Foundation 1C–1F
- Objective: Review the entire project before further fixes and remove runtime
  paths that mismatch the canonical AI-native architecture.
- Environment/target: Local repository; macOS Docker Compose source; no live
  target workflow in this checkpoint; provider intentionally not required.
- Exact command or endpoint: `rg --files` inventory; ECC audits by Carson,
  Kant, and Volta; `py_compile` for API/worker/core/tools; focused pytest;
  `pytest -q -p no:cacheprovider`; `git diff --check`; YAML parse check.
- Change or observation: Canonical full/recon execution no longer builds
  legacy CrewAI agents; guarded transport no longer inherits ambient proxies;
  parameter discovery/recon/browser preserve typed errors and recovery;
  ReasoningGateway has configurable transient-provider retry with distinct
  retry/fallback telemetry; config snapshots deep-merge; circuit-breaker skips
  are operationally typed and not false required coverage.
- Result: implementation/regression passed; live 1F unproven
- Evidence/artifact IDs: `NEXUS_CONTEXT_MEMORY.md`,
  `PROJECT_HANDOFF.md`, `NEXUS_UPGRADE_LEDGER.md`,
  `NEXUS_SCORECARD.yaml`; focused **75 passed**; full **387 passed, 9
  warnings**; `git diff --check` clean.
- Impact on rating: unchanged
- Remaining work: Start the provider and rerun the fresh authorized 1F live
  gate. Only that run can prove durable recovery, provider participation,
  report/export completion, and whether the rating changes. Worker/API
  process-local compatibility state and Phase 2–5 capability evaluation remain
outside this checkpoint.

## EVENT-2026-09-03-011 — Execution Foundation local gap closure

- Date/time: 2026-09-03
- Type: code review | fix | regression verification
- Phase/sub-phase: Phase 1 — AI-native architecture — Execution Foundation 1C–1F
- Objective: Close the reviewed runtime gaps before the next provider-backed
  live test; live testing was intentionally paused because the AI provider was
  offline.
- Environment/target: macOS Docker Compose source; no provider inference and no
  target workflow executed.
- Changes: bounded worker recovery/telemetry retries; typed legacy
  cancellation/failure semantics; partial-as-failure mission status;
  session-scoped canonical V2 validation; durable evidence verification in the
  acceptance gate; synchronous non-blocking readiness route; exact-origin
  browser local-lab authorization and request/response accounting; authorized
  local-lab discovery defaults.
- Verification: Docker build passed; focused **83 passed**; full **398 passed,
  9 warnings**; syntax/YAML/diff checks passed; API `/health/live` and
  `/health/ready` HTTP 200; API and worker healthy.
- Result: implementation/regression verified; live 1F pending.
- Impact on rating: unchanged.
- Remaining work: Start the local provider and run the fresh authorized 1F
  acceptance gate. Only that run can prove durable AI participation, retry
  recovery, complete report/export behavior, and whether the score changes.
