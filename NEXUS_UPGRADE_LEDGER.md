# Nexus Upgrade Ledger

Ledger ini adalah catatan append-only untuk perubahan Nexus. Tujuannya menjaga
konteks antar sesi dan mencegah rating berubah hanya karena code bertambah.

## Aturan pencatatan

Setiap upgrade wajib mencatat:

- ID dan tanggal;
- gap/hipotesis yang ditargetkan;
- file atau komponen yang diubah;
- behavior yang diharapkan berubah;
- risiko/regresi;
- command dan environment test;
- hasil aktual dan evidence ID bila tersedia;
- status `implemented`, `tested`, `live-tested`, atau `proven`;
- hal yang belum terbukti;
- keputusan rating: `unchanged`, `increased`, `decreased`, atau `unproven`.

`proven` hanya boleh dipakai jika exit criteria dan test yang relevan benar-benar
lulus. Test unit/contract tidak membuktikan recall vulnerability di live lab.

## Baseline snapshot — Phase 0

**ID:** `BASELINE-2026-08-31`

**Tujuan:** membekukan titik awal sebelum perubahan arsitektur AI-native dan
menetapkan aturan pengukuran yang tidak bergantung pada ingatan percakapan.

**Source snapshot:**

- HEAD commit: `ab377a12` (`upgrade`)
- working tree: dirty; perubahan terdahulu belum dibuat clean checkpoint
- runtime: Docker Compose di macOS
- deployment mode: `shadow`
- detection depth: `strict`
- autonomous web pentest: enabled, read-only auto-run, bounded
- local model: configured by environment but live availability tidak terbukti
  pada full run terakhir karena provider remote offline

**Evidence yang sudah ada:**

- API, worker, dan frontend terakhir terverifikasi healthy;
- live matrix: 5 profile, 4 configured, 4 reachable, 4 surface-ready;
- full live run terakhir: 51 structured tool runs, 0 hard execution errors,
  4 partial runs;
- candidate findings pada run tersebut: 4, semuanya time-based SQLi;
- validated findings pada run tersebut: 0;
- seluruh 4 candidate: `inconclusive`;
- regression terarah sebelumnya: 82 passed, 1 deselected;
- test source suite terbaru wajib dijalankan ulang setelah baseline file ini
  selesai dan hasil aktualnya dicatat di scorecard.

**Baseline score:**

| Area | Score | Status | Alasan |
|---|---:|---|---|
| Safety/execution | 7/10 | evidenced | Scope, bounded execution, health, dan structured runner berjalan |
| Recon breadth | 6/10 | partially evidenced | Banyak lane berjalan, tetapi sebagian capability memang gated |
| Recon actionability | 4/10 | unproven | Data belum konsisten menjadi hypothesis/input spesifik |
| Vulnerability analysis | 3/10 | evidenced limitation | Candidate sedikit dan seluruhnya inconclusive; AI belum di main loop |
| Exploitation/impact proof | N/R | unproven | Belum ada live end-to-end proof yang cukup |
| Final report quality | N/R | unproven | Plumbing tersedia, kualitas senior-review belum dibenchmark live |
| Overall autonomous web pentest | 4/10 | provisional | Fondasi ada, AI-native control loop belum terbukti |

N/R berarti `not rated` karena evidence belum cukup; bukan nilai nol.

**Rating decision:** `unchanged`

Phase 0 sendiri bukan capability upgrade dan tidak menaikkan rating.

## Historical upgrade context

Catatan ini merangkum perubahan yang sudah ada agar upgrade berikutnya tidak
mengulang pekerjaan lama. Statusnya sengaja dibedakan dari klaim world-class.

### `HIST-STRUCTURED-VALIDATION`

- Scope: typed tool results, legacy adapter, V2 validation, proof envelope,
  validation trace, candidate/evidence persistence.
- Status: `implemented`, `tested`.
- Terbukti: persistence dan deterministic validation plumbing memiliki coverage;
  false-positive gate lebih ketat.
- Belum terbukti: live vulnerability recall dan target-specific detection.
- Rating impact: `unchanged`.

### `HIST-RECON-KNOWLEDGE`

- Scope: deterministic multi-lane recon, knowledge graph, surface inventory,
  technology/application contract, identity/workflow projections, bounded local
  lab fan-out.
- Status: `implemented`, `live-tested` untuk wiring/surface.
- Terbukti: recon scope, bounded execution, structured runs, dan graph persistence.
- Belum terbukti: seluruh fakta recon menjadi hypothesis dan action yang spesifik.
- Rating impact: `unchanged`.

### `HIST-AUTONOMOUS-CONTROL`

- Scope: bounded autonomous loop, runtime failure feedback, replan metadata,
  progress reporting, local-lab preapproval.
- Status: `implemented`, `tested`.
- Terbukti: loop dapat merencanakan dan menjalankan action terdaftar secara
  bounded; failure tidak dipromosikan menjadi success.
- Belum terbukti: model-driven exploration, creative hypothesis generation,
  multi-step adaptation, dan validated recall.
- Rating impact: `unchanged`.

### `HIST-MODEL-ROUTING`

- Scope: local model menjadi default bila environment valid dan stale provider
  fallback tidak diam-diam dipilih.
- Status: `implemented`, `contract-tested`.
- Terbukti: routing selection pada test.
- Belum terbukti pada live run: model provider online dan terlibat di full
  autonomous pentest path.
- Rating impact: `unchanged`.

### `MAINT-TEST-CONTRACT-2026-08-31`

- Scope: menyinkronkan test config dengan tiga local-lab human-recon bounds yang
  memang sudah ada di config.
- File: `tests/test_config_loader.py`.
- Behavior impact: none; ini maintenance contract, bukan capability upgrade.
- Status: `implemented`, `tested`.
- Test command: `./.venv/bin/python -m pytest -q`.
- Actual result: `262 passed in 1m55s`.
- Validation: `docker compose config --quiet` dan parse YAML scorecard berhasil.
- Rating impact: `unchanged`.

## Phase 0 completion record

**Status:** `complete`

Phase 0 berhasil membuat baseline governance tanpa mengubah capability pentest.
Score baseline tetap sama. Perubahan source satu-satunya pada phase ini adalah
sinkronisasi expectation test dengan local-lab config yang sudah ada; semua
perubahan capability terdahulu tetap dicatat sebagai historical context dan belum
dianggap AI-native proof.

**Verified:**

- `262 passed in 1m55s` pada source regression suite;
- Compose configuration valid;
- `NEXUS_SCORECARD.yaml` valid;
- baseline dan rating tidak dinaikkan.

**Not proven:**

- AI belum menjadi decision-maker pada autonomous full path;
- recon-to-hypothesis closure;
- live validated vulnerability recall;
- multi-step authenticated/business-logic impact;
- senior-review report quality.

**Rating decision:** `unchanged`.

## LIVE-JUICE-SHOP-PHASE1-2026-09-01

**Date:** `2026-09-01`

**Objective:** Validate the Phase 1 execution foundation against one authorized
local OWASP Juice Shop instance: scoped private transport, real worker-owned
execution, truthful partial/failed tool states, and behavior beyond the old
eight-action ceiling.

**Environment:** macOS Docker Compose; target
`http://host.docker.internal:3001` mapped to the local Juice Shop; session scope
contained `allow_private: true`; local model `dolphin3-cyber` returned HTTP 200
from `/health`.

**Result:** Job `a1e92d6c-8cfe-4b80-b735-e7618da0151b` ran for approximately
`723.31s` and ended with durable status `failed` / compatibility status `error`.
There were `16` structured runs, including `14` authoritative tool runs:
`10 succeeded`, `3 partial`, and `1 failed`. No `private_ip_rejected` occurred.
The worker executed real probes including CORS, DOM XSS, GraphQL, LFI/RFI,
SQLi, SSTI, session management, WebSocket, and access-control tooling.

**What passed:** Session-scoped private transport; target reachability from
API and worker; model availability; real tool dispatch; explicit partial and
failed tool records; more than eight structured runs; fail-closed terminal
behavior when an authoritative tool failed.

**What failed:** Browser tools could not navigate
`host.docker.internal` and produced three partial plus one failed run. The
durable job retained no terminal `error_code`, `error_message`, or summary,
because `update_job()` only updates the API process-local `jobs` map while the
worker executes in a separate process. The worker health file also became
stale during the long synchronous handler and temporarily reported unhealthy.

**Finding interpretation:** `0` candidates and `0` validated findings are not
a clean-target result. Several legacy tools emitted heuristic warnings, but
those were not promoted into typed candidates; this run therefore cannot score
vulnerability recall or precision.

**Status:** `live-tested`, `failed-integrity-gate`.

**Rating decision:** `unchanged`. Phase 1 is not live-accepted yet. Next fixes
must address worker/API terminal-state persistence, browser target reachability,
and heartbeat freshness during active jobs before repeating the acceptance run.

## PHASE1-EXECUTION-FOUNDATION-2026-09-01

**Date:** `2026-09-01`

**Targeted gap:** The live loop rejected explicitly scoped private targets,
the previous default produced a fixed eight-action ceiling, and scope/private
authorization behavior was not sufficiently centralized for non-lab targets.

**Changed components:** `core/safety_kernel.py`, `core/scope.py`,
`core/tool_transport.py`, `tools/playwright_tools.py`,
`core/autonomous_web_pentest.py`, `core/authorized_lab_mode.py`,
`core/checkpoint.py`, `config/pentest_config.yaml`,
`core/config_loader.py`, `api.py`, and Phase 1 regression tests.

**Behavior change:** A private target is eligible when its exact session scope
rule explicitly carries `allow_private: true`, regardless of whether it is a
named local lab. The caller flag is not authoritative. Metadata/link-local
destinations remain hard-blocked, scope contexts are session-isolated, provider
addresses are checked, and raw socket attempts count against the durable
budget. The autonomous loop has no default total-action cap; timeout, durable
budget, cancellation, emergency stop, and planner decisions remain controls.

**Verification:**

```text
Phase 1 targeted regression: 37 passed in 17.93s
Full source regression: 281 passed in 115.48s (1m55.48s)
Frontend lint/build: passed
YAML parse, Python compile, and git diff check: passed
Docker API /health/live: 200
Docker API /health/ready: 200; config/supabase/durable_schema: ok
```

**What this proves:** The implementation supports explicitly authorized
private targets outside the local-lab shortcut, removes the implicit eight
action default, and preserves auditable scope/budget/emergency-stop controls.

**What this does not prove:** DNS connection pinning, full browser peer-IP
enforcement, vulnerability recall, or validated finding quality on live labs.
No rating increase is justified before the live matrix is rerun.

**Status:** `implemented-and-regression-tested`; live gate pending.

**Rating decision:** `unchanged`.

## Next planned change

`ARCH-AI-NATIVE-CONTROL-LOOP` adalah phase berikutnya. Targetnya memindahkan
reasoning, hypothesis generation, tool selection, dan adaptation ke model AI,
sementara safety/approval/validation tetap menjadi hard boundary. Phase ini
belum dimulai pada saat ledger dibuat.

Exit criteria minimal:

- full autonomous path benar-benar memanggil model;
- model menerima structured recon snapshot dan hasil action terbaru;
- model mengeluarkan proposal terstruktur yang dapat direplay;
- safety layer hanya menolak aksi yang melanggar policy;
- validator tetap memutuskan status finding;
- ada live test dengan bukti model participation dan tidak ada regression safety.

## Template entry berikutnya

```text
ID:
Date:
Objective/gap:
Changed components:
Expected behavior:
Safety/regression risk:
Test commands:
Environment/target:
Actual result:
Evidence IDs/artifacts:
Not proven:
Exit criteria:
Rating decision:
```

## `ARCH-AI-NATIVE-CONTROL-LOOP-2026-08-31`

**Date:** `2026-08-31`

**Objective/gap:** Memindahkan reasoning, hypothesis generation, tool selection,
dan adaptation pada autonomous web path ke model AI dengan contract dan
telemetry yang dapat direplay, tanpa melewati safety, approval, scope, evidence,
atau deterministic validation boundary.

**Changed components:**

- `core/reasoning_gateway.py` — bounded/redacted JSON gateway, typed result,
  explicit fallback, output limits, digest-only trace;
- `core/autonomous_web_pentest.py` — model-driven cycle dispatch, fresh context,
  model action admission, deterministic diagnostic fallback, stop handling;
- `core/adaptive_planner.py` — strict observed endpoint boundary validation;
- `core/structured_contract.py` — `ModelCallTraceV1`;
- `core/structured_repository.py` — model-call persistence/readback;
- `migrations/023_reasoning_model_calls.sql` — additive provider-attempt ledger;
- `core/interactive_flow.py`, `api.py`, config, and `.env.example` — wiring and
  explicit reasoning model/fallback configuration;
- `tests/test_reasoning_gateway.py`, `tests/test_autonomous_web_pentest.py` —
  gateway, fallback, stop, action-admission, and execution-source coverage.
- Revision 2026-09-01: `core/autonomous_web_pentest.py` now materializes all
  model hypotheses (including model-only/implicit hypotheses), bridges all
  reasoning action types, records bounded branches/evidence gaps, persists a
  model-only cycle before stopping, and enforces true `shadow` versus `strict`
  dispatch semantics.
- Revision 2026-09-01: `core/interactive_flow.py` and
  `core/recon_orchestrator.py` add an AI recon-selection boundary with bounded
  follow-up; shadow/provider-failure paths retain the canonical recon mission.

**Expected behavior:** Pada setiap autonomous cycle, Nexus mengirim snapshot
terstruktur yang dibatasi/redacted ke gateway; model dapat memilih hypothesis,
observation, payload proposal, approval request, stop, dan action terstruktur.
`strict` meneruskan hanya action yang lolos validasi ke safety/execution path;
`shadow` mencatat keputusan AI tanpa dispatch dan memilih deterministic planner
hanya sebagai fallback diagnostik eksplisit. Semua cycle, branch, gap, provider
attempt, dan hypothesis tetap dapat direplay tanpa raw secret/prompt/output.
Deterministic planner tidak dipanggil sebelum AI pada jalur AI-enabled.

**Safety/regression risk:** Model tidak dapat mengeksekusi tool secara langsung,
memberi approval, atau menetapkan validated finding. Mutation/high-risk action
tetap butuh approval/cleanup. Provider failure, malformed JSON, oversized output,
unknown tool, invented evidence, stale evidence, dan hallucinated endpoint fail
closed atau memakai fallback diagnostik.

**Test commands/environment:** macOS workspace, Python `.venv`, Docker Compose
config validation; no live target and no local model endpoint required for the
automated suite.

```text
./.venv/bin/python -m pytest -q tests/test_reasoning_gateway.py tests/test_autonomous_web_pentest.py tests/test_model_registry.py
./.venv/bin/python -m pytest -q
./.venv/bin/python -m compileall -q core api.py tests
docker compose config --quiet
git diff --check
```

**Actual result:** Focused reasoning/autonomous `24 passed in 21.26s`; recon/
interactive regression `44 passed in 16.03s`; full source regression
`277 passed in 1m52.55s`; compile, YAML, Compose, and diff checks passed. Regression
assertion membuktikan deterministic planner tidak dipanggil sebelum AI pada model
path. Backend/worker berhasil rebuild-recreate dan kembali `healthy`; `/health/live`
dan `/health/ready` kembali 200 setelah cold-start.
The implementation was reviewed with ECC subagent `Planck`; its scoped gateway
and test contribution passed the same full regression suite after integration.

**Evidence IDs/artifacts:** `ARCH-AI-NATIVE-CONTROL-LOOP-2026-08-31`,
`migrations/023_reasoning_model_calls.sql`, `tests/test_reasoning_gateway.py`,
`tests/test_autonomous_web_pentest.py`.

**Exit criteria:** Structural gateway, full action bridge, lineage persistence
boundary, shadow/strict semantics, AI recon selection boundary, and
model-to-execution handoff: passed.
Safety/validation regression: passed. Live model participation with successful
provider telemetry: not run. Live lab vulnerability recall, adaptive recovery
quality, business-logic chain, and report quality: not proven.

**Status:** `tested`

**Not proven:** Local/remote provider availability in a full live job; model
creative hypothesis quality; recon-to-hypothesis closure; validated recall and
precision; multi-step authenticated/business-logic impact; senior-review report
quality; migration 023 applied/read back against the live Supabase project; any
world-class capability claim.

**Rating decision:** `unchanged` — no score increase from implementation or
offline/fake-provider tests.

## Next planned change after Phase 1

`LIVE-AI-PARTICIPATION-AND-LAB-COVERAGE` is the next gate. It requires an online
explicit model endpoint, a run against authorized local labs, persisted
successful `model_calls`, model-selected actions, deterministic validation
metrics, and comparison against the immutable baseline. Until those artifacts
exist, the scorecard remains unchanged.

## LIVE-CRAPI-SHADOW-STRICT-2026-09-01

**Date:** `2026-09-01`

**Objective:** Execute a real, bounded full-pentest comparison against an
authorized local crAPI deployment in both `shadow` and `strict` reasoning
modes, using the live local model and recording objective execution evidence.

**Environment:** macOS Docker Compose; crAPI checkout `73d309c`; target
`http://host.docker.internal:8888` mapped only to local `127.0.0.1:8888`;
provider preflight `/models` and `/chat/completions`: HTTP 200.

**Shadow run:** Job `60b03471-137b-4112-8b28-fe25b1d42f8c`, 554.53 seconds,
50 structured tool-runs: 14 succeeded, 6 failed, 30 skipped; 0 candidates;
7 open evidence gaps; terminal status `error` because execution integrity
blocked on `amass_enum`, `browser_extract_surface`,
`browser_find_open_redirect`, `browser_screenshot`,
`detect_subdomain_takeover`, and `human_recon_crawl`.

**Strict run:** Job `84a0c608-ed9d-446b-adc7-a208a5103ceb`, 493.45 seconds,
12 structured tool-runs: 9 succeeded, 3 failed; 0 candidates; 4 persisted
reasoning cycles with `mode=strict`; terminal status `error` because execution
integrity blocked on `browser_find_open_redirect`,
`browser_intercept_requests`, and `param_discovery_get`.

**What this proves:** The provider was reachable and the strict path accepted
live model reasoning and dispatched bounded model-selected actions. Both modes
ran through recon, vulnerability analysis, evidence persistence, and the
execution-integrity gate.

**What this does not prove:** No vulnerability recall/precision, validated
finding, business-logic impact, authenticated multi-identity workflow, or
report-quality claim. `private_ip_rejected` and `NoneType` response failures
show that local-target transport/policy compatibility is currently blocking
parts of the toolchain; zero findings must not be interpreted as a clean crAPI.

**Post-run state:** `reasoning_mode` restored to `shadow`; backend and worker
recreated with the safe default. Score remains unchanged.

**Status:** `live-tested`, `not-proven`.

**Next gap:** Fix the local-lab transport authorization boundary and failure
contracts, then repeat the same runs before changing capability architecture.

## RUNTIME-AUTONOMOUS-MODE-2026-09-01

**Date:** `2026-09-01`

**Targeted gap:** The operational `shadow`/`strict` split prevented the AI
decision path from being the single live execution path and made durable
execution, validation, and reporting behavior depend on configuration mode.

**Changed components:** `config/pentest_config.yaml`, `core/config_loader.py`,
`api.py`, `worker.py`, `core/durable_execution.py`,
`core/autonomous_web_pentest.py`, `core/interactive_flow.py`,
`core/adaptive_planner.py`, `core/detection_validation_v2.py`,
`core/structured_runner.py`, `core/detection_validation_api.py`,
`core/impact_service.py`, `core/business_logic_engine.py`,
`core/production_contract.py`, `frontend-pentest/app/page.tsx`, and related
regression tests.

**Behavior change:** New runtime jobs use one `autonomous` path. Pentest and
browser jobs are worker-owned; model proposals are dispatched after typed
admission; validation/reporting are authoritative; old mode switches no
longer control execution. Legacy labels remain readable only in historical
records and offline benchmark fixtures.

**Verification:**

```text
.venv/bin/python -m pytest -q tests/test_autonomous_web_pentest.py \
  tests/test_config_loader.py tests/test_stage9_detection.py \
  tests/test_stage11_chain.py tests/test_stage19_production_autonomy.py \
  tests/test_execution_integrity.py
58 passed in 28.64s
python -m py_compile <runtime modules>
YAML config reload: assessment_mode=autonomous
```

**What this proves:** The old live branching is removed from the operational
path, AI proposals are dispatched in the loop, durable queue behavior is the
only production path, and candidate validation no longer depends on a
shadow/strict promotion switch.

**What this does not prove:** Full vulnerability recall, business-logic
coverage, destructive lab workflows, local private-IP transport, or
world-class capability. No rating increase is justified from this refactor.

**Status:** `tested`

**Rating decision:** `unchanged`.

## PHASE1-FIVE-GAP-CLOSURE-IMPLEMENTATION-2026-09-01

**Status:** implementation regression passed; live rerun pending.

This checkpoint addresses all five concrete gaps recorded by the Juice Shop
Phase 1 run:

1. Browser SPA navigation now uses a bounded DOM-aware lifecycle fallback, and
   Compose services explicitly map `host.docker.internal` to the Docker host
   gateway.
2. Worker-owned application terminal state is persisted through a durable
   append-only event, so the API can read status, message, summary, logs,
   error details, and report reference across processes.
3. The active lease heartbeat refreshes `/tmp/nexus-worker.health` during a
   long-running job.
4. Compact autonomous cycle/action traces are persisted in phase metrics and
   available from `/sessions/{session_id}/execution/trace`.
5. Legacy structured warning buckets and explicit count blocks are ingested as
   typed suspected candidates with `validation_required`; heuristic text alone
   cannot create validated findings.

The reasoning gateway also no longer silently drops a nine-action response:
the deployment setting is config-driven at `20`, with a parser safety maximum
of `32`, while actual dispatch remains governed by mission/resource controls.

**Verification:** focused five-gap regression `63 passed in 25.58s`; full source
regression `292 passed in 127.35s`; Python compile, YAML parse, Docker Compose
config, and `git diff --check` passed. The
recreated API and worker are healthy; `/health/live` and `/health/ready` return
HTTP 200. The worker reaches `host.docker.internal:3001` with HTTP 200, and a
container Playwright navigation smoke reached Juice Shop with HTTP 200 and the
expected title. A fresh authorized full live rerun is still required. Rating
remains unchanged until live evidence proves the five fixes end-to-end.
## PHASE1-DYNAMIC-AI-BUDGET-IMPLEMENTATION-2026-09-01

**Status:** implementation regression passed; live AI rerun pending provider
preflight.

**Objective:** remove arbitrary default action/proposal ceilings so the model
can propose broadly and the scheduler can choose the admissible batch from the
live mission state. This is a runtime-budget change, not a removal of scope,
approval, cancellation, timeout, resource, or emergency-stop controls.

**ECC review:** Planck audited the gateway, adaptive planner, reasoning cycle,
and autonomous dispatch paths. The audit found separate default/hard-coded
ceilings and a hidden raw-action truncation. The implementation uses one
explicit auto/None convention for an unbounded-by-count default.

**Changed behavior:**

- reasoning.max_model_actions, reasoning.max_actions_per_cycle, and
  autonomous_web_pentest.max_actions_per_cycle default to auto;
- adaptive_planner.max_proposals defaults to auto;
- gateway parsing preserves all schema-valid model actions unless an operator
  explicitly sets a count limit;
- planner validation no longer truncates raw actions at 20;
- autonomous dispatch continues until the live timeout, cancellation, resource
  budget, emergency stop, planner stop, or an explicit operator limit;
- response bytes, schema validation, tool admission, scope, and mutation
  approval remain bounded runtime controls.

**Verification:** targeted dynamic-budget tests and related contracts:
103 passed in 41.41s; full source regression: 294 passed in 100.80s; Python
compile, YAML parse, Docker Compose config, and git diff check passed. Backend
and worker were rebuilt with force-recreate; both are healthy, and the live
and ready health endpoints return HTTP 200.

**Provider preflight:** the configured local-provider URL was queried without
printing credentials; the provider returned ngrok ERR_NGROK_3200 and HTTP 404
for the models endpoint. Live model participation is therefore unproven, and
the live pentest gate must not be started as an AI-success evaluation until the
provider tunnel is restored.

**Rating decision:** unchanged. Removing count ceilings improves execution
flexibility, but implementation tests and a failed provider preflight do not
prove vulnerability recall, precision, validated findings, or report quality.

## LIVE-PHASE1-DYNAMIC-BUDGET-JUICE-SHOP-2026-09-01

**Status:** live-tested; failed acceptance gate; not-proven.

**Environment:** Docker Compose on macOS; authorized local OWASP Juice Shop at
http://host.docker.internal:3001; session scope explicitly allowed
host.docker.internal with allow_private=true; local dolphin3-cyber provider
preflight returned HTTP 200 for health, models, and completion.

**Job:** 1891bbff-f935-4b9f-ac91-af255b4af1f3; session
f8dce27d-51d4-4f14-929d-53f6bc119cd1; durable application status done;
durable execution status succeeded; elapsed 1135.97 seconds; report file
persisted locally.

**Observed live metrics:**

- 73 structured tool runs and 91 compatibility log entries;
- 12 succeeded, 13 partial, and 50 skipped structured runs;
- autonomous trace: 7 cycles, 18 dispatched actions, 5 blocked actions;
- 159 hypotheses, 24 proposals, 6 planner decisions;
- 16 candidates: 5 validated header findings and 11 inconclusive candidates;
- validated types were missing X-XSS-Protection, CSP, HSTS, X-Frame-Options,
  and X-Content-Type-Options;
- 0 private_ip_rejected events in this run;
- 50 skips were explicitly classified as circuit-breaker, provider-query
  disabled, local-lab-not-applicable, raw-network-disabled, or R2-disabled.

**Acceptance failures:**

- 0 durable reasoning_cycles, model_action_traces, and reasoning_model_calls
  rows were persisted for this session. Workflow hypotheses included a small
  number of AI-generation labels and the provider was reachable, but durable
  model participation cannot be credited without those records.
- 11 legacy validation attempts recorded validation_trace_persistence_error:
  validation_runs referenced candidate IDs that were not present in
  candidate_findings. The candidate endpoint therefore showed 5 validated
  statuses while the validation endpoint returned zero validation rows for a
  validated candidate.
- Browser screenshot and human recon were partial due bounded browser timeout.
- The report artifact exists, but the report export endpoint returned HTTP 400
  even though the durable job was done; report delivery is not fully
  consistent across processes.
- No authenticated identity matrix, business-logic chain, retest chain, or
  impact proof was recorded in this run.

**Interpretation:** Dynamic budgeting worked live because the autonomous trace
exceeded the former eight-action ceiling and continued through replanning.
That does not make the pentest pass: skipped applicability is not coverage,
validated status without a durable validation trace is not proof, and job
completion is not vulnerability recall.

**Rating decision:** unchanged. This is a real live result, but it does not
meet the Phase 1 exit criteria.

## PHASE1-BROWSER-RECON-RESILIENCE-2026-09-01

**Status:** implementation verified; scoped live acceptance passed.

**Objective:** fix the two concrete live failures where Browser Screenshot
timed out/returned partial evidence and Human Recon returned an empty or
partial page for a busy SPA. The acceptance scope is execution resilience,
typed outcome truth, and durable browser evidence—not vulnerability recall.

**ECC review:** the relevant vulnerability-scanning workflow skill was used
for evidence-first acceptance criteria. Planck audited the browser and human
recon paths and identified SPA lifecycle over-gating, synchronous model
blocking, raw screenshot transport, missing artifact persistence, and coarse
error/cancellation taxonomy.

**Changes:**

- Browser navigation is commit-first with bounded DOM settle and screenshot
  deadlines; usable DOM is accepted even when a requested SPA lifecycle event
  times out.
- Screenshot PNGs are stored as typed ArtifactV1 records with SHA-256, byte
  size, metadata, timings, and an authenticated content endpoint.
- Supabase Storage upload failure is explicit and falls back to the private
  shared `/app/reports/browser-artifacts` backend; artifact metadata records
  `storage_backend: local_fallback`.
- Human recon uses a bounded DOM probe, preserves network-only page records,
  caches one LLM per crawl, and times out synchronous provider calls without
  killing the crawl.
- Cancellation and browser/recon failure outcomes have typed status/error
  codes, including cross-process durable cancellation visibility.

**Verification:**

```text
Focused browser/recon resilience tests: 17 passed
Full source regression: 302 passed in 386.55s
Python compileall: passed
git diff --check: passed
API/worker ready health: HTTP 200; both containers healthy
```

**Scoped live acceptance:**

- Target: authorized local OWASP Juice Shop at
  `http://host.docker.internal:3001`.
- Session: `59b22f3a-3530-4be0-bb02-8645f360971a`.
- Browser Screenshot run: `run_b675641f9c344b32852f9d3de020a4fb`,
  `succeeded`, screenshot available, no recorded errors.
- Artifact: `art_539d7fc979074b009cebcf945844ab98`, 249315 bytes, PNG content
  endpoint HTTP 200, SHA-256
  `1ea246a99986acbe5442130d3c001fadcc7a705e179e865759ed913c17697ba2`.
- Human Recon run: `run_4a7f4ba7cd3a44d0a0d7718499108fd7`, `succeeded`, one
  `dom_observed` page, six bounded clicks, 43 XHR observations, zero
  navigation timeouts, zero LLM timeouts, one explicit provider-error
  heuristic fallback.

**Known limitations:**

- The broad recon job was stopped after the targeted evidence and is not a
  full-suite pass.
- Supabase Storage still returns HTTP 403 for the configured anon upload
  attempt; the verified artifact path is the private local fallback.
- The outer compatibility wrapper reports `legacy_source=true`; internal
  structured capture and durable metrics are authoritative.
- Browser extraction quality, validation/FK persistence integrity, and
  vulnerability recall remain unproven.

**Rating decision:** unchanged. This is a real scoped pass for browser/recon
execution resilience, not a Phase 1 or world-class capability pass.

## PHASE1-SIX-GAP-CLOSURE-2026-09-01

Status: implementation and regression verified; fresh AI-backed live acceptance
is still pending.

This checkpoint addresses the six blockers recorded after the previous live
Phase 1 gate:

- Reasoning persistence is now strict and typed. Provider-call telemetry is no
  longer silently discarded, and synchronous model invocation has a
  configuration-driven watchdog (`reasoning.invoke_timeout_seconds`).
- Candidate persistence is session-aware and candidate-first. V2 validation
  traces are deferred until the candidate exists; a candidate is staged as
  `inconclusive` and can become `validated` only after a durable successful
  validation run and at least one validation check. Migration
  `024_candidate_validation_integrity.sql` adds a database-level guard.
- Recon skip records now carry `skip_class`, `coverage_required`, denominator
  metrics, and terminal timeout/cancel records. Skip persistence failures
  become `partial` instead of disappearing.
- AI context and final readiness expose two-identity auth prerequisites,
  business workflow/invariant prerequisites, fresh retest evidence, and
  impact-proof results. The model can adapt to explicit missing evidence
  instead of repeatedly proposing blocked actions.
- Report generation no longer treats a historical status-only `validated`
  row as authoritative; durable worker report references and typed
  md/pdf/docx export errors are supported.

Verification:

``@
Focused regression: 76 passed
Full source regression: 326 passed in 141.17s
Python compileall: passed
git diff --check: passed
docker compose config: passed
Docker rebuild/recreate: passed
/health/live: HTTP 200
/health/ready: HTTP 200, mode=autonomous
``@

The rating remains unchanged. This is not yet a live Phase 1 pass: the
Supabase migration must be applied/verified, and a fresh authorized lab run
with the AI provider online is required to prove durable model participation,
validation recall, auth/business chains, retest, and impact evidence.

## PHASE1-ACCEPTANCE-READINESS-GATE-2026-09-01

**Status:** implementation verified; active Supabase migration and AI-backed
live acceptance pending.

**Changes:**

- Added `migrations/025_phase1_acceptance_schema_marker.sql`. It records the
  023/024 markers only after PostgreSQL confirms the required tables and 024
  integrity triggers exist.
- `/health/ready` now fails closed for a missing/invalid Phase 1 marker rather
  than calling an incompletely migrated deployment ready.
- Reasoning cycle, model-call, and model-action-trace writes now require a
  durable query read-back.

**Evidence:**

- Full source regression: `328 passed in 160.39s`.
- PostgreSQL 14 migration/trigger verification passed.
- An invalid `validated` candidate without a durable successful validation run
  was rejected by the 024 trigger.
- Active Supabase probe found the existing acceptance tables but no
  `nexus_schema_migrations` marker table yet.

**Rating decision:** unchanged. This closes the readiness/proof plumbing at
the implementation layer; it does not substitute for applying the migration
or running the fresh AI-backed authorized lab gate.

## PHASE1-ACCEPTANCE-HARDENING-2026-09-01

Status: source and PostgreSQL acceptance checks passed; active Supabase
marker/RPC deployment is pending.

Changes:

- Corrected reasoning persistence read-back to select every field being
  verified, not only the primary key.
- Added a regression for append-only `ignore_duplicates` conflicts so stale
  model-call rows cannot be reported as successfully persisted.
- Strengthened migration 025 with complete acceptance-column checks, enabled
  trigger/function-definition checks, dynamic definition checksums, and the
  `nexus_phase1_acceptance_status()` RPC.
- Rebuilt the API/worker images so the fail-closed readiness behavior is in
  the running containers.

Evidence:

```text
Focused Phase 1 regression: 16 passed
Full source regression: 334 passed in 158.32s
compileall/YAML/compose config/git diff --check: passed
PostgreSQL 14 migration 023->024->025: passed
PostgreSQL status RPC: ready=true
Valid candidate promotion: accepted
Failed-check candidate promotion: rejected and remained inconclusive
Docker rebuild/recreate: passed; API and worker healthy
/health/live: 200
/health/ready: 503, phase1_acceptance_schema=error because active Supabase
  has not received migration 025
```

Interpretation: the implementation no longer hides incomplete database
state, but the live deployment is not yet Phase 1-ready. Apply migrations
023, 024, and 025 in the active Supabase project and rerun the AI-backed
authorized acceptance job. Rating: unchanged.

## PHASE1-CANONICAL-VALIDATION-HARDENING-2026-09-01

The canonical validation lookup no longer has an arbitrary 20-run ceiling,
and a successful validation now requires every persisted check to contain the
real boolean value `true`. This closes the remaining false-success edge in
the application gate and adds a regression for string `"false"` values.

Evidence:

```text
Focused Phase 1 regression: 27 passed
Full source regression: 335 passed in 365.13s
Docker rebuild/recreate: passed; API and worker healthy
/health/live: HTTP 200
/health/ready: HTTP 503 because active Supabase migration 025 is absent
```

Rating remains unchanged. The active Supabase migration and fresh AI-backed
authorized acceptance are still required.

## PHASE1-LIVE-AI-ACCEPTANCE-2026-09-01

Live evidence after the operator applied migrations 023/024/025 and brought
the local model provider online.

```text
Preflight: /health/live 200; /health/ready 200; mode=autonomous
Live lab matrix: 5/5 configured, reachable, surface-ready
Target: local OWASP Benchmark bridge
Session: 51223a6d-8e29-4eba-94a1-9a44a0e0839b
Job: 509da2db-b43b-441b-9545-912409a8c780
Terminal: durable done; 1513.8s; hard errors 0
Durable tool runs: 68 = 51 succeeded, 17 skipped, 0 partial/failed
Reasoning cycles: 5 succeeded; model calls 3 succeeded, 2 failed
Model action traces: 10 = 2 valid, 8 invalid
Observations: 75; candidates: 12 = 5 validated, 7 inconclusive
Validated candidates with durable passed checks/evidence: 5/5
Report quality: ready; 10 grounded claims; redaction leaks 0
Exports before/after API restart: md/pdf/docx HTTP 200
```

The 5 validated records passed the current typed exposure validation policy,
but this run did not provide two authenticated identities, business-state
transitions, fresh retest observations, or impact/cleanup proof. Three
required recon tools were policy-blocked by `r2_active_disabled`; 5 evidence
gaps remained open; no adaptation records were created. The model-generated
narrative also contained unsupported negative/positive wording, so the
structured candidate/validation pipeline remains the authority.

First launch attempt without `POST /sessions` was rejected with
`Session scope context not found`; this was correct fail-closed behavior. The
fresh run used the official session setup plus exact local-lab scope.

Decision: real partial live acceptance; Phase 1 and rating unchanged.

Additional report audit: the latest narrative contained 10 claim IDs, while
four report-generation/read cycles left 40 durable `report_claims` rows under
the same report ID. Export remained restart-safe, but claim upsert/idempotency
needs a follow-up before report persistence can be called fully consistent.

## CANONICAL-CONTEXT-MEMORY-2026-09-01

**Purpose:** Prevent phase-name and project-goal drift when Nexus work resumes
after context compaction or a later run.

**Change:** Added [`NEXUS_CONTEXT_MEMORY.md`](NEXUS_CONTEXT_MEMORY.md) as the
canonical project-memory file. It records the product vision, the official
Phase 0–6 plan, the five Phase 1 sub-phases, locked evaluation decisions,
current status, and the resume protocol. `PROJECT_HANDOFF.md` now points to it.

**Verification:** `git diff --check` passed; the file contains no secrets.

**Rating decision:** `unchanged`. This is context/governance maintenance and
does not claim a capability improvement.

## EVENT-LOG-MAINTENANCE-2026-09-01

The project now maintains [`NEXUS_EVENT_LOG.md`](NEXUS_EVENT_LOG.md) as an
append-only record for every run/testing session, upgrade, bug, gap, fix,
decision, and verification. Each entry must identify the phase/sub-phase,
environment, command or endpoint, result, evidence, rating impact, and
remaining work. This is a memory and auditability rule; it does not change the
capability rating.

## PHASE1-EXECUTION-FOUNDATION-LIVE-2026-09-02

This was a fresh live acceptance verification after the operator restarted the
local AI provider and recreated the API/worker containers. No new source patch
was claimed in this entry; the turn verified the already-landed 1C–1E
hardening and exercised the 1F gate.

Environment and procedure:

- macOS Docker Compose runtime; API and worker rebuilt/recreated from source.
- `/health/ready`: HTTP 200, `mode=autonomous`, Supabase and Phase 1 schema ok.
- Local OWASP Benchmark bridge from inside the API container: HTTP 200.
- Official `POST /sessions` setup with `authorization_confirmed=true`, exact
  `host.docker.internal` allow rule, and `allow_private=true`; then full
  `POST /pentest` with Dolphin3-Cyber and autopilot.

Live result:

- Job `616a8efb-ab44-4da1-af67-437e9bd5fe3e`, session
  `ccaa00a9-f119-4143-ac8c-5f2222f9baa6`.
- Terminal status: `error`; execution-integrity failure on
  `browser_find_open_redirect` with durable `tool_timeout`.
- 16 durable tool runs: 15 succeeded, 1 failed; 5 cycles: 1 succeeded,
  4 failed; 5 model calls: 1 succeeded, 4 failed.
- 13 actions were traced, with 3 blocked actions; 14 candidates were created,
  1 validated and 13 inconclusive. No report/export acceptance was available
  after the fail-closed terminal state.

The earlier launch attempt `f99961fd-3d68-40ff-a281-be82f88d2f3a` was rejected
before execution because a legacy session had no `session_context`. That is a
diagnostic of the old entry path, not a vulnerability result.

Decision: the private-lab transport path is proven when the session carries the
explicit private opt-in, but 1F failed. Rating unchanged. Remaining work is
browser timeout recovery, stable model protocol/action output, and a fresh
acceptance run that reaches report/export without integrity failure.

## PHASE1-EXECUTION-FOUNDATION-HARDENING-2026-09-02

**Scope:** Phase 1 — AI-native architecture; Execution Foundation 1C–1F.

Implemented cooperative browser timeout/partial semantics, strict later-success
retry reconciliation for the execution-integrity gate, and durable explicit
failure outcomes for AI-expected actions whose dispatch callback is missing.
Docker regression passed **113 tests**; the API/worker were rebuilt/recreated;
readiness and local Benchmark transport were HTTP 200.

Fresh live job `10394abf-8111-41da-9f2c-3a66f2c28f93` completed `done` in
925.36 seconds. Audit: 64 non-narrative runs (47 succeeded, 1 partial, 0
failed, 16 skipped), zero private-IP rejections, six candidates with five V2
validated evidence-linked records, and Markdown/PDF/DOCX exports all HTTP 200.
The browser timeout remained typed partial and did not abort the job.

The configured Dolphin endpoint returned ngrok HTML 404 for all provider
routes. Both durable reasoning cycles/model calls failed `NotFoundError`, so
zero AI actions/traces were produced and deterministic fallback performed the
scan. 1C/1E behavior is live-proven; 1F remains **failed** and the rating is
unchanged. Next run requires a live provider health/models/completion preflight.

## LIVE-PHASE1-EXECUTION-FOUNDATION-FRESH-AI-2026-09-02

**Type:** live verification / gap discovery  
**Scope:** Phase 1 — AI-native architecture; Execution Foundation 1A–1F  
**Environment:** macOS Docker Compose, authorized local OWASP Benchmark
bridge, full/autopilot, Dolphin3-Cyber provider online

Preflight passed: API `/health/ready` HTTP 200 with Supabase and Phase 1 schema
healthy; worker healthy; Benchmark HTTP 200; provider root `/health` HTTP 200,
`/v1/models` HTTP 200, and `/v1/chat/completions` HTTP 200.

Live evidence: session `f05255e6-d7a3-45de-8e6f-6faddb28d2f2`, job
`c1a01b11-09b4-4581-8eeb-d2ba3a1c8b6f`. The job ran 69 durable tool-runs:
46 succeeded, 4 partial, 1 failed, and 18 skipped. No private-IP rejection
occurred. The one failed run was `browser_find_open_redirect`, durable
`tool_timeout`, and it triggered the execution-integrity gate. Its four other
same-tool attempts were typed partial, but no later successful same-target run
closed the failure.

AI telemetry: 5 reasoning cycles and 5 model calls were durable; all five
model calls failed `_GatewayProtocolError` despite the provider smoke preflight
passing. No AI hypotheses, model-selected actions, or model action traces were
created. The execution trace contained 13 actions and 4 blocked actions from
the fallback/analysis path.

Validation/report telemetry: 12 candidates were persisted; 5 had validated
candidate/validation decisions and 7 were inconclusive. Validation decisions
totaled 5 validated and 47 inconclusive across retries/controls. The workflow
report was durable with 5 finding IDs, 10 grounded claims, and zero redaction
leaks. Job-level Markdown/PDF/DOCX exports returned HTTP 409 because the job
was `error`; this is not an export pass.

**Result:** failed 1F; rating unchanged. 1A transport and durable failure /
validation recording are evidenced. AI-native reasoning participation and
retryable browser recovery are not proven. Next work must address the real
Dolphin JSON/protocol contract and timeout recovery, then repeat the same live
gate. Do not treat the five low/info configuration findings as Benchmark
recall or as proof that the target is clean.

## PHASE1-EXECUTION-FOUNDATION-1F-CORRECTED-AI-LIVE-2026-09-02

**Type:** live verification / gap discovery  
**Scope:** Phase 1 — AI-native architecture; Execution Foundation 1A–1F  
**Environment:** macOS Docker Compose; authorized local OWASP Benchmark bridge;
full/autopilot; Dolphin3-Cyber provider

Preflight passed: API readiness, worker health, Benchmark HTTP 200, provider
'/health', '/v1/models', and post-run completion all HTTP 200. Session
'247d5603-95b2-46bf-b4cf-c560372cc55c'; job
'13d7e512-7282-4820-936a-2c4b232c7b0a'; terminal 'done'; 1625.30 seconds.

Measured result:

- 70 durable endpoint rows (68 structured runs plus phase markers):
  47 succeeded, 5 partial, 0 failed, and 18 skipped.
- 0 private-IP rejections, 0 missing dispatch outcomes, and 0 validation
  persistence errors.
- Six successful durable reasoning cycles/model calls; 13 execution-trace
  actions and 4 blocked actions; three model-action traces.
- 12 candidates: 5 validated with linked evidence, 7 inconclusive.
- Structured report ready with 5 finding IDs, 10 grounded claims, quality 1.0,
  zero redaction leaks; report and Markdown export HTTP 200.
- Repeated report reads preserved 10 claim rows, proving current report
  idempotency.
- Full regression: 363 passed, 9 warnings.

Remaining gaps:

- Five 'browser_find_open_redirect' runs returned typed partial evidence and
  no later same-target success exercised recovery reconciliation.
- One 'mixed_content_scanner' skipped row had no typed error reason.
- The legacy/CrewAI assessor logged two ngrok gateway errors, although the
  structured report fallback completed and persisted.
- Hidden-label recall/precision and later-phase auth, business-logic, retest,
  and impact proof remain outside this acceptance.

**Decision:** partial live acceptance; 1F is **not passed** under the rule that
partial/inconclusive outcomes cannot be credited as pass. The run materially
proves the prior AI-telemetry, private-transport, validation-FK, report
idempotency, and dispatch-outcome blockers are resolved in this environment,
but rating remains unchanged.

## PHASE1-EXECUTION-FOUNDATION-1C-1F-IMPLEMENTATION-HARDENING-2026-09-02

**Type:** implementation / regression verification  
**Scope:** Phase 1 — AI-native architecture; Execution Foundation 1C–1F  
**AI provider:** intentionally offline; live acceptance deferred until the
operator starts Dolphin3-Cyber

Implemented the planned gap closure:

- Structured tool results now fail closed with typed diagnostics for failed,
  partial, cancelled, and skipped outcomes; recon skip rows include explicit
  reason/class/coverage metadata and a typed `tool_skipped` error.
- Browser open-redirect probing observes encoded cases through response and
  navigation signals, aborts external canary navigation, accounts for all
  planned parameters adaptively, and returns typed partial/failed diagnostics
  on timeout instead of a bare/ambiguous result.
- Retryable read-only failures can be recovered by a bounded retry. The retry
  stores `metrics.recovery.recovered_from_run_id` and the acceptance evaluator
  reconciles the earlier attempt only when that durable relationship exists.
- Final assessment was moved to the canonical provider-agnostic
  `ReasoningGateway`; model-call/cycle/action telemetry and missing dispatch
  outcomes stay auditable.
- The 1F evaluator is fail-closed for unresolved failures/partials, untyped or
  coverage-required skips, missing AI telemetry, missing recovery proof,
  validation persistence errors, evidence-less validated candidates, report
  quality failures, and legacy assessor errors.
- `auto` reasoning limits preserve valid model hypotheses/actions within the
  explicit resource envelope rather than silently applying an arbitrary count.

Verification:

- Docker build: passed for API and worker images.
- Focused suite: **60 passed**.
- Full worker-image regression: **377 passed, 10 warnings**.
- Recreated API/worker: `/health/live` HTTP 200; `/health/ready` HTTP 200;
  autonomous mode, Supabase, durable schema, and Phase 1 acceptance schema
  all reported healthy.

**Result:** implementation and regression verified. 1F live acceptance remains
pending and the rating is unchanged. The next live run must start the local AI
provider and prove the complete durable gate; no live vulnerability result is
credited by this entry.

## PHASE1-EXECUTION-FOUNDATION-1F-LIVE-2026-09-02

**Type:** live acceptance run  
**Environment:** macOS Docker Compose; Dolphin3-Cyber provider reachable through
Google Colab/ngrok; OWASP Benchmark at
`http://host.docker.internal:8446/benchmark/`  
**Session/job:** `234e2969-265b-4f02-a238-7bd1084e39b8` /
`c356fb34-722b-4bae-b6df-5dcb88fd7644`

The run was executed after correcting the authorized local-lab scope to include
`allow_private: true`. Preflight passed for API, worker, target, and the model
contract (provider `/models` and contract-shaped completion both HTTP 200). The
run lasted `1973.606959` seconds and persisted 66 authoritative tool rows:
47 succeeded, 1 partial, 2 failed, and 18 skipped. No `private_ip_rejected`
occurred in the corrected run. The trace persisted 3 reasoning cycles, 3 model
calls, 2 model action traces, and 11 actions.

The fail-closed 1F evaluator returned **FAIL**. The concrete blockers were:

- `param_discovery_get` and `param_discovery_headers` returned
  `legacy_tool_failed` proxy diagnostics;
- `browser_find_open_redirect` returned a retryable partial timeout;
- `param_discovery_post`, `wp_scanner`, and `dir_bruteforce_scanner` were
  skipped with `coverage_required: true`;
- one reasoning cycle/model call failed, so durable AI telemetry was incomplete;
- no dedicated recovery fixture produced a durable `recovered_from_run_id`;
- report generation was HTTP 200 and quality-ready (score 1.0, 9 grounded
  claims, zero redaction leaks), but Markdown export returned HTTP 409 because
  the job ended in error.

The run produced 9 candidates: 5 validated and 4 inconclusive. All 5 validated
records had evidence IDs, but these are observed Benchmark misconfiguration/
header records—not hidden-label recall or proof that the Benchmark is clean.
Rating remains unchanged. This entry does not claim Phase 1 passed.

## PHASE1-EXECUTION-FOUNDATION-CODE-REVIEW-2026-09-03

**Type:** code review / upgrade / regression verification  
**Scope:** Phase 1 — AI-native architecture; Execution Foundation 1C–1F  
**Review basis:** Full code-surface inventory plus ECC audits by Carson, Kant,
and Volta. Inventory: 247 code files (240 Python, 7 TypeScript/JavaScript
family) and 58 test files.

### Architectural findings closed

- The canonical `full` and `recon-only` paths no longer construct the legacy
  CrewAI/provider graph; legacy remains an explicit compatibility path only.
- Ambient proxy inheritance was removed from guarded HTTP; only an exact
  operator proxy can be used.
- Parameter-discovery failures, recon skips, browser timeouts, and structured
  runner outcomes preserve typed diagnostics and status semantics.
- Read-only recovery is shared between recon and the AI loop and persists
  `recovered_from_run_id`.
- Browser redirect deadlines derive from actual case workload.
- ReasoningGateway retries only transient provider transport failures once by
  default, with explicit configurable backoff; malformed model output is not
  retried. Retry versus fallback provider metadata is durable and distinct.
- Config overrides are recursively merged and copied into each job snapshot.
- The acceptance evaluator verifies actual recovery and lineage rather than
  trusting arbitrary string links; circuit-breaker skips are operationally
  typed without becoming fake required coverage.

### Verification

- Syntax compilation: passed.
- Focused Execution Foundation suite after final patch: **75 passed**.
- Full repository regression: **387 passed, 9 warnings** in 167.83 seconds.
- `git diff --check`: passed.
- Runtime config and scorecard YAML parse: passed.
- Static raw-transport check: no unguarded requests/httpx imports in tool or
  engine source outside designated boundary modules.

### Decision

Implementation and regression are verified. **Live 1F remains unproven and the
rating is unchanged.** The next step is a fresh authorized OWASP Benchmark
provider-backed run after the operator starts the local Dolphin3-Cyber service.
That run must verify provider preflight, durable AI cycles/calls/traces,
typed tool outcomes, real retry recovery, report/export, and the machine 1F
gate. This entry does not claim vulnerability recall, precision, or a clean
target.

## PHASE1-EXECUTION-FOUNDATION-CODE-VERIFICATION-2026-09-03-R2

**Type:** code hardening / local verification  
**Scope:** Phase 1 — AI-native architecture; Execution Foundation 1C–1F  
**Provider/target:** intentionally offline; no live provider or target
workflow executed.

### Changes

- Bounded worker RPC and telemetry retries no longer kill the worker on a
  transient persistence failure.
- Legacy cancellation and command errors are typed; partial actions cannot
  yield a successful mission.
- Canonical V2 validation is required for promotion and pending validation
  batches are scoped to their session.
- Acceptance requires durable same-session evidence verification.
- Readiness runs off the async event loop; browser local-lab access uses exact
  origin authorization plus request/response accounting.
- Authorized local-lab discovery defaults cover the previously required
  read-only tools.

### Verification

- Docker build: passed for API and worker images.
- Focused suite: **83 passed**.
- Full regression: **398 passed, 9 warnings**.
- Python compile, YAML parse, and `git diff --check`: passed.
- Recreated runtime: API/worker healthy; `/health/live` 200;
  `/health/ready` 200; all readiness checks `ok`.
- API import boundary: 64.31 seconds; CrewAI, LangChain, and model registry
  were not eagerly imported.

### Decision

Implementation/regression verified; **live 1F remains unproven** because the
provider was offline. Rating unchanged. No vulnerability recall, precision,
target cleanliness, or full autonomous attack-chain capability is credited.
