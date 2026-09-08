# Nexus AI — Autonomous Pentest Agent

> AI-powered penetration testing platform using multi-agent architecture for autonomous web security assessment.

## Overview

Nexus AI is an autonomous penetration testing platform that runs **4 AI agents** in a phased pipeline (Recon → Vulnerability Analysis → Exploitation → Risk Assessment) to discover, exploit, and report web vulnerabilities independently — mimicking a real Red Team workflow.

### Key Features

- **Autonomous Scanning** — 87 built-in security tools + 15 external tools integrated
- **Multi-Agent Architecture** — 4 agents (Recon, Analyst, Executor, Assessor) with specific models
- **60+ Vulnerability Types** — SQLi, XSS, SSRF, XXE, SSTI, IDOR, CSRF, and more
- **Human-in-the-Loop** — Approval checkpoints for high-risk actions
- **Auto-Login** — Automatic login wall detection and credential request
- **Stealth Mode** — Random delays, rotating UAs, slower scan rate
- **Scope Rules** — Whitelist/blacklist targets via Supabase
- **WAF Detection** — Auto-detect WAF and adjust scanning strategy
- **Professional Reports** — Export to Markdown, PDF, and DOCX

## Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11, FastAPI, CrewAI, LangChain |
| **Frontend** | Next.js 16, React 19, TypeScript, Tailwind CSS |
| **Database** | Supabase (PostgreSQL) |
| **Browser** | Playwright (headless Chromium) + mitmproxy passive |
| **AI Models** | GLM 5.2, DeepSeek V4, Claude, GPT via OpenRouter + Local (Kaggle/Colab ngrok) |
| **Infrastructure** | Docker, docker-compose |

## External Tools Integrated

| Tool | Function | Integrated In |
|---|---|---|
| **nuclei** | Template-based vulnerability scanning | `nuclei_tool.py` |
| **sqlmap** | SQL injection detection & exploitation | `custom_tools.py` |
| **commix** | Command injection exploitation | `command_injection.py` |
| **dalfox** | XSS detection | `xss_advanced.py` |
| **tplmap** | SSTI exploitation | `ssti_tester.py` |
| **gobuster** | Directory brute-force | `dir_bruteforce.py` |
| **ffuf** | Web fuzzing | `dir_bruteforce.py` |
| **testssl.sh** | SSL/TLS testing | `ssl_scanner.py` |
| **jwt_tool** | JWT token analysis | `auth_testing.py` |
| **arjun** | Parameter discovery | `param_discovery.py` |
| **hydra** | Password brute-force | `auth_recon_tools.py` |
| **katana** | Web crawling | `web_crawler.py` |
| **graphql-cop** | GraphQL security testing | `graphql_tester.py` |
| **subfinder** | Subdomain enumeration | `recon_advanced.py` |
| **httpx** | Live host probe | `hunter_pipeline.py` |
| **naabu** | Port scanning (fast) | `hunter_pipeline.py` |
| **gowitness** | Screenshot utility | `hunter_pipeline.py` |
| **gau** | Historical URL gathering | `hunter_pipeline.py` |
| **hakrawler** | JS endpoint crawling | `hunter_pipeline.py` |
| **amass** | Asset discovery | `hunter_pipeline.py` |
| **mitmproxy** | Passive traffic capture | `mitm_passive.py` |
| **nmap** | Port scanning | `recon_advanced.py` |

## Vulnerability Coverage

| Category | Types | Tools |
|---|---|---|
| **Injection** | SQLi, NoSQLi, XSS, SSTI, CMDi, LDAP, XPath, XXE | 19 types |
| **Auth & Session** | Session Fixation, JWT Weakness, 2FA Bypass, OAuth | 14 types |
| **Access Control** | IDOR, Privilege Escalation, Mass Assignment | 9 types |
| **Client-Side** | Clickjacking, CORS, Reverse Tabnapping, Prototype Pollution | 7 types |
| **Server-Side** | SSRF, LFI/RFI, Deserialization, File Upload | 9 types |
| **Recon & Infra** | Misconfiguration, Subdomain Takeover, DNS Rebinding | 11 types |

**Total: 60+ vulnerability types**

## Installation

### Docker (Recommended)

```bash
# Clone repository
git clone <repo-url> && cd hellyeah

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Build and run
docker-compose up --build

# Backend: http://localhost:8000
# Frontend: http://localhost:3000
```

### Manual Installation

```bash
# Backend
pip install -r requirements.txt
playwright install chromium
playwright install-deps

# External tools
apt install nmap hydra -y
pip install sqlmap arjun
git clone https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap
git clone https://github.com/commixproject/commix.git /opt/commix
# ... (see Dockerfile for complete list)

# Run backend
uvicorn api:app --host 0.0.0.0 --port 8000

# Frontend
cd frontend-pentest
npm install
npm run dev
```

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `OPENROUTER_API_KEY` | ✅ | API key for LLM access |
| `SUPABASE_URL` | ✅ | Supabase project URL |
| `SUPABASE_KEY` | ✅ | Supabase anon key |
| `NEXUS_API_KEY` | ✅ | API authentication key |
| `SHODAN_API_KEY` | ❌ | Shodan API key (OSINT) |
| `CENSYS_PAT` | ❌ | Censys Personal Access Token |
| `GITHUB_TOKEN` | ❌ | GitHub token for secret dorking |
| `TOKENHUB_API_KEY` | ❌ | Tencent TokenHub API key |
| `NEXUS_LOCAL_LLM_ENABLED` | ❌ | `true` to enable local model |
| `NEXUS_LOCAL_LLM_BASE_URL` | ❌ | ngrok URL for local LLM |
| `NEXUS_LOCAL_LLM_API_KEY` | ❌ | dummy key for local |
| `NEXUS_LOCAL_LLM_MODELS` | ❌ | comma-separated local model slugs |
| `STEALTH_MODE` | ❌ | `1` for evasive mode (0.5 req/s) |
| `AUTO_PILOT` | ❌ | `1` to skip HITL approval |
| `NEXUS_AUTH_VAULT_KEY` | ✅ for identity secrets | Random base64/hex key for encrypted engagement-scoped auth material |


## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/pentest` | Start new pentest scan |
| `GET` | `/job/{job_id}` | Poll job status |
| `GET` | `/job/{job_id}/stream` | SSE real-time stream |
| `GET/POST` | `/sessions/{session_id}/identities` | Manage isolated authorization identities |
| `POST` | `/sessions/{session_id}/authorization/discover` | Persist runtime request/resource discovery |
| `POST` | `/sessions/{session_id}/authorization/replays` | Run evidence-linked differential replay |
| `POST` | `/job/{job_id}/cancel` | Cancel running job |
| `POST` | `/job/{job_id}/continue` | Continue to next phase |
| `POST` | `/sessions/{session_id}/workflow/plan` | Recompute evidence-driven hypotheses and next-test proposals |
| `GET` | `/sessions/{session_id}/workflow/hypotheses` | Inspect belief, status, evidence, and test budget per hypothesis |
| `GET` | `/sessions/{session_id}/workflow/planner-decisions` | Inspect deterministic ranking and skip/stop reasons |
| `GET` | `/job/{job_id}/report.md` | Download report |
| `GET` | `/job/{job_id}/export` | Export (md/pdf/docx) |
| `POST` | `/checkpoint/respond` | Approve/reject HITL |
| `POST` | `/auth/respond` | Submit credentials |
| `GET` | `/sessions` | List sessions |
| `POST` | `/sessions` | Create setup wizard session |
| `GET` | `/sessions/{session_id}/context` | Load target, goal, scope, and TargetState |
| `POST` | `/sessions/{session_id}/messages` | Send a natural-language chat message |
| `POST` | `/scope-rules` | Create scope rule |
| `GET` | `/sessions/{session_id}/workflow` | Load workflow state |
| `POST` | `/sessions/{session_id}/workflow/plan` | Generate evidence-driven next-step proposal |
| `POST` | `/sessions/{session_id}/workflow/actions/{action_id}/approve` | Approve a proposed action |
| `POST` | `/sessions/{session_id}/workflow/actions/{action_id}/reject` | Reject a proposed action |
| `GET` | `/sessions/{session_id}/workflow/progress` | Read objective progress |
| `POST` | `/sessions/{session_id}/workflow/evidence` | Store redacted evidence |
| `POST` | `/sessions/{session_id}/workflow/cleanup` | Register cleanup work |
| `POST` | `/sessions/{session_id}/workflow/retest` | Start finding retest |
| `POST` | `/sessions/{session_id}/workflow/retest/result` | Record bounded retest result |
| `POST` | `/sessions/{session_id}/workflow/impact-proof` | Propose bounded impact proof |
| `POST` | `/sessions/{session_id}/workflow/impact-proof/result` | Record impact-proof evidence |
| `GET` | `/sessions/{session_id}/workflow/report` | Generate evidence-linked report |
| `GET` | `/sessions/{session_id}/jobs/latest` | Restore latest durable job |


## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (Next.js)                     │
│              Chat UI + Scan Config + Reports              │
└───────────────────────────┬─────────────────────────────┘
                            │ API Calls
                            ▼
┌─────────────────────────────────────────────────────────┐
│                 Backend (FastAPI + CrewAI)                │
│                                                          │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐ │
│  │  Recon   │→ │ Analyst  │→ │ Executor │→ │ Assessor │ │
│  │  Agent   │  │  Agent   │  │  Agent   │  │  Agent   │ │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘ │
│       │              │             │              │       │
│       ▼              ▼             ▼              ▼       │
│  ┌─────────────────────────────────────────────────────┐ │
│  │           87 Custom Tools + 15 External Tools       │ │
│  │   sqlmap | dalfox | commix | nuclei | nmap | ...    │ │
│  └─────────────────────────────────────────────────────┘ │
└───────────────────────────┬─────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────┐
│                     Supabase (PostgreSQL)                 │
│          Sessions | Messages | Scope Rules | Memory       │
└─────────────────────────────────────────────────────────┘
```

## Stealth Mode

Enable via frontend toggle or environment variable:

```bash
# Via environment
STEALTH_MODE=1

# Or via frontend toggle (next to Auto-Pilot)
```

**Stealth mode activates:**
- Rate limit: 0.5 req/s (down from 2.0 req/s)
- Random delay: 1.5-6s between requests
- Random User-Agent rotation
- External tools: `--random-agent`, `--delay=1`, `--threads=1`
- Nuclei: `-rl 10`, `-bs 3`, `-delay 1s`

## Auto-Pilot Mode

Enable via frontend toggle:

```bash
# All HITL approvals auto-approved
AUTO_PILOT=1
```

## False Positive Reduction

The platform uses multiple techniques to reduce false positives:

| Technique | Impact |
|---|---|
| Tightened Error Patterns | -30% FP |
| Baseline Exclusion | -40% FP |
| Body Change Gate | -20% FP |
| Confirmation Step (safe payload) | -30% FP |
| Temporal Consistency (3x request) | -15% FP |
| Semantic Response Diff | -10% FP |
| Application Fingerprinting | Framework-aware detection |
| External Tool Verification | sqlmap/dalfox/commix confirmation |
| Entropy Analysis | High entropy diff detection |

**Overall FP Reduction: ~70-80%**

## Report Format

Reports available in 3 formats:
- **Markdown** (GFM) — Default, with severity badges and collapsible sections
- **PDF** — Via fpdf2 library
- **DOCX** — Via python-docx library

## Current Implementation and Evaluation Status

The sections above describe the original product vision, configured coverage,
and tool catalog. The current implementation has evolved into an AI-native
execution architecture:

```text
Next.js UI
    │
    ▼
FastAPI API ───────────────► Supabase/PostgreSQL
    │                         durable sessions, jobs,
    │                         evidence, validation, telemetry
    ▼
Durable execution worker
    │
    ├── AI Reasoning Gateway
    │      hypotheses, next actions, adaptation, retest proposals
    ├── Scope / authorization / lifecycle controls
    ├── Structured HTTP, browser, recon, auth, API, and OOB tools
    └── Evidence → validation → report pipeline
```

The AI model is the reasoning and planning layer. It proposes hypotheses and
actions, while scope enforcement, action accounting, evidence integrity,
validation, cancellation, cleanup, and durable audit records remain outside
the model. A successful provider health check is not the same as a validated
finding.

Current Docker services:

| Service | Role | Default port |
|---|---|---:|
| `pentest-ai-backend` | FastAPI control plane and API | `8000` |
| `nexus-worker` | Durable background execution | internal |
| `nexus-frontend` | Next.js operator UI | `3000` |

The local provider is OpenAI-compatible and can run on an authorized Kaggle or
Colab GPU runtime through `NEXUS_LOCAL_LLM_BASE_URL`. Provider availability is
separate from backend readiness.

Use Nexus only against targets you own or are explicitly authorized to test.
The platform records scope and lifecycle state, supports cancellation and
cleanup, redacts sensitive material, and fails closed when authorization or
evidence is insufficient.

### Repository layout

```text
core/                   orchestration, reasoning, validation, persistence
tools/                  security-tool adapters and structured runners
engines/                reusable analysis engines
benchmarks/             benchmark fixtures and evaluators
tests/                  regression and acceptance tests
config/                 runtime and toolchain configuration
migrations/             additive database migrations
frontend-pentest/       Next.js operator interface
docs/                   handoff, memory, ledger, event log, and scorecard
results/                reviewed benchmark and stage artifacts
scripts/                repository maintenance utilities
stored_reports/         local runtime reports; ignored by Git
```

### Evaluation commands

Repeatable stage results are kept under `results/stages/`:

```bash
python -m core.evaluation_cli run \
  --suite stage27-recon-closure \
  --mode deterministic \
  --trials 3 \
  > results/stages/stage27-result.json
```

For an explicitly authorized local-lab matrix:

```bash
python -m core.live_lab_matrix --confirm
```

This matrix proves reachability and surface only; it is not a substitute for
full vulnerability detection, authenticated workflows, or hidden-label
benchmark evaluation.

### Project records

- [`docs/PROJECT_HANDOFF.md`](docs/PROJECT_HANDOFF.md) — architecture, scope,
  decisions, and current handoff.
- [`docs/NEXUS_CONTEXT_MEMORY.md`](docs/NEXUS_CONTEXT_MEMORY.md) — persistent
  Phase 0–6 roadmap and resume context.
- [`docs/NEXUS_UPGRADE_LEDGER.md`](docs/NEXUS_UPGRADE_LEDGER.md) — upgrade
  history, evidence, and limitations.
- [`docs/NEXUS_EVENT_LOG.md`](docs/NEXUS_EVENT_LOG.md) — append-only project
  event log.
- [`docs/NEXUS_SCORECARD.yaml`](docs/NEXUS_SCORECARD.yaml) — evaluation
  criteria and rating decisions.
- [`results/README.md`](results/README.md) — generated-artifact policy.

The current scorecard keeps unproven areas—such as authenticated identity
matrices, deep business-logic chains, impact proof, and full live-lab recall—
separate from code-only test results. Phase 1F live acceptance remains an
explicit evidence gate and is not marked passed until a live provider run
proves durable reasoning, dispatch, tool outcomes, and validation integrity
together.
