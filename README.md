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
| **Browser** | Playwright (headless Chromium) |
| **AI Models** | GLM 5.2, DeepSeek V4, Claude, GPT via OpenRouter |
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
| `STEALTH_MODE` | ❌ | `1` for evasive mode (0.5 req/s) |
| `AUTO_PILOT` | ❌ | `1` to skip HITL approval |

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/pentest` | Start new pentest scan |
| `GET` | `/job/{job_id}` | Poll job status |
| `GET` | `/job/{job_id}/stream` | SSE real-time stream |
| `POST` | `/job/{job_id}/cancel` | Cancel running job |
| `POST` | `/job/{job_id}/continue` | Continue to next phase |
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

