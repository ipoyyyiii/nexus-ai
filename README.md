# Nexus AI — Autonomous Pentest Agent

> AI-powered penetration testing framework with 88+ security tools, phase-by-phase execution, authenticated scanning, and professional report generation.

![Python](https://img.shields.io/badge/Python-3.11+-blue?logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.109+-green?logo=fastapi)
![Next.js](https://img.shields.io/badge/Next.js-16-black?logo=next.js)
![CrewAI](https://img.shields.io/badge/CrewAI-0.28+-orange)

---

## Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before testing any target. The authors are not responsible for any misuse of this software.

---

## Features

- **88+ Security Tools** — SQLi, XSS, SSRF, IDOR, SSTI, XXE, Command Injection, and more
- **50/50 Vulnerability Benchmark Coverage** — OWASP Top 10, CWE Top 25, and custom checklist
- **Phase-by-Phase Execution** — Recon → Analysis → Exploitation → Risk Assessment
- **Human-in-the-Loop** — Interactive approval at each phase with auto-pilot option
- **Authenticated Scanning** — Auto-login, session injection, login wall detection
- **OOB Detection** — Private interactsh server integration (whoopbhapzham.my.id)
- **WAF Detection** — Auto-detect Cloudflare, AWS WAF, ModSecurity, Imperva, and adjust strategy
- **Stealth Engine** — TLS fingerprint spoofing, UA rotation, request jitter
- **Professional Reports** — GFM Markdown, PDF, DOCX export with severity badges
- **Scan History** — Track and compare scans over time

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Frontend (Next.js)                     │
│  Sidebar │ Chat Area │ Scan Config │ Auth Banner │ Export │
└───────────────────────┬─────────────────────────────────┘
                        │ REST + SSE
┌───────────────────────▼─────────────────────────────────┐
│                    Backend (FastAPI)                      │
│  api.py → Agent Orchestration → Background Workers       │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│               4 CrewAI Agents (Sequential)               │
│  Recon → Analis → Eksekutor → Assessor                   │
└───────────────────────┬─────────────────────────────────┘
                        │
┌───────────────────────▼─────────────────────────────────┐
│              88+ Tools + 17 Infrastructure Modules        │
│  tools/    │ engines/    │ core/                          │
│  31 tools  │ 8 engines   │ 15 modules                     │
└─────────────────────────────────────────────────────────┘
```

---

## Quick Start

### Prerequisites
- Docker & Docker Compose
- OpenRouter API key (or TokenHub Tencent Cloud key)

### Installation

```bash
# Clone the repository
git clone https://github.com/your-username/nexus-ai-pentest.git
cd nexus-ai-pentest

# Configure environment
cp .env.example .env
# Edit .env with your API keys

# Start with Docker
docker compose up --build -d
```

### Environment Variables

```env
# Required
OPENROUTER_API_KEY=sk-or-v1-...
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your-anon-key
NEXUS_API_KEY=your-api-key

# Optional (TokenHub)
TOKENHUB_API_KEY=sk-...
TOKENHUB_API_BASE=https://tokenhub-intl.tencentcloudmaas.com/v1

# Optional (External Services)
SHODAN_API_KEY=your-shodan-key
CENSYS_PAT=your-censys-pat
GITHUB_TOKEN=your-github-token
```

### Access

- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs

---

## Project Structure

```
nexus-ai-pentest/
├── api.py                    # FastAPI entry point
├── agent.py                  # CLI entry point
├── .env                      # Environment variables
├── requirements.txt          # Python dependencies
├── Dockerfile                # Backend Docker config
├── docker-compose.yml        # Docker orchestration
│
├── core/                     # Infrastructure (15 files)
│   ├── checkpoint.py         # HITL approval flow
│   ├── cancellation.py       # Job cancellation tokens
│   ├── rate_limiter.py       # Per-domain rate limiting
│   ├── auth_store.py         # Authenticated session storage
│   ├── model_registry.py     # LLM model registry & fallback
│   └── ...
│
├── tools/                    # Security scanners (31 files)
│   ├── custom_tools.py       # Core recon & injection tools
│   ├── playwright_tools.py   # Browser-based tools
│   ├── ssrf_idor_tools.py    # SSRF & IDOR scanners
│   ├── injection_advanced.py # Blind SQLi, NoSQL, LDAP, XPath
│   ├── xss_advanced.py       # Stored, DOM, JSONP XSS
│   └── ...
│
├── engines/                  # Shared engines (8 files)
│   ├── oob_engine.py         # Out-of-band interaction
│   ├── stealth_engine.py     # Anti-detection evasion
│   ├── waf_detector.py       # WAF fingerprinting
│   ├── response_differ.py    # Semantic response comparison
│   └── ...
│
└── frontend-pentest/         # Next.js frontend
    └── app/
        ├── page.tsx          # Main dashboard (single file)
        └── markdown-components.ts  # Report rendering
```

---

## Tools Reference

### Reconnaissance (11 tools)
| Tool | Description |
|------|-------------|
| `recon_target` | DNS resolution, port scan, WAF detection, tech stack fingerprinting |
| `enumerate_dns_subdomains` | DNS record enumeration, subdomain bruteforce |
| `analyze_ssl_tls` | SSL/TLS certificate analysis, MITM detection |
| `browser_screenshot` | Headless browser screenshot + page analysis |
| `browser_extract_surface` | Extract links, forms, inputs, API endpoints |
| `browser_extract_js_secrets` | Scan JS files for secrets and API keys |
| `analyze_js_deep` | Deep JS analysis for endpoints, env leaks, GraphQL |
| `param_discovery_get` | Hidden GET parameter bruteforce |
| `param_discovery_headers` | Custom header discovery |
| `recon_advanced` | Certificate transparency, cloud assets, security.txt |
| `shodan_scanner` / `censys_scanner` | Passive reconnaissance via Shodan/Censys |

### Injection (11 tools)
| Tool | Description |
|------|-------------|
| `scan_sql_injection` | SQL injection (error-based) |
| `blind_sqli_scanner` | Blind SQLi (time-based & boolean-based) |
| `nosql_injection_scanner` | MongoDB/CouchDB injection |
| `ldap_injection_scanner` | LDAP injection |
| `xpath_injection_scanner` | XPath injection |
| `command_injection_scanner` | OS command injection |
| `ssti_tester` | Server-side template injection |
| `xxe_tester` | XML external entity injection |
| `html_injection_scanner` | HTML injection |
| `ssi_injection_scanner` | Server-side includes injection |
| `hpp_scanner` | HTTP parameter pollution |

### XSS (4 tools)
| Tool | Description |
|------|-------------|
| `detect_xss_csrf` | Reflected XSS + CSRF detection |
| `stored_xss_scanner` | Persistent XSS via form submission |
| `dom_xss_scanner` | DOM-based XSS |
| `jsonp_injection_scanner` | JSONP XSS |

### Authentication & Session (7 tools)
| Tool | Description |
|------|-------------|
| `session_management_scanner` | Cookie flags, session fixation, timeout |
| `test_jwt_weakness` | JWT algorithm bypass |
| `oauth_flow_tester` | OAuth state parameter, redirect URI bypass |
| `twofa_bypass_scanner` | 2FA/OTP bypass |
| `password_reset_tester` | Password reset poisoning |
| `credential_stuffing_scanner` | Credential stuffing detection |
| `password_storage_analyzer` | Weak password hashing detection |

### Access Control (4 tools)
| Tool | Description |
|------|-------------|
| `access_control_scanner` | Forced browsing, method bypass, path traversal, privilege escalation |
| `csrf_exploit_scanner` | CSRF token validation testing |
| `mass_assignment_scanner` | Mass assignment / over-posting |
| `http_method_tampering_scanner` | HTTP method override |

### Web Attacks (12 tools)
| Tool | Description |
|------|-------------|
| `scan_ssrf` / `ssrf_advanced_scanner` | Server-side request forgery |
| `scan_idor` / `idor_uuid_scanner` | Insecure direct object reference |
| `host_header_injection_scanner` | Host header injection |
| `race_condition_scanner` | Race condition testing |
| `file_upload_scanner` | File upload bypass (MIME, double extension, polyglot) |
| `http_request_smuggling_scanner` | HTTP request smuggling (CL.TE, TE.CL) |
| `websocket_security_scanner` | WebSocket security (CSWSH) |
| `insecure_deserialization_scanner` | PHP/Java/Python deserialization |
| `web_cache_poisoning_scanner` / `cache_deception_scanner` | Cache attacks |
| `email_header_injection_scanner` | Email header injection |

### Infrastructure (8 tools)
| Tool | Description |
|------|-------------|
| `misconfiguration_scanner` | .git, .env, directory listing, default creds, DNS rebinding |
| `cors_tester` | CORS misconfiguration |
| `graphql_tester` | GraphQL introspection, batch query DoS, schema stitching |
| `nuclei_tool` | Nuclei template scanner (CVE, misconfig) |
| `subdomain_takeover` | Subdomain takeover detection |
| `client_side_security_scanner` | Clickjacking, CSP, SRI, reverse tabnapping |
| `prototype_pollution_scanner` | JavaScript prototype pollution |
| `waf_detector` | WAF fingerprinting (Cloudflare, AWS, ModSecurity, etc.) |

---

## Supported Models

### TokenHub (Tencent Cloud)
- GLM 5V Turbo (multimodal)
- GLM 5.2 (1M context)
- DeepSeek V4 Pro
- MiniMax M3

### OpenRouter
**Paid:** Claude Opus 4.8, GPT-5.5, Qwen 3.7 Max, MiMo V2.5 Pro

**Free:** Qwen3 Coder 480B, Tencent Hy3, Llama 3.3 70B, Hermes 3 405B, Nemotron 3 Ultra, GPT-OSS 120B

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/pentest` | Start new scan |
| `GET` | `/job/{id}` | Poll job status |
| `GET` | `/job/{id}/stream` | SSE stream |
| `POST` | `/job/{id}/cancel` | Cancel job |
| `POST` | `/job/{id}/continue` | Continue to next phase |
| `GET` | `/job/{id}/export?format=md\|pdf\|docx` | Export report |
| `POST` | `/checkpoint/respond` | Approve/reject HITL |
| `POST` | `/auth/respond` | Submit credentials |
| `DELETE` | `/sessions/{id}` | Delete session |
| `GET` | `/scope-rules` | List scope rules |
| `POST` | `/scope-rules` | Add scope rule |
