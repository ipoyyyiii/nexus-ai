# Changelog

## v7.0 — Human Recon 99.9% + Local Model + Hunter Pipeline
- Stateful human recon: Observe → LLM Decide → Act loop (BFS 60 pages, depth 3, XHR/JS per click)
- Local model additive: Kaggle/Colab ngrok selectable in UI (NEXUS_LOCAL_LLM_*)
- Hunter pipeline 1:1: httpx, naabu, gowitness, gau, hakrawler, amass
- Mitmproxy passive core observer (Burp-like headers/cookies/sensitive URL)
- Dynamic exploit planner + goal verifier (LLM-driven, any goal)
- Payload generator: PayloadsAllTheThings fetcher + LLM creative generation
- GitHub dorking: auto domain→org dual query

## v6.1 — Hardened Edition
- Interactive chat-first session store + workflow engine
- 60+ vuln coverage, 87 custom + 15 external tools
