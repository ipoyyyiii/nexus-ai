# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# pentesting
- Automate all vulnerability scanners comprehensively; do not skip any item based on priority assumptions—implement everything missing from the coverage list. Confidence: 0.65
- For web security testing, focus on web applications only; skip mobile app and desktop app testing. Confidence: 0.70

# workflow
- Before making code changes, read and understand all existing code and file relationships in the repository first. Confidence: 0.70
- Execute vulnerability scanning agents in sequential phases (recon → analysis → exploitation → assessment) with user pause/continue between each phase. Confidence: 0.70

# code-style
- AI agent reports must use Github Flavored Markdown (GFM) format only; no ASCII art decorations or manual borders. Confidence: 0.75
- All code, comments, and tool output must be in English for GitHub accessibility. Confidence: 0.85

# pentesting
- De-prioritize notification systems (Telegram/Discord/Slack alerts); focus on core pentesting features first. Confidence: 0.65
- Post-exploitation features are unnecessary; skip data exfiltration, persistence, and post-exploitation tooling. Confidence: 0.70

