# Taste (Continuously Learned by [CommandCode][cmd])

[cmd]: https://commandcode.ai/

# pentesting
- Automate all vulnerability scanners comprehensively; do not skip any item based on priority assumptions—implement everything missing from the coverage list. Confidence: 0.72
- For web security testing, focus on web applications only; skip mobile app and desktop app testing. Confidence: 0.70

# workflow
See [workflow/taste.md](workflow/taste.md)
# code-style
- AI agent reports must use Github Flavored Markdown (GFM) format only; no ASCII art decorations or manual borders. Confidence: 0.75
- All code, comments, tool output, and documentation (including README) must be in English for GitHub accessibility. Confidence: 0.95

# communication
See [communication/taste.md](communication/taste.md)
# architecture
- Design multi-agent pipelines with a centralized TargetState memory layer that aggregates outputs from each phase and is dynamically injected into LLM prompts. Confidence: 0.80
- Implement an interactive co-pilot mode where automated scanning pauses after reconnaissance/analysis, allowing the user to ask questions and request custom payloads before proceeding to exploitation/reporting. Confidence: 0.85
- Start each new pentesting session with a setup wizard that collects the target/domain, attack goal, authorization, and allow/deny scope rules before entering the chat interface. Confidence: 0.95
- Make the agent chat-first and session-scoped: each message should use persistent TargetState tied to its session rather than triggering an autonomous full scan or relying on global target state. Confidence: 0.95
- Use a 3-phase architecture: (1) Automated Data Gathering, (2) Interactive Consultation, (3) Automated Synthesis & Reporting — with each phase feeding data into a shared state store. Confidence: 0.82

# pentesting
See [pentesting/taste.md](pentesting/taste.md)
