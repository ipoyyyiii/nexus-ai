# communication
- Communicate with the user using casual Indonesian language (e.g., "kocak", "men", "gue", "lu", "bentar dulu"). Confidence: 0.80
- Assess current project state before implementing any refactoring or architectural changes — do not blindly apply plans without first confirming what already exists. Confidence: 0.80
- Prefers candid, scope-calibrated project reviews that clearly separate what is already implemented, the main workflow gaps, and the broader remaining backlog; state whether the list is exhaustive and do not overclaim completeness. Confidence: 0.92
- For this project, treat the deployment as a personal/private tool rather than a public multi-user service: deprioritize public-production concerns such as multi-user ownership, credential vaulting, and report access control, while retaining safeguards and reliability that matter for personal use. Confidence: 0.97
- When discussing missing features or project gaps, explain the practical purpose and benefit of each one, not just its name or implementation status; before implementation, walk through why each planned item matters in concrete, easy-to-follow examples. Confidence: 0.93
- When the user provides a large architectural blueprint/prompt, first audit the codebase against it and report gaps before writing any code. Confidence: 0.75
- When giving operational instructions, clearly distinguish the exact content to copy/run from wrapper syntax (such as Markdown code-fence markers), and briefly explain the purpose of tools like lint in plain language. Confidence: 0.86
- When the user asks how to access the running application, provide the URL immediately (e.g., http://48.193.45.254:3000) and verify the services are running. Confidence: 0.75
