# Nexus documentation

This directory contains the project’s durable context and evaluation records.

- `PROJECT_HANDOFF.md` — current architecture, operating decisions, known gaps,
  and resume instructions.
- `NEXUS_CONTEXT_MEMORY.md` — canonical roadmap and persistent project context.
- `NEXUS_UPGRADE_LEDGER.md` — append-on-change record of upgrades, evidence, and
  limitations.
- `NEXUS_EVENT_LOG.md` — append-only record of runs, bugs, fixes, decisions,
  and verification.
- `NEXUS_SCORECARD.yaml` — frozen evaluation criteria and rating evidence.

These files are project records, not runtime state. New entries should preserve
the existing chronology and should never contain secrets, tokens, or raw private
target data.

For generated benchmark artifacts, see [`../results/`](../results/README.md).
