# Evaluation results

Generated evaluation artifacts live here so the repository root stays focused
on source code and configuration.

- `stages/` — raw JSON output from repeatable evaluation-CLI stage runs.
- `final/` — reviewed stage artifacts and final validation snapshots.

Example:

```bash
python -m core.evaluation_cli run \
  --suite stage27-recon-closure \
  --mode deterministic \
  --trials 3 \
  > results/stages/stage27-result.json
```

Results are evidence for the scorecard, not proof by themselves that a target
is vulnerable. Interpret `ready`, `inconclusive`, `unsupported`, and
`diagnostic` according to `docs/PROJECT_HANDOFF.md`.

Runtime reports and temporary artifacts belong in `stored_reports/`, which is
intentionally ignored by Git.
