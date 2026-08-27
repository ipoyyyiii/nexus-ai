# Stage 20 — Final Authorized Validation Gate

Date: 2026-08-23

## Current decision

`IN_PROGRESS` — local release gates are ready; independent real-world
authorized validation is still pending.

Stage 20 is a validation gate, not a claim that the product is world-class.
No external target was scanned by this run.

## Completed checks

- Python regression suite: `114 passed`
- Python compile gate: passed
- Stage 6 deterministic suite: `succeeded / ready`
- Stage 8 deterministic suite: `succeeded / ready`
- Stage 9 deterministic suite: `succeeded / ready`
- Stage 10 deterministic suite: `succeeded / ready`
- Stage 11 deterministic suite: `succeeded / ready`
- Stage 12 deterministic suite: `succeeded / ready`
- Stage 13 deterministic suite: `succeeded / ready`
- Stage 14 deterministic suite: `succeeded / ready`
- Stage 15 deterministic suite: `succeeded / ready`
- Stage 16 deterministic suite: `succeeded / ready`
- Stage 17 deterministic suite: `succeeded / ready`
- Stage 18 deterministic suite: `succeeded / ready`
- Stage 19 deterministic suite: `succeeded / ready`
- Docker Compose configuration: passed
- API live/ready smoke: passed
- Frontend HTTP smoke: passed
- Frontend production build and TypeScript check: passed
- Nexus model registry exposes `local-ravenx-cyberagent`: passed
- RavenX health check: passed, dual GPU reported
- RavenX `/v1/models`: passed
- RavenX completion marker: passed
- Nexus-to-RavenX routing marker: passed

## Important finding

Creating a new session with `scan_preset: recon-only` returned a Supabase
schema-cache error because `session_context.scan_preset` is not currently
available. The same provider-routing smoke test passed with the default
`full` preset. This is a deployment/schema mismatch that should be fixed or
verified before strict production use.

Local remediation added in `migrations/021_session_scan_config.sql`. It is
additive and still needs to be executed in Supabase before the `recon-only`
path can be considered verified in deployment.

The requested target was not scanned: DNS resolved, but both HTTP and HTTPS
connections from the VM timed out. This is recorded as `infra_unreachable`,
not as a target finding.

## Remaining Stage 20 evidence

The final gate still needs an explicitly authorized target and test window:

1. previously unseen black-box web/API target;
2. documented scope and authorization;
3. seeded/known validation cases or an independent reference assessment;
4. Nexus result compared with a senior manual baseline and a conventional
   tool baseline;
5. false-positive, false-negative, reproducibility, cleanup, time, and cost
   review;
6. human sign-off on the evidence and report.

Until those items exist, the correct status is `IN_PROGRESS`, not `READY`.
