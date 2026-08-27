-- Stage 19: production autonomy, soak/SLO evidence, cutover and recovery control.
-- Additive and forward-only. Apply after migration 018. No RLS changes.
-- A rollback is a forward config decision recorded in production_cutover_decisions;
-- this migration intentionally does not delete or rewrite historical evidence.

alter table if exists production_readiness_runs
  add column if not exists platform_mode text not null default 'shadow',
  add column if not exists tool_boundary_mode text not null default 'shadow',
  add column if not exists schema_digest text not null default '',
  add column if not exists worker_topology jsonb not null default '{}'::jsonb,
  add column if not exists soak_run_id text not null default '',
  add column if not exists baseline_run_id text not null default '',
  add column if not exists slo_snapshot_id text not null default '',
  add column if not exists rollback_ref text not null default '',
  add column if not exists cutover_candidate boolean not null default false,
  add column if not exists reviewer_id text not null default '',
  add column if not exists review_reason text not null default '';

create table if not exists production_soak_runs (
  soak_run_id text primary key,
  readiness_run_id text not null default '',
  mode text not null default 'deterministic',
  duration_seconds integer not null default 0,
  sample_interval_seconds integer not null default 15,
  worker_count integer not null default 1,
  simulated_worker_count integer not null default 0,
  status text not null default 'queued',
  expected_jobs integer not null default 0,
  completed_jobs integer not null default 0,
  failed_jobs integer not null default 0,
  recovery_events integer not null default 0,
  stale_write_rejections integer not null default 0,
  duplicate_suppression_count integer not null default 0,
  cleanup_failures integer not null default 0,
  redaction_leaks integer not null default 0,
  started_at timestamptz not null default now(),
  finished_at timestamptz,
  config_digest text not null default '',
  fixture_digest text not null default '',
  metadata jsonb not null default '{}'::jsonb
);

create table if not exists production_soak_samples (
  sample_id text primary key,
  soak_run_id text not null references production_soak_runs(soak_run_id) on delete cascade,
  sample_number integer not null,
  elapsed_seconds integer not null default 0,
  queue_depth integer not null default 0,
  online_workers integer not null default 0,
  leased_jobs integer not null default 0,
  terminal_jobs integer not null default 0,
  heartbeat_age_seconds numeric not null default 0,
  cpu_percent numeric,
  memory_bytes bigint,
  error_rate numeric not null default 0,
  p95_latency_ms numeric not null default 0,
  budget_exhaustions integer not null default 0,
  circuit_breaker_opens integer not null default 0,
  created_at timestamptz not null default now(),
  unique (soak_run_id, sample_number)
);

create table if not exists production_slo_snapshots (
  slo_snapshot_id text primary key,
  readiness_run_id text not null default '',
  window_seconds integer not null default 0,
  availability numeric not null default 0,
  terminal_success_rate numeric not null default 0,
  recovery_success_rate numeric not null default 0,
  p95_latency_ms numeric not null default 0,
  error_rate numeric not null default 0,
  duplicate_execution_rate numeric not null default 0,
  stale_write_rate numeric not null default 0,
  cleanup_success_rate numeric not null default 0,
  redaction_leaks integer not null default 0,
  passed boolean not null default false,
  thresholds jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists production_cutover_decisions (
  decision_id text primary key,
  readiness_run_id text not null,
  from_mode text not null default 'shadow',
  to_mode text not null default 'strict',
  decision text not null,
  reviewer_id text not null,
  reason text not null,
  config_digest text not null default '',
  schema_digest text not null default '',
  image_digest text not null default '',
  soak_run_id text not null default '',
  slo_snapshot_id text not null default '',
  rollback_ref text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists recovery_verifications (
  verification_id text primary key,
  job_id text not null,
  attempt_id text not null default '',
  recovery_id text not null default '',
  decision text not null default 'inconclusive',
  checkpoint_valid boolean not null default false,
  side_effects_verified boolean not null default false,
  mutation_replayed boolean not null default false,
  cleanup_verified boolean not null default false,
  evidence_ids jsonb not null default '[]'::jsonb,
  reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists operator_incidents (
  incident_id text primary key,
  severity text not null default 'warning',
  category text not null,
  job_id text not null default '',
  attempt_id text not null default '',
  worker_id text not null default '',
  status text not null default 'open',
  summary text not null,
  action_required text not null default '',
  created_at timestamptz not null default now(),
  resolved_at timestamptz
);

create index if not exists idx_soak_runs_started on production_soak_runs(started_at desc);
create index if not exists idx_soak_samples_run on production_soak_samples(soak_run_id, sample_number);
create index if not exists idx_slo_readiness on production_slo_snapshots(readiness_run_id, created_at desc);
create index if not exists idx_cutover_readiness on production_cutover_decisions(readiness_run_id, created_at desc);
create index if not exists idx_recovery_verification_job on recovery_verifications(job_id, created_at desc);
create index if not exists idx_operator_incidents_status on operator_incidents(status, created_at desc);

-- All historical operational evidence is append-only.
drop trigger if exists production_soak_runs_append_only on production_soak_runs;
create trigger production_soak_runs_append_only before update or delete on production_soak_runs
for each row execute function nexus_append_only();
drop trigger if exists production_soak_samples_append_only on production_soak_samples;
create trigger production_soak_samples_append_only before update or delete on production_soak_samples
for each row execute function nexus_append_only();
drop trigger if exists production_slo_snapshots_append_only on production_slo_snapshots;
create trigger production_slo_snapshots_append_only before update or delete on production_slo_snapshots
for each row execute function nexus_append_only();
drop trigger if exists production_cutover_decisions_append_only on production_cutover_decisions;
create trigger production_cutover_decisions_append_only before update or delete on production_cutover_decisions
for each row execute function nexus_append_only();
drop trigger if exists recovery_verifications_append_only on recovery_verifications;
create trigger recovery_verifications_append_only before update or delete on recovery_verifications
for each row execute function nexus_append_only();
drop trigger if exists operator_incidents_append_only on operator_incidents;
create trigger operator_incidents_append_only before update or delete on operator_incidents
for each row execute function nexus_append_only();
