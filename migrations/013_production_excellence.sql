-- Stage 13: production excellence, readiness evidence, recovery telemetry.
-- Additive, forward-only migration.  Apply after migration 012.
-- RLS remains disabled by the current deployment decision; keep the service
-- credential server-side and never expose these tables to the frontend.

create table if not exists production_readiness_runs (
  run_id text primary key,
  suite_id text not null,
  suite_version text not null default '1.0',
  status text not null default 'queued',
  mode text not null default 'deterministic',
  commit_sha text not null default '',
  config_digest text not null default '',
  image_digest text not null default '',
  fixture_digest text not null default '',
  metrics jsonb not null default '{}'::jsonb,
  release_decision text not null default 'pending',
  created_at timestamptz not null default now(),
  started_at timestamptz,
  finished_at timestamptz
);

create table if not exists readiness_checks (
  check_id text primary key,
  run_id text not null references production_readiness_runs(run_id) on delete cascade,
  name text not null,
  passed boolean not null,
  expected jsonb not null default 'null'::jsonb,
  actual jsonb not null default 'null'::jsonb,
  reason text not null default '',
  evidence_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists worker_health_snapshots (
  snapshot_id text primary key,
  worker_id text not null,
  status text not null,
  capabilities jsonb not null default '[]'::jsonb,
  active_job_id text not null default '',
  active_attempt_id text not null default '',
  heartbeat_at timestamptz not null default now(),
  resource_sample jsonb not null default '{}'::jsonb,
  queue_depth integer not null default 0,
  lease_age_seconds numeric not null default 0,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists recovery_events (
  recovery_id text primary key,
  job_id text not null,
  attempt_id text not null default '',
  worker_id text not null default '',
  kind text not null,
  decision text not null,
  status text not null default 'recorded',
  checkpoint_id text not null default '',
  side_effects jsonb not null default '[]'::jsonb,
  cleanup_refs jsonb not null default '[]'::jsonb,
  reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists resource_samples (
  sample_id text primary key,
  worker_id text not null default '',
  job_id text not null default '',
  attempt_id text not null default '',
  cpu_percent numeric,
  memory_bytes bigint,
  memory_limit_bytes bigint,
  process_count integer,
  request_count integer not null default 0,
  token_count integer not null default 0,
  created_at timestamptz not null default now()
);

create table if not exists artifact_sweeps (
  sweep_id text primary key,
  bucket text not null,
  dry_run boolean not null default true,
  scanned integer not null default 0,
  expired integer not null default 0,
  deleted integer not null default 0,
  orphaned integer not null default 0,
  errors integer not null default 0,
  started_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists release_gate_reviews (
  review_id text primary key,
  run_id text not null references production_readiness_runs(run_id) on delete cascade,
  decision text not null,
  reviewer_id text not null,
  reason text not null,
  signature text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists idx_readiness_checks_run on readiness_checks(run_id, created_at);
create index if not exists idx_worker_health_worker on worker_health_snapshots(worker_id, created_at desc);
create index if not exists idx_worker_health_heartbeat on worker_health_snapshots(heartbeat_at desc);
create index if not exists idx_recovery_job on recovery_events(job_id, created_at desc);
create index if not exists idx_resource_job on resource_samples(job_id, created_at desc);
create index if not exists idx_artifact_sweeps_bucket on artifact_sweeps(bucket, started_at desc);
create index if not exists idx_release_reviews_run on release_gate_reviews(run_id, created_at desc);

drop trigger if exists readiness_checks_append_only on readiness_checks;
create trigger readiness_checks_append_only before update or delete on readiness_checks
for each row execute function nexus_append_only();
drop trigger if exists worker_health_snapshots_append_only on worker_health_snapshots;
create trigger worker_health_snapshots_append_only before update or delete on worker_health_snapshots
for each row execute function nexus_append_only();
drop trigger if exists recovery_events_append_only on recovery_events;
create trigger recovery_events_append_only before update or delete on recovery_events
for each row execute function nexus_append_only();
drop trigger if exists resource_samples_append_only on resource_samples;
create trigger resource_samples_append_only before update or delete on resource_samples
for each row execute function nexus_append_only();
drop trigger if exists artifact_sweeps_append_only on artifact_sweeps;
create trigger artifact_sweeps_append_only before update or delete on artifact_sweeps
for each row execute function nexus_append_only();
drop trigger if exists release_gate_reviews_append_only on release_gate_reviews;
create trigger release_gate_reviews_append_only before update or delete on release_gate_reviews
for each row execute function nexus_append_only();
