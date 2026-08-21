-- Stage 6: versioned evaluation, benchmark metrics, and release decisions.
-- Additive migration. Apply after 001, 002, 003, and 004.

create table if not exists evaluation_suites (
  suite_id text primary key,
  name text not null,
  current_version text not null,
  description text not null default '',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists evaluation_suite_versions (
  suite_id text not null references evaluation_suites(suite_id) on delete cascade,
  version text not null,
  mode text not null default 'deterministic',
  manifest_digest text not null,
  description text not null default '',
  created_at timestamptz not null default now(),
  primary key (suite_id, version)
);

create table if not exists evaluation_cases (
  suite_id text not null,
  suite_version text not null,
  case_id text not null,
  name text not null,
  category text not null,
  fixture_id text not null,
  expected_outcome text not null,
  tags jsonb not null default '[]'::jsonb,
  required_assertions jsonb not null default '[]'::jsonb,
  deterministic boolean not null default true,
  model_required boolean not null default false,
  budget jsonb not null default '{}'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  timeout_seconds integer not null default 120,
  seed integer not null default 0,
  evidence_roles jsonb not null default '[]'::jsonb,
  cleanup_assertion text not null default '',
  identity_requirements jsonb not null default '[]'::jsonb,
  primary key (suite_id, suite_version, case_id),
  foreign key (suite_id, suite_version) references evaluation_suite_versions(suite_id, version) on delete cascade
);

create table if not exists evaluation_runs (
  run_id text primary key,
  suite_id text not null,
  suite_version text not null,
  status text not null default 'queued',
  mode text not null default 'deterministic',
  session_id uuid references sessions(id) on delete set null,
  job_id text,
  commit_sha text not null default '',
  config_digest text not null default '',
  config_snapshot jsonb not null default '{}'::jsonb,
  image_digest text not null default '',
  model_id text not null default '',
  prompt_version text not null default '',
  policy_versions jsonb not null default '{}'::jsonb,
  fixture_digest text not null default '',
  random_seed integer not null default 0,
  resource_budget jsonb not null default '{}'::jsonb,
  tool_contract_version text not null default '1.0',
  validator_version text not null default '1.0',
  trial_number integer not null default 1,
  trial_count integer not null default 1,
  totals jsonb not null default '{}'::jsonb,
  metrics jsonb not null default '{}'::jsonb,
  started_at timestamptz,
  finished_at timestamptz,
  error_code text not null default '',
  error_message text not null default '',
  created_at timestamptz not null default now(),
  foreign key (suite_id, suite_version) references evaluation_suite_versions(suite_id, version)
);

create table if not exists evaluation_case_runs (
  case_run_id text primary key,
  run_id text not null references evaluation_runs(run_id) on delete cascade,
  case_id text not null,
  fixture_id text not null,
  status text not null,
  expected_outcome text not null,
  actual_outcome text not null default '',
  metrics jsonb not null default '{}'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  error_code text not null default '',
  error_message text not null default '',
  started_at timestamptz not null,
  finished_at timestamptz not null
);

create table if not exists evaluation_assertions (
  assertion_id text primary key,
  case_run_id text not null references evaluation_case_runs(case_run_id) on delete cascade,
  name text not null,
  passed boolean not null,
  expected jsonb,
  actual jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists evaluation_metric_samples (
  sample_id uuid primary key default gen_random_uuid(),
  metric_id text not null,
  run_id text not null references evaluation_runs(run_id) on delete cascade,
  category text not null,
  value numeric not null,
  unit text not null default 'ratio',
  direction text not null default 'informational',
  threshold numeric,
  passed boolean,
  dimensions jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists evaluation_baselines (
  baseline_id text primary key,
  suite_id text not null,
  suite_version text not null,
  run_id text not null references evaluation_runs(run_id),
  commit_sha text not null default '',
  config_digest text not null default '',
  metrics jsonb not null default '{}'::jsonb,
  accepted_at timestamptz not null default now()
);

create table if not exists release_gate_decisions (
  decision_id text primary key,
  run_id text not null references evaluation_runs(run_id),
  suite_id text not null,
  suite_version text not null,
  decision text not null,
  hard_gates jsonb not null default '[]'::jsonb,
  metrics jsonb not null default '{}'::jsonb,
  reviewer_id text not null default '',
  review_reason text not null default '',
  signature text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists idx_evaluation_runs_suite on evaluation_runs(suite_id, created_at desc);
create index if not exists idx_evaluation_case_runs_run on evaluation_case_runs(run_id, started_at);
create index if not exists idx_evaluation_metrics_run on evaluation_metric_samples(run_id, created_at);
create index if not exists idx_release_gate_run on release_gate_decisions(run_id, created_at desc);

drop trigger if exists evaluation_suite_versions_append_only on evaluation_suite_versions;
create trigger evaluation_suite_versions_append_only
before update or delete on evaluation_suite_versions
for each row execute function nexus_append_only();

drop trigger if exists evaluation_cases_append_only on evaluation_cases;
create trigger evaluation_cases_append_only
before update or delete on evaluation_cases
for each row execute function nexus_append_only();

drop trigger if exists evaluation_case_runs_append_only on evaluation_case_runs;
create trigger evaluation_case_runs_append_only
before update or delete on evaluation_case_runs
for each row execute function nexus_append_only();

drop trigger if exists evaluation_assertions_append_only on evaluation_assertions;
create trigger evaluation_assertions_append_only
before update or delete on evaluation_assertions
for each row execute function nexus_append_only();

drop trigger if exists evaluation_metric_samples_append_only on evaluation_metric_samples;
create trigger evaluation_metric_samples_append_only
before update or delete on evaluation_metric_samples
for each row execute function nexus_append_only();

drop trigger if exists release_gate_decisions_append_only on release_gate_decisions;
create trigger release_gate_decisions_append_only
before update or delete on release_gate_decisions
for each row execute function nexus_append_only();
