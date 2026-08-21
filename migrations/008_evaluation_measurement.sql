-- Stage 8: immutable benchmark matrix, trials, coverage, and model diagnostics.
-- Additive only. Apply after the existing evaluation migration; do not run as
-- part of source installation or against production during implementation.

create table if not exists evaluation_scenarios (
  scenario_id text not null,
  suite_id text not null,
  suite_version text not null,
  vulnerability_family text not null,
  subtype text not null default '',
  variant text not null,
  target_surface text not null,
  endpoint_class text not null default 'fixture',
  auth_state text not null default 'anonymous',
  identity text not null default 'none',
  tenant text not null default 'none',
  expected_outcome text not null,
  capability_tier text not null,
  required_evidence_roles jsonb not null default '[]'::jsonb,
  cleanup_required boolean not null default false,
  cleanup_assertion text not null default '',
  fixture_id text not null,
  tags jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  fingerprint text not null,
  created_at timestamptz not null default now(),
  primary key (suite_id, suite_version, scenario_id),
  foreign key (suite_id, suite_version) references evaluation_suite_versions(suite_id, version) on delete restrict
);

create table if not exists evaluation_benchmark_matrices (
  matrix_id text primary key,
  suite_id text not null,
  suite_version text not null,
  suite_digest text not null,
  fixture_digest text not null,
  scenario_count integer not null default 0,
  required_count integer not null default 0,
  diagnostic_count integer not null default 0,
  dimension_coverage jsonb not null default '{}'::jsonb,
  unsupported_capabilities jsonb not null default '[]'::jsonb,
  baseline_id text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists evaluation_trials (
  trial_id text primary key,
  run_id text not null references evaluation_runs(run_id) on delete cascade,
  scenario_id text not null,
  trial_number integer not null,
  trial_count integer not null,
  seed integer not null default 0,
  mode text not null,
  model_id text not null default '',
  provider text not null default '',
  prompt_version text not null default '',
  config_digest text not null default '',
  policy_versions jsonb not null default '{}'::jsonb,
  status text not null,
  started_at timestamptz,
  finished_at timestamptz,
  duration_ms numeric not null default 0,
  token_usage jsonb not null default '{}'::jsonb,
  request_count integer not null default 0,
  budget_usage jsonb not null default '{}'::jsonb,
  action_count integer not null default 0,
  valid_action_count integer not null default 0,
  failure_taxonomy text,
  error_code text not null default '',
  error_message text not null default '',
  evidence_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists evaluation_coverage_samples (
  sample_id text primary key,
  run_id text not null references evaluation_runs(run_id) on delete cascade,
  trial_id text,
  scenario_id text not null,
  tool_name text not null default '',
  category text not null,
  vulnerability_family text not null,
  subtype text not null default '',
  endpoint_class text not null default 'fixture',
  identity text not null default 'none',
  tenant text not null default 'none',
  surface text not null,
  browser_or_api text not null default 'api',
  validator_policy text not null default '',
  outcome text not null,
  failure_taxonomy text,
  capability_tier text not null,
  evidence_complete boolean not null default false,
  reproducible boolean not null default false,
  cleanup_verified boolean,
  dimensions jsonb not null default '{}'::jsonb,
  metrics jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists evaluation_model_actions (
  action_id text primary key,
  trial_id text not null references evaluation_trials(trial_id) on delete cascade,
  action text not null,
  tool_name text not null default '',
  endpoint_ref text not null default '',
  evidence_roles jsonb not null default '[]'::jsonb,
  rationale text not null default '',
  valid boolean not null default false,
  rejection_reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists evaluation_baseline_acceptance (
  acceptance_id uuid primary key default gen_random_uuid(),
  baseline_id text not null references evaluation_baselines(baseline_id) on delete restrict,
  reviewer_id text not null,
  reason text not null,
  suite_digest text not null,
  fixture_digest text not null,
  metric_snapshot jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_evaluation_scenarios_suite on evaluation_scenarios(suite_id, suite_version, capability_tier);
create index if not exists idx_evaluation_matrices_suite on evaluation_benchmark_matrices(suite_id, suite_version, created_at desc);
create index if not exists idx_evaluation_trials_run on evaluation_trials(run_id, created_at);
create index if not exists idx_evaluation_trials_scenario on evaluation_trials(scenario_id, created_at);
create index if not exists idx_evaluation_coverage_run on evaluation_coverage_samples(run_id, created_at);
create index if not exists idx_evaluation_coverage_dimensions on evaluation_coverage_samples(vulnerability_family, identity, tenant);
create index if not exists idx_evaluation_model_actions_trial on evaluation_model_actions(trial_id, created_at);

 drop trigger if exists evaluation_scenarios_append_only on evaluation_scenarios;
create trigger evaluation_scenarios_append_only
before update or delete on evaluation_scenarios
for each row execute function nexus_append_only();

drop trigger if exists evaluation_benchmark_matrices_append_only on evaluation_benchmark_matrices;
create trigger evaluation_benchmark_matrices_append_only
before update or delete on evaluation_benchmark_matrices
for each row execute function nexus_append_only();

drop trigger if exists evaluation_trials_append_only on evaluation_trials;
create trigger evaluation_trials_append_only
before update or delete on evaluation_trials
for each row execute function nexus_append_only();

drop trigger if exists evaluation_coverage_samples_append_only on evaluation_coverage_samples;
create trigger evaluation_coverage_samples_append_only
before update or delete on evaluation_coverage_samples
for each row execute function nexus_append_only();

drop trigger if exists evaluation_model_actions_append_only on evaluation_model_actions;
create trigger evaluation_model_actions_append_only
before update or delete on evaluation_model_actions
for each row execute function nexus_append_only();

drop trigger if exists evaluation_baseline_acceptance_append_only on evaluation_baseline_acceptance;
create trigger evaluation_baseline_acceptance_append_only
before update or delete on evaluation_baseline_acceptance
for each row execute function nexus_append_only();
