-- Stage 9: versioned detection-depth validation records.
-- Additive only. Apply after the existing migrations; do not run automatically.

create table if not exists validation_policy_versions (
  policy_id text not null,
  policy_version text not null,
  schema_version text not null default '2.0',
  vulnerability_family text not null,
  subtypes jsonb not null default '[]'::jsonb,
  mandatory_observation_roles jsonb not null default '[]'::jsonb,
  minimum_iterations integer not null default 1,
  requires_baseline boolean not null default true,
  requires_control boolean not null default true,
  requires_clean_reproduction boolean not null default true,
  requires_cleanup boolean not null default false,
  required_evidence_kinds jsonb not null default '[]'::jsonb,
  failure_classification text not null default 'missing_evidence',
  thresholds jsonb not null default '{}'::jsonb,
  noise_tolerance numeric not null default 0,
  description text not null default '',
  fingerprint text not null,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  primary key (policy_id, policy_version)
);

alter table if exists validation_runs add column if not exists schema_version text not null default '1.0';
alter table if exists validation_runs add column if not exists input_digest text not null default '';
alter table if exists validation_runs add column if not exists evidence_ids jsonb not null default '[]'::jsonb;
alter table if exists validation_runs add column if not exists observation_ids jsonb not null default '[]'::jsonb;
alter table if exists validation_runs add column if not exists failure_classification text;
alter table if exists validation_runs add column if not exists mode text not null default 'shadow';
alter table if exists validation_runs add column if not exists validator_version text not null default '2.0';

alter table if exists validation_checks add column if not exists schema_version text not null default '1.0';
alter table if exists validation_checks add column if not exists check_id text;
alter table if exists validation_checks add column if not exists reason text not null default '';
alter table if exists validation_checks add column if not exists evidence_ids jsonb not null default '[]'::jsonb;
alter table if exists validation_checks add column if not exists observation_ids jsonb not null default '[]'::jsonb;
alter table if exists validation_checks add column if not exists input_digest text not null default '';
alter table if exists validation_checks add column if not exists failure_classification text;

create table if not exists validation_traces_v2 (
  trace_id text primary key,
  validation_run_id text not null,
  candidate_id text not null,
  policy_id text not null,
  policy_version text not null,
  validator_version text not null default '2.0',
  context jsonb not null default '{}'::jsonb,
  checks jsonb not null default '[]'::jsonb,
  decision text not null,
  evidence_ids jsonb not null default '[]'::jsonb,
  shadow_decision text,
  input_digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists validation_replays_v2 (
  replay_id text primary key,
  candidate_id text not null,
  validation_run_id text not null,
  source_input_digest text not null,
  replay_input_digest text not null,
  outcome_match boolean not null,
  evidence_digest text not null default '',
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists validation_gap_reports_v2 (
  report_id text primary key,
  scope text not null default 'local',
  policy_id text,
  failure_classification text,
  gap text not null,
  scenario_count integer not null default 0,
  details jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_validation_policy_v2_family on validation_policy_versions(vulnerability_family, active);
create index if not exists idx_validation_trace_v2_candidate on validation_traces_v2(candidate_id, created_at desc);
create index if not exists idx_validation_trace_v2_policy on validation_traces_v2(policy_id, policy_version, created_at desc);
create index if not exists idx_validation_replay_v2_candidate on validation_replays_v2(candidate_id, created_at desc);
create index if not exists idx_validation_gap_v2_classification on validation_gap_reports_v2(failure_classification, created_at desc);

drop trigger if exists validation_policy_v2_append_only on validation_policy_versions;
create trigger validation_policy_v2_append_only
before update or delete on validation_policy_versions
for each row execute function nexus_append_only();

drop trigger if exists validation_trace_v2_append_only on validation_traces_v2;
create trigger validation_trace_v2_append_only
before update or delete on validation_traces_v2
for each row execute function nexus_append_only();

drop trigger if exists validation_replay_v2_append_only on validation_replays_v2;
create trigger validation_replay_v2_append_only
before update or delete on validation_replays_v2
for each row execute function nexus_append_only();

drop trigger if exists validation_gap_v2_append_only on validation_gap_reports_v2;
create trigger validation_gap_v2_append_only
before update or delete on validation_gap_reports_v2
for each row execute function nexus_append_only();
