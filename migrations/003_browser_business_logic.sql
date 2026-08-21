-- Tahap 4: stateful browser workflows and deterministic business logic.
-- Additive migration. Workflow versions, snapshots, transitions, and evaluations are append-only.

create table if not exists browser_workflows (
  workflow_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  name text not null,
  origin text not null,
  goal text not null default '',
  status text not null default 'draft',
  current_version integer not null default 1,
  identity_requirements jsonb not null default '[]'::jsonb,
  input_schema jsonb not null default '{}'::jsonb,
  cleanup_step_ids jsonb not null default '[]'::jsonb,
  source_observation_ids jsonb not null default '[]'::jsonb,
  fingerprint text not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(session_id, fingerprint)
);

create table if not exists browser_workflow_versions (
  workflow_version_id text primary key,
  workflow_id text not null references browser_workflows(workflow_id) on delete cascade,
  version integer not null,
  status text not null default 'draft',
  preconditions jsonb not null default '[]'::jsonb,
  postconditions jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  unique(workflow_id, version)
);

create table if not exists browser_workflow_steps (
  step_id text primary key,
  workflow_version_id text not null references browser_workflow_versions(workflow_version_id) on delete cascade,
  ordinal integer not null,
  action text not null,
  locator jsonb,
  input_bindings jsonb not null default '{}'::jsonb,
  args jsonb not null default '{}'::jsonb,
  preconditions jsonb not null default '[]'::jsonb,
  postconditions jsonb not null default '[]'::jsonb,
  side_effect_class text not null default 'read',
  risk text not null default 'low',
  timeout_ms integer not null default 15000,
  retry_limit integer not null default 1,
  cleanup_step_id text not null default '',
  description text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  unique(workflow_version_id, ordinal)
);

create table if not exists browser_runs (
  run_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  workflow_id text not null references browser_workflows(workflow_id) on delete cascade,
  workflow_version integer not null,
  identity_id text,
  auth_context_id text,
  role text not null default 'baseline',
  status text not null default 'planned',
  current_step integer not null default 0,
  total_steps integer not null default 0,
  approval_digest text not null default '',
  approval_expires_at timestamptz,
  parent_run_id text,
  checkpoint_snapshot_id text not null default '',
  state_digest text not null default '',
  cleanup_refs jsonb not null default '[]'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  error_code text not null default '',
  error_message text not null default '',
  started_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists browser_step_runs (
  step_run_id text primary key,
  run_id text not null references browser_runs(run_id) on delete cascade,
  step_id text not null references browser_workflow_steps(step_id) on delete cascade,
  ordinal integer not null,
  status text not null default 'planned',
  before_snapshot_id text not null default '',
  after_snapshot_id text not null default '',
  observation_ids jsonb not null default '[]'::jsonb,
  artifact_ids jsonb not null default '[]'::jsonb,
  error_code text not null default '',
  error_message text not null default '',
  attempts integer not null default 0,
  started_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists browser_state_snapshots (
  snapshot_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  run_id text not null references browser_runs(run_id) on delete cascade,
  step_run_id text not null default '',
  url text not null default '',
  title text not null default '',
  dom_hash text not null default '',
  visible_landmarks jsonb not null default '[]'::jsonb,
  network_fingerprints jsonb not null default '[]'::jsonb,
  storage_metadata jsonb not null default '{}'::jsonb,
  entity_state jsonb not null default '[]'::jsonb,
  artifact_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists business_entities (
  entity_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  entity_type text not null,
  fingerprint text not null,
  locator_redacted jsonb,
  owner_identity_id text,
  tenant_label text not null default '',
  fields_redacted jsonb not null default '{}'::jsonb,
  source_snapshot_ids jsonb not null default '[]'::jsonb,
  source_observation_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now(),
  unique(session_id, fingerprint)
);

create table if not exists business_state_transitions (
  transition_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  entity_id text references business_entities(entity_id) on delete set null,
  action text not null,
  before_snapshot_id text not null references browser_state_snapshots(snapshot_id) on delete restrict,
  after_snapshot_id text not null references browser_state_snapshots(snapshot_id) on delete restrict,
  before_state jsonb not null default '{}'::jsonb,
  after_state jsonb not null default '{}'::jsonb,
  expected text not null default '',
  observation_ids jsonb not null default '[]'::jsonb,
  artifact_ids jsonb not null default '[]'::jsonb,
  side_effects jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists business_invariants (
  invariant_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  name text not null,
  rule_type text not null,
  rule_version text not null default '1.0',
  status text not null default 'draft',
  source text not null default 'llm_draft',
  rule jsonb not null default '{}'::jsonb,
  required_workflow_ids jsonb not null default '[]'::jsonb,
  required_identity_ids jsonb not null default '[]'::jsonb,
  source_observation_ids jsonb not null default '[]'::jsonb,
  revision integer not null default 1,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists invariant_evaluations (
  evaluation_id text primary key,
  invariant_id text not null references business_invariants(invariant_id) on delete cascade,
  invariant_version text not null default '1.0',
  decision text not null default 'inconclusive',
  score numeric not null default 0,
  reason text not null default '',
  evidence_ids jsonb not null default '[]'::jsonb,
  run_ids jsonb not null default '[]'::jsonb,
  candidate_id text,
  created_at timestamptz not null default now()
);

create table if not exists invariant_checks (
  evaluation_id text not null references invariant_evaluations(evaluation_id) on delete cascade,
  check_name text not null,
  passed boolean not null,
  details jsonb not null default '{}'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  primary key(evaluation_id, check_name)
);

alter table if exists browser_runs add column if not exists approval_expires_at timestamptz;
create index if not exists idx_browser_workflows_session on browser_workflows(session_id, status, updated_at desc);
create index if not exists idx_browser_workflow_versions_workflow on browser_workflow_versions(workflow_id, version desc);
create index if not exists idx_browser_runs_session on browser_runs(session_id, started_at desc);
create index if not exists idx_browser_step_runs_run on browser_step_runs(run_id, ordinal);
create index if not exists idx_browser_snapshots_run on browser_state_snapshots(run_id, created_at);
create index if not exists idx_business_entities_session on business_entities(session_id, entity_type);
create index if not exists idx_business_transitions_session on business_state_transitions(session_id, created_at desc);
create index if not exists idx_business_invariants_session on business_invariants(session_id, status, updated_at desc);
create index if not exists idx_invariant_evaluations_invariant on invariant_evaluations(invariant_id, created_at desc);

-- Keep browser artifacts private; the API issues short-lived signed URLs.
do $$
begin
  insert into storage.buckets (id, name, public)
  values ('nexus-evidence', 'nexus-evidence', false)
  on conflict (id) do update set public = false;
exception when undefined_table then
  -- Non-Supabase local PostgreSQL can provision the bucket out-of-band.
  null;
end $$;
