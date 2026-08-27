-- Tahap 12: bounded autonomous reasoning and evidence-grounded reporting.
-- Additive only. Run after local acceptance; no RLS is enabled to match the
-- current deployment contract. Reasoning/report traces are append-only.

create table if not exists reasoning_cycles (
  cycle_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  job_id uuid,
  objective text not null default '',
  mode text not null default 'shadow',
  status text not null default 'queued',
  snapshot_digest text not null default '',
  config_digest text not null default '',
  model_id text not null default '',
  prompt_version text not null default '',
  action_budget integer not null default 3,
  cycle_number integer not null default 1,
  max_cycles integer not null default 10,
  selected_action_ids jsonb not null default '[]'::jsonb,
  hypothesis_ids jsonb not null default '[]'::jsonb,
  evidence_gap_ids jsonb not null default '[]'::jsonb,
  stop_condition_ids jsonb not null default '[]'::jsonb,
  stop_reason text not null default '',
  input_digest text not null default '',
  output_digest text not null default '',
  created_at timestamptz not null default now(),
  finished_at timestamptz
);

create table if not exists reasoning_hypotheses (
  record_id uuid primary key default gen_random_uuid(),
  hypothesis_id text not null,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  claim text not null,
  null_hypothesis text not null default '',
  status text not null default 'proposed',
  category text not null default 'unknown',
  target_url text not null default '',
  method text not null default 'GET',
  parameter text not null default '',
  supporting_evidence_ids jsonb not null default '[]'::jsonb,
  contradicting_evidence_ids jsonb not null default '[]'::jsonb,
  required_evidence_roles jsonb not null default '[]'::jsonb,
  evidence_gap_ids jsonb not null default '[]'::jsonb,
  priority_score numeric not null default 0,
  expected_information_gain numeric not null default 0,
  confidence_score numeric not null default 0.5,
  source text not null default 'deterministic',
  fingerprint text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(hypothesis_id, cycle_id)
);

create table if not exists reasoning_actions (
  action_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  action_type text not null,
  tool_name text not null default '',
  endpoint_ref text not null default '',
  hypothesis_id text not null default '',
  risk text not null default 'read_only',
  side_effect_class text not null default 'read',
  evidence_ids jsonb not null default '[]'::jsonb,
  expected_evidence_roles jsonb not null default '[]'::jsonb,
  requires_approval boolean not null default false,
  cleanup_ref text not null default '',
  expected_information_gain numeric not null default 0,
  rationale text not null default '',
  status text not null default 'proposed',
  rejection_reason text not null default '',
  input_digest text not null default '',
  source text not null default 'deterministic',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists reasoning_decisions (
  decision_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  snapshot_digest text not null default '',
  selected_action_ids jsonb not null default '[]'::jsonb,
  rejected_action_ids jsonb not null default '[]'::jsonb,
  evidence_gap_ids jsonb not null default '[]'::jsonb,
  stop_condition_ids jsonb not null default '[]'::jsonb,
  rationale text not null default '',
  deterministic boolean not null default true,
  input_digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists reasoning_evidence_gaps (
  gap_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  hypothesis_id text not null default '',
  gap_type text not null,
  description text not null,
  required_role text not null default '',
  blocking boolean not null default true,
  status text not null default 'open',
  evidence_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists reasoning_stop_conditions (
  stop_condition_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  kind text not null,
  triggered boolean not null default false,
  reason text not null default '',
  evidence_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists model_action_traces (
  trace_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  model_id text not null default '',
  provider text not null default '',
  prompt_version text not null default '',
  raw_output_digest text not null default '',
  action jsonb,
  valid boolean not null default false,
  rejection_reason text not null default '',
  hallucinated_reference boolean not null default false,
  unsafe_mutation boolean not null default false,
  invented_evidence boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists report_narratives (
  report_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  target text not null default '',
  objective text not null default '',
  status text not null default 'shadow',
  finding_ids jsonb not null default '[]'::jsonb,
  claim_ids jsonb not null default '[]'::jsonb,
  markdown text not null default '',
  grounding_complete boolean not null default false,
  redaction_leaks integer not null default 0,
  source_digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists report_claims (
  claim_id text primary key,
  report_id text not null references report_narratives(report_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  claim_type text not null,
  text text not null,
  source_candidate_ids jsonb not null default '[]'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  policy_versions jsonb not null default '{}'::jsonb,
  validated boolean not null default false,
  override boolean not null default false,
  grounded boolean not null default false,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists report_claim_evidence (
  claim_id text not null references report_claims(claim_id) on delete restrict,
  evidence_id text not null,
  role text not null default 'supporting',
  created_at timestamptz not null default now(),
  primary key(claim_id, evidence_id, role)
);

create index if not exists idx_reasoning_cycles_session on reasoning_cycles(session_id, created_at desc);
create index if not exists idx_reasoning_hypotheses_cycle on reasoning_hypotheses(cycle_id, status);
create index if not exists idx_reasoning_actions_cycle on reasoning_actions(cycle_id, status);
create index if not exists idx_reasoning_gaps_session on reasoning_evidence_gaps(session_id, status);
create index if not exists idx_model_traces_cycle on model_action_traces(cycle_id, valid);
create index if not exists idx_report_narratives_session on report_narratives(session_id, created_at desc);
create index if not exists idx_report_claims_report on report_claims(report_id, grounded);

drop trigger if exists reasoning_hypotheses_append_only on reasoning_hypotheses;
create trigger reasoning_hypotheses_append_only before update or delete on reasoning_hypotheses for each row execute function nexus_append_only();
drop trigger if exists reasoning_actions_append_only on reasoning_actions;
create trigger reasoning_actions_append_only before update or delete on reasoning_actions for each row execute function nexus_append_only();
drop trigger if exists reasoning_decisions_append_only on reasoning_decisions;
create trigger reasoning_decisions_append_only before update or delete on reasoning_decisions for each row execute function nexus_append_only();
drop trigger if exists reasoning_evidence_gaps_append_only on reasoning_evidence_gaps;
create trigger reasoning_evidence_gaps_append_only before update or delete on reasoning_evidence_gaps for each row execute function nexus_append_only();
drop trigger if exists reasoning_stop_conditions_append_only on reasoning_stop_conditions;
create trigger reasoning_stop_conditions_append_only before update or delete on reasoning_stop_conditions for each row execute function nexus_append_only();
drop trigger if exists model_action_traces_append_only on model_action_traces;
create trigger model_action_traces_append_only before update or delete on model_action_traces for each row execute function nexus_append_only();
drop trigger if exists report_narratives_append_only on report_narratives;
create trigger report_narratives_append_only before update or delete on report_narratives for each row execute function nexus_append_only();
drop trigger if exists report_claims_append_only on report_claims;
create trigger report_claims_append_only before update or delete on report_claims for each row execute function nexus_append_only();
drop trigger if exists report_claim_evidence_append_only on report_claim_evidence;
create trigger report_claim_evidence_append_only before update or delete on report_claim_evidence for each row execute function nexus_append_only();
