-- Stage 16: bounded autonomous reasoning, search branches, and adaptation.
-- Additive only. Run after local acceptance. No RLS is enabled to match the
-- current deployment contract. Branch lineage and adaptation traces are
-- append-only; cycle lifecycle remains the only mutable reasoning record.

alter table if exists reasoning_cycles
  add column if not exists branch_ids jsonb not null default '[]'::jsonb,
  add column if not exists current_branch_id text not null default '',
  add column if not exists search_strategy text not null default 'best_first',
  add column if not exists search_depth integer not null default 0,
  add column if not exists replan_count integer not null default 0,
  add column if not exists budget_snapshot jsonb not null default '{}'::jsonb;

alter table if exists reasoning_hypotheses
  add column if not exists parent_hypothesis_id text not null default '',
  add column if not exists branch_id text not null default '',
  add column if not exists assumptions jsonb not null default '[]'::jsonb,
  add column if not exists expected_outcomes jsonb not null default '[]'::jsonb,
  add column if not exists contradiction_ids jsonb not null default '[]'::jsonb,
  add column if not exists alternative_strategy_ids jsonb not null default '[]'::jsonb,
  add column if not exists search_depth integer not null default 0,
  add column if not exists freshness_boundary text not null default '';

alter table if exists reasoning_actions
  add column if not exists capability_id text not null default '',
  add column if not exists branch_id text not null default '',
  add column if not exists parent_action_id text not null default '',
  add column if not exists target_digest text not null default '',
  add column if not exists input_bindings jsonb not null default '{}'::jsonb,
  add column if not exists expected_observation_kinds jsonb not null default '[]'::jsonb,
  add column if not exists mutation_operator text not null default '',
  add column if not exists approval_digest text not null default '',
  add column if not exists budget_snapshot jsonb not null default '{}'::jsonb;

alter table if exists reasoning_decisions
  add column if not exists selected_branch_id text not null default '',
  add column if not exists score_breakdown jsonb not null default '{}'::jsonb,
  add column if not exists rejected_alternatives jsonb not null default '[]'::jsonb,
  add column if not exists replan_reason text not null default '';

alter table if exists model_action_traces
  add column if not exists unknown_tool boolean not null default false,
  add column if not exists unsupported_capability boolean not null default false,
  add column if not exists stale_context boolean not null default false;

create table if not exists reasoning_branches (
  branch_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  parent_branch_id text not null default '',
  status text not null default 'proposed',
  hypothesis_ids jsonb not null default '[]'::jsonb,
  action_ids jsonb not null default '[]'::jsonb,
  evidence_snapshot_digest text not null default '',
  search_depth integer not null default 0,
  score numeric not null default 0,
  score_breakdown jsonb not null default '{}'::jsonb,
  estimated_cost numeric not null default 0,
  risk_score numeric not null default 0,
  failure_count integer not null default 0,
  backtrack_count integer not null default 0,
  stop_reason text not null default '',
  input_digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists reasoning_branch_transitions (
  transition_id text primary key,
  branch_id text not null references reasoning_branches(branch_id) on delete restrict,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  transition_type text not null,
  from_status text not null default '',
  to_status text not null default '',
  reason text not null default '',
  action_id text not null default '',
  evidence_ids jsonb not null default '[]'::jsonb,
  input_digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists reasoning_adaptations (
  adaptation_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  strategy text not null default 'best_first',
  selected_branch_id text not null default '',
  selected_action_id text not null default '',
  alternative_action_ids jsonb not null default '[]'::jsonb,
  reason text not null default '',
  information_gain numeric not null default 0,
  uncertainty_before numeric not null default 0,
  uncertainty_after numeric not null default 0,
  backtracked boolean not null default false,
  stop_recommended boolean not null default false,
  input_digest text not null default '',
  created_at timestamptz not null default now()
);

create index if not exists idx_reasoning_branches_cycle on reasoning_branches(cycle_id, status, score desc);
create index if not exists idx_reasoning_branches_session on reasoning_branches(session_id, created_at desc);
create index if not exists idx_reasoning_transitions_branch on reasoning_branch_transitions(branch_id, created_at);
create index if not exists idx_reasoning_adaptations_cycle on reasoning_adaptations(cycle_id, created_at desc);
create index if not exists idx_reasoning_actions_branch on reasoning_actions(branch_id, status);

drop trigger if exists reasoning_branches_append_only on reasoning_branches;
create trigger reasoning_branches_append_only before update or delete on reasoning_branches for each row execute function nexus_append_only();
drop trigger if exists reasoning_branch_transitions_append_only on reasoning_branch_transitions;
create trigger reasoning_branch_transitions_append_only before update or delete on reasoning_branch_transitions for each row execute function nexus_append_only();
drop trigger if exists reasoning_adaptations_append_only on reasoning_adaptations;
create trigger reasoning_adaptations_append_only before update or delete on reasoning_adaptations for each row execute function nexus_append_only();
