-- Stage 18: identity, browser, business logic, and impact-chain validation.
-- Additive only. Apply after local acceptance. No RLS is enabled here to match
-- the current deployment contract; service credentials remain backend-only.

alter table if exists attack_chains
  add column if not exists mission_id text not null default '',
  add column if not exists identity_graph_digest text not null default '',
  add column if not exists knowledge_graph_digest text not null default '',
  add column if not exists workflow_matrix_id text not null default '',
  add column if not exists path_score double precision not null default 0,
  add column if not exists score_breakdown jsonb not null default '{}'::jsonb,
  add column if not exists impact_status text not null default 'inconclusive',
  add column if not exists reproduction_status text not null default 'unknown',
  add column if not exists cleanup_status text not null default 'unknown',
  add column if not exists input_digest text not null default '';

alter table if exists attack_chain_versions
  add column if not exists mission_id text not null default '',
  add column if not exists identity_graph_digest text not null default '',
  add column if not exists knowledge_graph_digest text not null default '',
  add column if not exists workflow_matrix_id text not null default '',
  add column if not exists path_score double precision not null default 0,
  add column if not exists score_breakdown jsonb not null default '{}'::jsonb,
  add column if not exists input_digest text not null default '';

alter table if exists attack_chain_nodes
  add column if not exists capability text not null default '',
  add column if not exists role text not null default '',
  add column if not exists state_digest text not null default '',
  add column if not exists resource_fingerprint text not null default '';

alter table if exists attack_chain_edges
  add column if not exists preconditions jsonb not null default '[]'::jsonb,
  add column if not exists required_identity_ids jsonb not null default '[]'::jsonb,
  add column if not exists risk text not null default 'read_only',
  add column if not exists cleanup_refs jsonb not null default '[]'::jsonb,
  add column if not exists impact_role text not null default '';

alter table if exists chain_evaluations
  add column if not exists impact_status text not null default 'inconclusive',
  add column if not exists reproduction_status text not null default 'unknown',
  add column if not exists cleanup_status text not null default 'unknown',
  add column if not exists score double precision not null default 0,
  add column if not exists failure_classification text not null default '',
  add column if not exists mandatory_check_count integer not null default 0,
  add column if not exists passed_check_count integer not null default 0;

alter table if exists impact_proof_plans
  add column if not exists chain_version integer not null default 1,
  add column if not exists graph_digest text not null default '',
  add column if not exists workflow_matrix_id text not null default '',
  add column if not exists required_evidence_roles jsonb not null default '[]'::jsonb,
  add column if not exists expected_effect jsonb not null default '{}'::jsonb,
  add column if not exists state_fingerprint text not null default '';

alter table if exists impact_proof_attempts
  add column if not exists chain_version integer not null default 1,
  add column if not exists state_comparison jsonb not null default '{}'::jsonb,
  add column if not exists effect_count integer not null default 0,
  add column if not exists reproduction_attempt_id text not null default '',
  add column if not exists cleanup_evidence_ids jsonb not null default '[]'::jsonb;

create table if not exists chain_impact_observations (
  impact_observation_id text primary key,
  chain_id text not null references attack_chains(chain_id) on delete restrict,
  chain_version integer not null default 1,
  session_id uuid not null references sessions(id) on delete cascade,
  plan_id text references impact_proof_plans(plan_id) on delete restrict,
  attempt_id text references impact_proof_attempts(attempt_id) on delete restrict,
  role text not null,
  identity_id text not null default '',
  auth_context_id text not null default '',
  tenant_label text not null default '',
  entity_fingerprint text not null default '',
  state_digest text not null default '',
  effect_fingerprint text not null default '',
  effect_count integer not null default 0,
  clean_context boolean not null default false,
  cleanup_verified boolean not null default false,
  evidence_ids jsonb not null default '[]'::jsonb,
  redacted_state jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_attack_chains_identity_matrix
  on attack_chains(session_id, workflow_matrix_id, updated_at desc);
create index if not exists idx_attack_chains_impact_status
  on attack_chains(session_id, impact_status, path_score desc);
create index if not exists idx_chain_evaluations_impact
  on chain_evaluations(session_id, impact_status, cleanup_status, created_at desc);
create index if not exists idx_impact_plans_chain_version
  on impact_proof_plans(session_id, chain_id, chain_version, created_at desc);
create index if not exists idx_impact_observations_chain_role
  on chain_impact_observations(session_id, chain_id, chain_version, role, created_at desc);
create index if not exists idx_impact_observations_entity
  on chain_impact_observations(session_id, entity_fingerprint, identity_id, created_at desc);

drop trigger if exists chain_impact_observations_append_only on chain_impact_observations;
create trigger chain_impact_observations_append_only
before update or delete on chain_impact_observations
for each row execute function nexus_append_only();

