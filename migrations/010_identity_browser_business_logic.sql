-- Tahap 10: identity graph, cross-identity browser matrix, and business state.
-- Additive only. Do not run automatically during application startup.

create table if not exists identity_graph_versions (
  graph_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  version integer not null,
  node_ids jsonb not null default '[]'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  gaps jsonb not null default '[]'::jsonb,
  digest text not null,
  created_at timestamptz not null default now(),
  unique(session_id, version),
  unique(session_id, digest)
);

create table if not exists identity_graph_edges (
  relation_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  graph_id text not null references identity_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  subject_id text not null references identities(identity_id) on delete restrict,
  relation text not null,
  object_id text not null,
  evidence_ids jsonb not null default '[]'::jsonb,
  source text not null default 'observation',
  confidence numeric not null default 0.5,
  status text not null default 'proposed',
  created_at timestamptz not null default now()
);

create table if not exists identity_coverage_plans (
  plan_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  graph_id text not null references identity_graph_versions(graph_id) on delete restrict,
  required_identity_ids jsonb not null default '[]'::jsonb,
  required_relations jsonb not null default '[]'::jsonb,
  required_resource_fingerprints jsonb not null default '[]'::jsonb,
  required_auth_context_ids jsonb not null default '[]'::jsonb,
  missing_requirements jsonb not null default '[]'::jsonb,
  status text not null default 'blocked',
  digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists workflow_run_matrices (
  matrix_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  workflow_id text not null references browser_workflows(workflow_id) on delete restrict,
  workflow_version integer not null,
  graph_id text not null references identity_graph_versions(graph_id) on delete restrict,
  entity_fingerprint text not null default '',
  run_roles jsonb not null default '{}'::jsonb,
  identity_ids jsonb not null default '[]'::jsonb,
  auth_context_ids jsonb not null default '[]'::jsonb,
  required_roles jsonb not null default '[]'::jsonb,
  cleanup_required boolean not null default false,
  cleanup_verified boolean not null default false,
  approval_digest text not null default '',
  status text not null default 'planned',
  missing_requirements jsonb not null default '[]'::jsonb,
  run_ids jsonb not null default '[]'::jsonb,
  digest text not null,
  created_at timestamptz not null default now()
);

create table if not exists business_entity_versions (
  entity_version_id text primary key,
  entity_id text not null references business_entities(entity_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  fingerprint text not null,
  graph_id text not null default '',
  identity_ids jsonb not null default '[]'::jsonb,
  state_digest text not null default '',
  fields_redacted jsonb not null default '{}'::jsonb,
  source_snapshot_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists business_invariant_versions (
  invariant_version_id text primary key,
  invariant_id text not null references business_invariants(invariant_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  revision integer not null,
  compiler_version text not null default '1.1',
  rule_type text not null,
  rule jsonb not null default '{}'::jsonb,
  compiled boolean not null default false,
  input_digest text not null default '',
  created_at timestamptz not null default now(),
  unique(invariant_id, revision)
);

alter table if exists browser_runs add column if not exists graph_id text not null default '';
alter table if exists browser_runs add column if not exists matrix_id text not null default '';
alter table if exists browser_runs add column if not exists entity_fingerprints jsonb not null default '[]'::jsonb;
alter table if exists browser_runs add column if not exists clean_context boolean not null default false;
alter table if exists browser_state_snapshots add column if not exists identity_id text not null default '';
alter table if exists browser_state_snapshots add column if not exists graph_id text not null default '';
alter table if exists browser_state_snapshots add column if not exists tenant_label text not null default '';
alter table if exists browser_state_snapshots add column if not exists state_digest text not null default '';
alter table if exists business_entities add column if not exists state_digest text not null default '';
alter table if exists business_entities add column if not exists graph_id text not null default '';
alter table if exists business_entities add column if not exists identity_ids jsonb not null default '[]'::jsonb;
alter table if exists business_state_transitions add column if not exists entity_fingerprint text not null default '';
alter table if exists business_state_transitions add column if not exists identity_id text not null default '';
alter table if exists business_state_transitions add column if not exists tenant_label text not null default '';
alter table if exists business_state_transitions add column if not exists graph_id text not null default '';
alter table if exists business_state_transitions add column if not exists clean_context boolean not null default false;
alter table if exists business_state_transitions add column if not exists state_digest text not null default '';
alter table if exists business_invariants add column if not exists required_role_labels jsonb not null default '[]'::jsonb;
alter table if exists business_invariants add column if not exists required_tenant_labels jsonb not null default '[]'::jsonb;
alter table if exists business_invariants add column if not exists required_entity_fingerprints jsonb not null default '[]'::jsonb;
alter table if exists business_invariants add column if not exists graph_id text not null default '';
alter table if exists business_invariants add column if not exists workflow_matrix_id text not null default '';
alter table if exists business_invariants add column if not exists compiler_version text not null default '1.1';
alter table if exists business_invariants add column if not exists compiled boolean not null default false;
alter table if exists invariant_evaluations add column if not exists graph_id text not null default '';
alter table if exists invariant_evaluations add column if not exists workflow_matrix_id text not null default '';
alter table if exists invariant_evaluations add column if not exists compiler_version text not null default '1.1';
alter table if exists invariant_evaluations add column if not exists input_digest text not null default '';
alter table if exists invariant_evaluations add column if not exists cleanup_status text not null default 'unknown';

create index if not exists idx_identity_graph_session on identity_graph_versions(session_id, version desc);
create index if not exists idx_identity_graph_edges_graph on identity_graph_edges(session_id, graph_id, relation);
create index if not exists idx_identity_coverage_session on identity_coverage_plans(session_id, created_at desc);
create index if not exists idx_workflow_matrices_session on workflow_run_matrices(session_id, created_at desc);
create index if not exists idx_workflow_matrices_entity on workflow_run_matrices(session_id, entity_fingerprint);
create index if not exists idx_business_entity_versions_entity on business_entity_versions(session_id, fingerprint, created_at desc);
create index if not exists idx_business_invariant_versions on business_invariant_versions(session_id, invariant_id, revision desc);

drop trigger if exists identity_graph_versions_append_only on identity_graph_versions;
create trigger identity_graph_versions_append_only
before update or delete on identity_graph_versions
for each row execute function nexus_append_only();
drop trigger if exists identity_graph_edges_append_only on identity_graph_edges;
create trigger identity_graph_edges_append_only
before update or delete on identity_graph_edges
for each row execute function nexus_append_only();
drop trigger if exists business_entity_versions_append_only on business_entity_versions;
create trigger business_entity_versions_append_only
before update or delete on business_entity_versions
for each row execute function nexus_append_only();
drop trigger if exists business_invariant_versions_append_only on business_invariant_versions;
create trigger business_invariant_versions_append_only
before update or delete on business_invariant_versions
for each row execute function nexus_append_only();
