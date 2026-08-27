-- Stage 15: target knowledge graph and coverage closure.
-- Additive and forward-only. Apply after migration 014.
-- No RLS changes: backend/worker service credentials remain the only writers.

create table if not exists target_knowledge_graph_versions (
  graph_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  target_fingerprint text not null,
  scope_fingerprint text not null default '',
  version integer not null,
  parent_graph_id text not null default '',
  node_ids jsonb not null default '[]'::jsonb,
  edge_ids jsonb not null default '[]'::jsonb,
  contradiction_ids jsonb not null default '[]'::jsonb,
  coverage_snapshot_id text not null default '',
  source_digests jsonb not null default '[]'::jsonb,
  digest text not null,
  status text not null default 'draft',
  policy_version text not null default '15.0',
  created_at timestamptz not null default now(),
  unique(session_id, version),
  unique(session_id, digest)
);

create table if not exists target_knowledge_nodes (
  node_id text primary key,
  graph_id text not null references target_knowledge_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  session_id uuid not null references sessions(id) on delete cascade,
  node_type text not null,
  reference_id text not null,
  canonical_locator text not null default '',
  label text not null default '',
  protocol text not null default 'http',
  method text not null default '',
  parameter_location text not null default '',
  parameter_name text not null default '',
  identity_id text not null default '',
  tenant_label text not null default '',
  entity_fingerprint text not null default '',
  status text not null default 'observed',
  evidence_ids jsonb not null default '[]'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  fingerprint text not null,
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique(graph_id, fingerprint)
);

create table if not exists target_knowledge_edges (
  edge_id text primary key,
  graph_id text not null references target_knowledge_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  session_id uuid not null references sessions(id) on delete cascade,
  source_node_id text not null references target_knowledge_nodes(node_id) on delete restrict,
  target_node_id text not null references target_knowledge_nodes(node_id) on delete restrict,
  relation text not null,
  status text not null default 'observed',
  evidence_ids jsonb not null default '[]'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  fingerprint text not null,
  observed_at timestamptz not null default now(),
  created_at timestamptz not null default now(),
  unique(graph_id, fingerprint)
);

create table if not exists target_knowledge_source_links (
  link_id text primary key,
  graph_id text not null references target_knowledge_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  session_id uuid not null references sessions(id) on delete cascade,
  node_id text not null default '',
  edge_id text not null default '',
  source_kind text not null default 'observation',
  source_id text not null,
  evidence_ids jsonb not null default '[]'::jsonb,
  input_digest text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists target_knowledge_contradictions (
  contradiction_id text primary key,
  graph_id text not null references target_knowledge_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  session_id uuid not null references sessions(id) on delete cascade,
  subject_fingerprint text not null,
  predicate text not null,
  conflicting_node_ids jsonb not null default '[]'::jsonb,
  conflicting_edge_ids jsonb not null default '[]'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  status text not null default 'unresolved',
  review_reason text not null default '',
  reviewer_id text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists target_knowledge_contradiction_reviews (
  review_id text primary key,
  contradiction_id text not null references target_knowledge_contradictions(contradiction_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  status text not null,
  reviewer_id text not null,
  reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists target_coverage_snapshots (
  coverage_snapshot_id text primary key,
  graph_id text not null references target_knowledge_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  session_id uuid not null references sessions(id) on delete cascade,
  target_fingerprint text not null,
  coverage_ids jsonb not null default '[]'::jsonb,
  gap_ids jsonb not null default '[]'::jsonb,
  digest text not null,
  created_at timestamptz not null default now(),
  unique(graph_id, digest)
);

create table if not exists target_coverage_items (
  coverage_id text primary key,
  graph_id text not null references target_knowledge_graph_versions(graph_id) on delete restrict,
  graph_version integer not null,
  session_id uuid not null references sessions(id) on delete cascade,
  target_fingerprint text not null,
  asset_node_id text not null default '',
  endpoint_node_id text not null default '',
  operation_node_id text not null default '',
  parameter_node_id text not null default '',
  identity_id text not null default '',
  auth_context_id text not null default '',
  tenant_label text not null default '',
  entity_fingerprint text not null default '',
  workflow_id text not null default '',
  state_label text not null default '',
  protocol text not null default 'http',
  policy_id text not null default '',
  status text not null default 'untested',
  evidence_ids jsonb not null default '[]'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  required_prerequisites jsonb not null default '[]'::jsonb,
  gap_reason text not null default '',
  last_tested_at timestamptz,
  input_digest text not null default '',
  fingerprint text not null,
  created_at timestamptz not null default now(),
  unique(graph_id, fingerprint)
);

create table if not exists target_memory_records (
  memory_id text primary key,
  session_id uuid references sessions(id) on delete cascade,
  source_session_id uuid references sessions(id) on delete set null,
  target_fingerprint text not null,
  scope_fingerprint text not null default '',
  graph_id text not null default '',
  graph_version integer not null default 0,
  memory_type text not null,
  content jsonb not null default '{}'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  evidence_ids jsonb not null default '[]'::jsonb,
  source_digest text not null,
  status text not null default 'current',
  observed_at timestamptz not null default now(),
  expires_at timestamptz,
  created_at timestamptz not null default now()
);

alter table if exists session_memory add column if not exists target_fingerprint text;
alter table if exists session_memory add column if not exists scope_fingerprint text not null default '';
alter table if exists session_memory add column if not exists graph_id text not null default '';
alter table if exists session_memory add column if not exists graph_version integer not null default 0;
alter table if exists session_memory add column if not exists source_ids jsonb not null default '[]'::jsonb;
alter table if exists session_memory add column if not exists evidence_ids jsonb not null default '[]'::jsonb;
alter table if exists session_memory add column if not exists source_digest text not null default '';
alter table if exists session_memory add column if not exists memory_status text not null default 'historical';
alter table if exists session_memory add column if not exists expires_at timestamptz;

create index if not exists idx_knowledge_graph_session on target_knowledge_graph_versions(session_id, version desc);
create index if not exists idx_knowledge_graph_target on target_knowledge_graph_versions(target_fingerprint, created_at desc);
create index if not exists idx_knowledge_nodes_session_type on target_knowledge_nodes(session_id, node_type, created_at desc);
create index if not exists idx_knowledge_nodes_locator on target_knowledge_nodes(session_id, canonical_locator);
create index if not exists idx_knowledge_edges_session_relation on target_knowledge_edges(session_id, relation, created_at desc);
create index if not exists idx_knowledge_contradictions_session_status on target_knowledge_contradictions(session_id, status, created_at desc);
create index if not exists idx_coverage_session_status on target_coverage_items(session_id, status, created_at desc);
create index if not exists idx_coverage_dimensions on target_coverage_items(session_id, endpoint_node_id, identity_id, tenant_label);
create index if not exists idx_memory_target_freshness on target_memory_records(target_fingerprint, status, expires_at);
create index if not exists idx_legacy_memory_target_fingerprint on session_memory(target_fingerprint, memory_status, expires_at);

drop trigger if exists target_knowledge_graph_append_only on target_knowledge_graph_versions;
create trigger target_knowledge_graph_append_only before update or delete on target_knowledge_graph_versions
for each row execute function nexus_append_only();
drop trigger if exists target_knowledge_nodes_append_only on target_knowledge_nodes;
create trigger target_knowledge_nodes_append_only before update or delete on target_knowledge_nodes
for each row execute function nexus_append_only();
drop trigger if exists target_knowledge_edges_append_only on target_knowledge_edges;
create trigger target_knowledge_edges_append_only before update or delete on target_knowledge_edges
for each row execute function nexus_append_only();
drop trigger if exists target_knowledge_source_links_append_only on target_knowledge_source_links;
create trigger target_knowledge_source_links_append_only before update or delete on target_knowledge_source_links
for each row execute function nexus_append_only();
drop trigger if exists target_knowledge_contradictions_append_only on target_knowledge_contradictions;
create trigger target_knowledge_contradictions_append_only before update or delete on target_knowledge_contradictions
for each row execute function nexus_append_only();
drop trigger if exists target_knowledge_reviews_append_only on target_knowledge_contradiction_reviews;
create trigger target_knowledge_reviews_append_only before update or delete on target_knowledge_contradiction_reviews
for each row execute function nexus_append_only();
drop trigger if exists target_coverage_snapshots_append_only on target_coverage_snapshots;
create trigger target_coverage_snapshots_append_only before update or delete on target_coverage_snapshots
for each row execute function nexus_append_only();
drop trigger if exists target_coverage_items_append_only on target_coverage_items;
create trigger target_coverage_items_append_only before update or delete on target_coverage_items
for each row execute function nexus_append_only();
drop trigger if exists target_memory_records_append_only on target_memory_records;
create trigger target_memory_records_append_only before update or delete on target_memory_records
for each row execute function nexus_append_only();
