  -- Stage 14: mission control and bounded attack-path graph.
  -- Additive, forward-only migration. Apply after migration 013.
  -- RLS intentionally remains unchanged; only the backend/worker service
  -- credential may access these tables.

  create table if not exists missions (
    mission_id text primary key,
    session_id uuid not null references sessions(id) on delete cascade,
    target text not null,
    objective text not null,
    status text not null default 'draft',
    graph_version integer not null default 0,
    graph_digest text not null default '',
    risk_profile text not null default 'bounded_autonomy',
    budget jsonb not null default '{}'::jsonb,
    deadline_at timestamptz,
    config_digest text not null default '',
    policy_version text not null default '1.0',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
  );

  create table if not exists mission_versions (
    mission_version_id text primary key default ('mversion_' || gen_random_uuid()::text),
    mission_id text not null references missions(mission_id) on delete restrict,
    session_id uuid not null references sessions(id) on delete cascade,
    version integer not null,
    graph_digest text not null,
    objective text not null default '',
    config_digest text not null default '',
    policy_version text not null default '1.0',
    created_at timestamptz not null default now(),
    unique(mission_id, version)
  );

  create table if not exists attack_graph_nodes (
    node_id text primary key,
    mission_id text not null references missions(mission_id) on delete restrict,
    session_id uuid not null references sessions(id) on delete cascade,
    graph_version integer not null,
    node_type text not null,
    reference_id text not null,
    label text not null default '',
    status text not null default 'hypothesized',
    evidence_ids jsonb not null default '[]'::jsonb,
    identity_id text not null default '',
    tenant_label text not null default '',
    protocol text not null default 'http',
    metadata jsonb not null default '{}'::jsonb,
    fingerprint text not null,
    created_at timestamptz not null default now(),
    unique(mission_id, graph_version, fingerprint)
  );

  create table if not exists attack_graph_edges (
    edge_id text primary key,
    mission_id text not null references missions(mission_id) on delete restrict,
    session_id uuid not null references sessions(id) on delete cascade,
    graph_version integer not null,
    source_node_id text not null,
    target_node_id text not null,
    relation text not null,
    status text not null default 'hypothesized',
    evidence_ids jsonb not null default '[]'::jsonb,
    required_action_ids jsonb not null default '[]'::jsonb,
    preconditions jsonb not null default '[]'::jsonb,
    required_identity_ids jsonb not null default '[]'::jsonb,
    risk text not null default 'read_only',
    cleanup_refs jsonb not null default '[]'::jsonb,
    reason text not null default '',
    deterministic boolean not null default true,
    fingerprint text not null,
    created_at timestamptz not null default now(),
    unique(mission_id, graph_version, fingerprint)
  );

  create table if not exists attack_paths (
    path_id text primary key,
    mission_id text not null references missions(mission_id) on delete restrict,
    session_id uuid not null references sessions(id) on delete cascade,
    graph_version integer not null,
    edge_ids jsonb not null default '[]'::jsonb,
    node_ids jsonb not null default '[]'::jsonb,
    objective text not null default '',
    status text not null default 'proposed',
    score numeric not null default 0,
    score_breakdown jsonb not null default '{}'::jsonb,
    required_evidence_ids jsonb not null default '[]'::jsonb,
    required_identity_ids jsonb not null default '[]'::jsonb,
    required_approval boolean not null default false,
    approval_digest text not null default '',
    budget jsonb not null default '{}'::jsonb,
    cleanup_refs jsonb not null default '[]'::jsonb,
    stop_conditions jsonb not null default '[]'::jsonb,
    stale_reason text not null default '',
    path_digest text not null,
    created_at timestamptz not null default now(),
    unique(mission_id, path_digest)
  );

  create table if not exists mission_decisions (
    decision_id text primary key,
    mission_id text not null references missions(mission_id) on delete restrict,
    session_id uuid not null references sessions(id) on delete cascade,
    graph_version integer not null,
    decision_type text not null,
    selected_path_id text not null default '',
    selected_edge_id text not null default '',
    selected_action_id text not null default '',
    considered_paths jsonb not null default '[]'::jsonb,
    rejected_alternatives jsonb not null default '[]'::jsonb,
    evidence_gap_ids jsonb not null default '[]'::jsonb,
    reason text not null default '',
    expected_information_gain numeric not null default 0,
    estimated_cost numeric not null default 0,
    risk_score numeric not null default 0,
    deterministic boolean not null default true,
    input_digest text not null default '',
    output_digest text not null default '',
    created_at timestamptz not null default now()
  );

  create table if not exists mission_events (
    event_id text primary key,
    mission_id text not null references missions(mission_id) on delete restrict,
    session_id uuid not null references sessions(id) on delete cascade,
    graph_version integer not null default 0,
    event_type text not null,
    path_id text not null default '',
    edge_id text not null default '',
    decision_id text not null default '',
    job_id uuid,
    attempt_id text not null default '',
    checkpoint_id text not null default '',
    payload jsonb not null default '{}'::jsonb,
    created_at timestamptz not null default now()
  );

  create index if not exists idx_missions_session_status on missions(session_id, status, updated_at desc);
  create index if not exists idx_mission_versions_mission on mission_versions(mission_id, version desc);
  create index if not exists idx_graph_nodes_mission_version on attack_graph_nodes(mission_id, graph_version, node_type);
  create index if not exists idx_graph_nodes_reference on attack_graph_nodes(session_id, reference_id);
  create index if not exists idx_graph_edges_mission_version on attack_graph_edges(mission_id, graph_version, relation);
  create index if not exists idx_attack_paths_mission_status on attack_paths(mission_id, status, created_at desc);
  create index if not exists idx_mission_decisions_mission on mission_decisions(mission_id, created_at desc);
  create index if not exists idx_mission_events_mission on mission_events(mission_id, created_at);

  drop trigger if exists mission_versions_append_only on mission_versions;
  create trigger mission_versions_append_only before update or delete on mission_versions
  for each row execute function nexus_append_only();
  drop trigger if exists attack_graph_nodes_append_only on attack_graph_nodes;
  create trigger attack_graph_nodes_append_only before update or delete on attack_graph_nodes
  for each row execute function nexus_append_only();
  drop trigger if exists attack_graph_edges_append_only on attack_graph_edges;
  create trigger attack_graph_edges_append_only before update or delete on attack_graph_edges
  for each row execute function nexus_append_only();
  drop trigger if exists attack_paths_append_only on attack_paths;
  create trigger attack_paths_append_only before update or delete on attack_paths
  for each row execute function nexus_append_only();
  drop trigger if exists mission_decisions_append_only on mission_decisions;
  create trigger mission_decisions_append_only before update or delete on mission_decisions
  for each row execute function nexus_append_only();
  drop trigger if exists mission_events_append_only on mission_events;
  create trigger mission_events_append_only before update or delete on mission_events
  for each row execute function nexus_append_only();
