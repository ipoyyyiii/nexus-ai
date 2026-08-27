-- Stage 26: identity, session, auth-boundary, and workflow intelligence.
-- Additive only. Apply after migration 021. Raw credentials, cookies, tokens,
-- PKCE verifiers, and redirect values are never stored here.

create table if not exists auth_surface_observations (
  observation_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  origin text not null,
  endpoint_reference_id text not null default '',
  event text not null default 'unknown',
  mechanism text not null default 'unknown',
  auth_state text not null default 'unknown',
  identity_id text not null default '',
  auth_context_id text not null default '',
  redirect_uri_digest text not null default '',
  issuer_digest text not null default '',
  audience_digest text not null default '',
  evidence_ids jsonb not null default '[]'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  status text not null default 'observed',
  confidence numeric not null default 0.5,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists auth_session_transitions (
  transition_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  identity_id text not null default '',
  auth_context_id text not null default '',
  origin text not null default '',
  event text not null default 'unknown',
  before_status text not null default 'unknown',
  after_status text not null default 'unknown',
  evidence_ids jsonb not null default '[]'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  clean_context boolean not null default false,
  state_digest text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists workflow_prerequisite_versions (
  prerequisite_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  workflow_id text not null references browser_workflows(workflow_id) on delete restrict,
  workflow_version integer not null default 1,
  kind text not null,
  reference_id text not null default '',
  label text not null default '',
  required boolean not null default true,
  status text not null default 'observed',
  evidence_ids jsonb not null default '[]'::jsonb,
  source_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table if exists browser_workflows add column if not exists workflow_class text not null default 'unknown';
alter table if exists browser_workflows add column if not exists required_role_labels jsonb not null default '[]'::jsonb;
alter table if exists browser_workflows add column if not exists required_tenant_labels jsonb not null default '[]'::jsonb;
alter table if exists browser_workflows add column if not exists state_graph jsonb not null default '{}'::jsonb;
alter table if exists browser_workflows add column if not exists auth_surface_ids jsonb not null default '[]'::jsonb;
alter table if exists browser_workflows add column if not exists prerequisite_ids jsonb not null default '[]'::jsonb;
alter table if exists browser_workflows add column if not exists ambiguity_reasons jsonb not null default '[]'::jsonb;

create index if not exists idx_auth_surface_session_event on auth_surface_observations(session_id, event, created_at desc);
create index if not exists idx_auth_surface_identity on auth_surface_observations(session_id, identity_id, auth_context_id);
create index if not exists idx_auth_transition_session on auth_session_transitions(session_id, created_at desc);
create index if not exists idx_auth_transition_context on auth_session_transitions(session_id, auth_context_id, event);
create index if not exists idx_workflow_prereq_session on workflow_prerequisite_versions(session_id, workflow_id, workflow_version);
create index if not exists idx_workflow_prereq_status on workflow_prerequisite_versions(session_id, status, created_at desc);

drop trigger if exists auth_surface_observations_append_only on auth_surface_observations;
create trigger auth_surface_observations_append_only before update or delete on auth_surface_observations
for each row execute function nexus_append_only();
drop trigger if exists auth_session_transitions_append_only on auth_session_transitions;
create trigger auth_session_transitions_append_only before update or delete on auth_session_transitions
for each row execute function nexus_append_only();
drop trigger if exists workflow_prerequisite_versions_append_only on workflow_prerequisite_versions;
create trigger workflow_prerequisite_versions_append_only before update or delete on workflow_prerequisite_versions
for each row execute function nexus_append_only();
