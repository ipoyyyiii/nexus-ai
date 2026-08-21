-- Tahap 2: dynamic multi-identity authorization graph and differential replay.
-- Additive migration. Raw credentials are never stored in these tables.

create table if not exists identities (
  identity_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  label text not null,
  kind text not null default 'user',
  source text not null default 'user_session',
  role_label text not null default '',
  tenant_label text not null default '',
  status text not null default 'pending',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(session_id, label)
);

create table if not exists identity_claims (
  claim_id text primary key,
  identity_id text not null references identities(identity_id) on delete cascade,
  name text not null,
  value_redacted text not null default '',
  source text not null default 'observation',
  confidence numeric not null default 0.5,
  evidence_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists auth_contexts (
  auth_context_id text primary key,
  identity_id text not null references identities(identity_id) on delete cascade,
  origin text not null,
  auth_type text not null default 'none',
  secret_ref text not null default '',
  secret_fingerprint text not null default '',
  status text not null default 'pending',
  expires_at timestamptz,
  last_checked_at timestamptz,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(identity_id, origin)
);

create table if not exists auth_secret_blobs (
  secret_ref text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  identity_id text not null references identities(identity_id) on delete cascade,
  purpose text not null default 'auth_context',
  algorithm text not null default 'AES-256-GCM',
  nonce_b64 text not null,
  ciphertext_b64 text not null,
  secret_fingerprint text not null,
  expires_at timestamptz not null,
  created_at timestamptz not null default now()
);

create table if not exists authorization_expectations (
  expectation_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  subject_identity_id text not null references identities(identity_id) on delete cascade,
  resource_fingerprint text not null,
  action text not null,
  expected text not null default 'deny',
  source text not null default 'user_asserted',
  reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists request_templates (
  template_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  origin text not null,
  method text not null default 'GET',
  path_template text not null,
  query_template jsonb not null default '{}'::jsonb,
  body_template jsonb,
  header_template jsonb not null default '{}'::jsonb,
  variable_bindings jsonb not null default '{}'::jsonb,
  operation_name text not null default '',
  protocol text not null default 'http',
  side_effect_class text not null default 'unknown',
  source_observation_ids jsonb not null default '[]'::jsonb,
  fingerprint text not null,
  created_at timestamptz not null default now(),
  unique(session_id, fingerprint)
);

create table if not exists resource_instances (
  resource_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  resource_type text not null,
  origin text not null,
  locator_redacted jsonb,
  locator_ref text not null default '',
  fingerprint text not null,
  owner_identity_id text references identities(identity_id) on delete set null,
  tenant_label text not null default '',
  private_canary boolean not null default false,
  source_observation_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  unique(session_id, fingerprint)
);

create table if not exists authorization_edges (
  edge_id uuid primary key default gen_random_uuid(),
  session_id uuid not null references sessions(id) on delete cascade,
  identity_id text not null references identities(identity_id) on delete cascade,
  template_id text not null references request_templates(template_id) on delete cascade,
  resource_fingerprint text not null,
  observed_result text not null,
  evidence_ids jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists authorization_replay_runs (
  replay_run_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  template_id text not null references request_templates(template_id) on delete cascade,
  resource_fingerprint text not null,
  owner_identity_id text not null references identities(identity_id) on delete cascade,
  test_identity_ids jsonb not null default '[]'::jsonb,
  expectation_ids jsonb not null default '[]'::jsonb,
  mutation_approved boolean not null default false,
  status text not null default 'planned',
  created_at timestamptz not null default now()
);

create table if not exists authorization_replay_attempts (
  attempt_id text primary key,
  replay_run_id text not null references authorization_replay_runs(replay_run_id) on delete cascade,
  identity_id text not null references identities(identity_id) on delete cascade,
  auth_context_id text not null default '',
  template_id text not null references request_templates(template_id) on delete cascade,
  resource_fingerprint text not null,
  observation_id text references observations(observation_id) on delete set null,
  status text not null default 'planned',
  response_status integer,
  semantic_result text not null default 'unknown',
  comparison jsonb not null default '{}'::jsonb,
  side_effects jsonb not null default '[]'::jsonb,
  cleanup_refs jsonb not null default '[]'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_identities_session on identities(session_id, status);
create index if not exists idx_auth_contexts_identity on auth_contexts(identity_id, status);
create index if not exists idx_request_templates_session on request_templates(session_id, created_at desc);
create index if not exists idx_resources_session_owner on resource_instances(session_id, owner_identity_id);
create index if not exists idx_replay_runs_session on authorization_replay_runs(session_id, created_at desc);
create index if not exists idx_replay_attempts_run on authorization_replay_attempts(replay_run_id, created_at);

