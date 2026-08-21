-- Tahap 1: structured tool runs and deterministic validation evidence.
-- Run this migration in the Supabase SQL editor before enabling strict mode.

create table if not exists tool_runs (
  tool_run_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  job_id text,
  tool_name text not null,
  tool_version text not null default '1',
  category text not null default 'unknown',
  target text not null,
  status text not null,
  started_at timestamptz not null,
  finished_at timestamptz,
  inputs_redacted jsonb not null default '{}'::jsonb,
  summary text not null default '',
  metrics jsonb not null default '{}'::jsonb,
  errors jsonb not null default '[]'::jsonb,
  side_effects jsonb not null default '[]'::jsonb,
  cleanup_refs jsonb not null default '[]'::jsonb,
  legacy_source boolean not null default false,
  created_at timestamptz not null default now()
);

create table if not exists evidence_artifacts (
  artifact_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  tool_run_id text references tool_runs(tool_run_id) on delete set null,
  kind text not null,
  mime_type text not null default 'text/plain',
  sha256 text not null default '',
  size_bytes integer not null default 0,
  excerpt text not null default '',
  storage_uri text not null default '',
  redacted boolean not null default true,
  retention_until timestamptz,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists observations (
  observation_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  tool_run_id text not null references tool_runs(tool_run_id) on delete cascade,
  role text not null,
  kind text not null,
  summary text not null default '',
  target_url text not null default '',
  method text not null default 'GET',
  request_excerpt text not null default '',
  response_excerpt text not null default '',
  status_code integer,
  response_time_ms numeric,
  payload_hash text not null default '',
  artifact_ids jsonb not null default '[]'::jsonb,
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create table if not exists candidate_findings (
  candidate_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  tool_run_id text references tool_runs(tool_run_id) on delete set null,
  title text not null,
  vuln_type text not null,
  severity text not null default 'INFO',
  target_url text not null default '',
  method text not null default 'GET',
  parameter text not null default '',
  injection_point text not null default '',
  fingerprint text not null,
  status text not null default 'suspected',
  confidence_score numeric not null default 0.5,
  confidence_reasons jsonb not null default '[]'::jsonb,
  remediation text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique(session_id, fingerprint)
);

create table if not exists candidate_evidence (
  candidate_id text not null references candidate_findings(candidate_id) on delete cascade,
  observation_id text not null references observations(observation_id) on delete cascade,
  primary key(candidate_id, observation_id)
);

create table if not exists validation_runs (
  validation_run_id text primary key,
  candidate_id text not null references candidate_findings(candidate_id) on delete cascade,
  policy_id text not null,
  policy_version text not null,
  decision text not null,
  score numeric not null default 0,
  reason text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists validation_checks (
  validation_run_id text not null references validation_runs(validation_run_id) on delete cascade,
  check_name text not null,
  passed boolean not null,
  details jsonb not null default '{}'::jsonb,
  primary key(validation_run_id, check_name)
);

create table if not exists finding_reviews (
  review_id uuid primary key default gen_random_uuid(),
  candidate_id text not null references candidate_findings(candidate_id) on delete cascade,
  decision text not null,
  reason text not null,
  reviewer text not null default 'api',
  created_at timestamptz not null default now()
);

create index if not exists idx_tool_runs_session on tool_runs(session_id, created_at desc);
create index if not exists idx_candidates_session_status on candidate_findings(session_id, status, updated_at desc);
