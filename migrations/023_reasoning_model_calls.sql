-- Phase 1: provider-attempt telemetry for the AI-native reasoning loop.
-- Additive only. Prompt/completion bodies are deliberately not persisted.

create table if not exists reasoning_model_calls (
  call_id text primary key,
  cycle_id text not null references reasoning_cycles(cycle_id) on delete restrict,
  session_id uuid not null references sessions(id) on delete cascade,
  job_id uuid,
  model_id text not null default '',
  provider text not null default '',
  prompt_version text not null default '',
  attempt_number integer not null default 1,
  fallback_index integer not null default 0,
  status text not null default 'failed',
  input_digest text not null default '',
  output_digest text not null default '',
  latency_ms numeric not null default 0,
  error_code text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_reasoning_model_calls_cycle
  on reasoning_model_calls(cycle_id, created_at);
create index if not exists idx_reasoning_model_calls_session
  on reasoning_model_calls(session_id, created_at desc);

drop trigger if exists reasoning_model_calls_append_only on reasoning_model_calls;
create trigger reasoning_model_calls_append_only
  before update or delete on reasoning_model_calls
  for each row execute function nexus_append_only();
