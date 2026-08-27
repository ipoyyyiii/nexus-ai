-- Stage 17: semantic detection and native modern protocol evidence.
-- Additive only. Apply after local acceptance; deployment currently runs without RLS.

alter table if exists protocol_operations
  add column if not exists parser_context text not null default 'unknown',
  add column if not exists content_type text not null default '',
  add column if not exists schema_digest text not null default '',
  add column if not exists discovered_from text not null default 'observation',
  add column if not exists scope_fingerprint text not null default '';

alter table if exists payload_proposals
  add column if not exists parser_context text not null default 'unknown',
  add column if not exists parameter_location text not null default '',
  add column if not exists mutation_operator text not null default '',
  add column if not exists schema_digest text not null default '',
  add column if not exists approval_digest text not null default '';

alter table if exists payload_attempts
  add column if not exists control_role text not null default '',
  add column if not exists reproduction_of text not null default '',
  add column if not exists comparison_ids jsonb not null default '[]'::jsonb,
  add column if not exists cleanup_status text not null default 'pending';

create table if not exists protocol_comparisons (
  comparison_id text primary key,
  session_id uuid not null references sessions(id) on delete cascade,
  operation_id text references protocol_operations(operation_id) on delete restrict,
  tool_run_id text not null default '',
  job_id uuid,
  attempt_id text not null default '',
  protocol text not null,
  baseline_exchange_id text not null default '',
  test_exchange_id text not null default '',
  control_exchange_id text not null default '',
  reproduction_exchange_id text not null default '',
  changed_dimensions jsonb not null default '[]'::jsonb,
  stable_dimensions jsonb not null default '[]'::jsonb,
  noise_ratio numeric not null default 0,
  signal_strength numeric not null default 0,
  semantic_signal boolean not null default false,
  status_only_signal boolean not null default false,
  length_only_signal boolean not null default false,
  replay_stable boolean not null default false,
  evidence_ids jsonb not null default '[]'::jsonb,
  input_digest text not null default '',
  metadata jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

alter table if exists validation_runs
  add column if not exists protocol text not null default '',
  add column if not exists operation_id text not null default '',
  add column if not exists comparison_id text not null default '',
  add column if not exists input_digest text not null default '',
  add column if not exists failure_classification text not null default '';

alter table if exists validation_checks
  add column if not exists evidence_ids jsonb not null default '[]'::jsonb,
  add column if not exists observation_ids jsonb not null default '[]'::jsonb,
  add column if not exists input_digest text not null default '',
  add column if not exists failure_classification text not null default '';

create index if not exists idx_protocol_operations_parser on protocol_operations(session_id, protocol, parser_context, created_at desc);
create index if not exists idx_protocol_comparisons_session on protocol_comparisons(session_id, protocol, created_at desc);
create index if not exists idx_protocol_comparisons_operation on protocol_comparisons(operation_id, created_at desc);
create index if not exists idx_protocol_comparisons_tool_run on protocol_comparisons(tool_run_id, created_at desc);
create index if not exists idx_payload_attempts_comparison on payload_attempts(job_id, created_at desc);

drop trigger if exists protocol_comparisons_append_only on protocol_comparisons;
create trigger protocol_comparisons_append_only before update or delete on protocol_comparisons
for each row execute function nexus_append_only();
