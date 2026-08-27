-- Stage 19 follow-up: durable soak lifecycle events.
-- Additive and forward-only. Apply after migration 019. No RLS changes.
-- production_soak_runs remains immutable; API derives effective status from
-- the latest append-only event in this table.

create table if not exists production_soak_events (
  event_id text primary key,
  soak_run_id text not null references production_soak_runs(soak_run_id) on delete cascade,
  job_id text not null default '',
  attempt_id text not null default '',
  status text not null check (status in ('queued','running','succeeded','failed','cancelled','partial')),
  payload jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);

create index if not exists idx_soak_events_run on production_soak_events(soak_run_id, created_at);
create index if not exists idx_soak_events_job on production_soak_events(job_id, created_at);

drop trigger if exists production_soak_events_append_only on production_soak_events;
create trigger production_soak_events_append_only
before update or delete on production_soak_events
for each row execute function nexus_append_only();
