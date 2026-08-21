-- Tahap 7: tool boundary hardening. Additive, no RLS.
-- Existing deployments already have 006/007 durable repair files; execute this
-- file manually after those files and before strict cutover.

alter table if exists safety_decisions add column if not exists tool_run_id text not null default '';
alter table if exists sandbox_runs add column if not exists tool_run_id text not null default '';

create table if not exists resource_budget_events (
  event_id uuid primary key default gen_random_uuid(),
  session_id uuid not null references sessions(id) on delete cascade,
  job_id uuid not null references workflow_jobs(job_id) on delete cascade,
  attempt_id text not null default '',
  tool_run_id text not null default '',
  origin text not null default '',
  request_delta integer not null default 0,
  download_delta bigint not null default 0,
  upload_delta bigint not null default 0,
  credential_delta integer not null default 0,
  created_at timestamptz not null default now()
);

create index if not exists idx_safety_decisions_tool_run
  on safety_decisions(tool_run_id, created_at desc);
create index if not exists idx_sandbox_runs_tool_run
  on sandbox_runs(tool_run_id, created_at desc);
create index if not exists idx_budget_events_job_origin
  on resource_budget_events(job_id, origin, created_at desc);
create index if not exists idx_budget_events_attempt
  on resource_budget_events(attempt_id, created_at desc);

drop trigger if exists resource_budget_events_append_only on resource_budget_events;
create trigger resource_budget_events_append_only
before update or delete on resource_budget_events
for each row execute function nexus_append_only();

create or replace function consume_resource_budget(
  p_session_id uuid,
  p_job_id uuid,
  p_attempt_id text,
  p_tool_run_id text,
  p_origin text,
  p_request_delta integer,
  p_download_delta bigint,
  p_upload_delta bigint,
  p_credential_delta integer,
  p_max_requests integer,
  p_max_download_bytes bigint,
  p_max_upload_bytes bigint,
  p_max_credential_attempts integer
) returns table(allowed boolean, reason text, request_count integer,
                downloaded_bytes bigint, uploaded_bytes bigint,
                credential_attempts integer)
language plpgsql security definer as $$
declare
  current_row resource_budget_usage%rowtype;
  next_requests integer;
  next_download bigint;
  next_upload bigint;
  next_credentials integer;
begin
  if p_request_delta < 0 or p_download_delta < 0 or p_upload_delta < 0 or p_credential_delta < 0 then
    return query select false, 'negative_budget_delta', 0, 0::bigint, 0::bigint, 0;
    return;
  end if;

  select * into current_row
  from resource_budget_usage
  where job_id = p_job_id and origin = p_origin
  for update;

  if not found then
    current_row.request_count := 0;
    current_row.downloaded_bytes := 0;
    current_row.uploaded_bytes := 0;
    current_row.credential_attempts := 0;
  end if;

  next_requests := current_row.request_count + p_request_delta;
  next_download := current_row.downloaded_bytes + p_download_delta;
  next_upload := current_row.uploaded_bytes + p_upload_delta;
  next_credentials := current_row.credential_attempts + p_credential_delta;

  if next_requests > p_max_requests then
    return query select false, 'request_budget_exhausted', next_requests, next_download, next_upload, next_credentials;
    return;
  elsif next_download > p_max_download_bytes then
    return query select false, 'download_budget_exhausted', next_requests, next_download, next_upload, next_credentials;
    return;
  elsif next_upload > p_max_upload_bytes then
    return query select false, 'upload_budget_exhausted', next_requests, next_download, next_upload, next_credentials;
    return;
  elsif next_credentials > p_max_credential_attempts then
    return query select false, 'credential_budget_exhausted', next_requests, next_download, next_upload, next_credentials;
    return;
  end if;

  insert into resource_budget_usage(
    session_id, job_id, origin, request_count, downloaded_bytes,
    uploaded_bytes, credential_attempts, updated_at
  ) values (
    p_session_id, p_job_id, p_origin, next_requests, next_download,
    next_upload, next_credentials, now()
  )
  on conflict (job_id, origin) do update set
    request_count = excluded.request_count,
    downloaded_bytes = excluded.downloaded_bytes,
    uploaded_bytes = excluded.uploaded_bytes,
    credential_attempts = excluded.credential_attempts,
    updated_at = now();

  insert into resource_budget_events(
    session_id, job_id, attempt_id, tool_run_id, origin,
    request_delta, download_delta, upload_delta, credential_delta
  ) values (
    p_session_id, p_job_id, coalesce(p_attempt_id, ''), coalesce(p_tool_run_id, ''),
    p_origin, p_request_delta, p_download_delta, p_upload_delta, p_credential_delta
  );

  return query select true, 'allowed', next_requests, next_download, next_upload, next_credentials;
end;
$$;
