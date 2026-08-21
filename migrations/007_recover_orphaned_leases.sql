-- Stage 5 follow-up: recover jobs whose lease survived a worker restart but
-- whose attempt row is missing or no longer matches the old recovery CTE.
-- Apply after migrations 001 through 006.

create or replace function recover_expired_execution_jobs() returns integer
language plpgsql security definer as $$
declare
  recovered integer := 0;
begin
  update workflow_job_attempts as a
  set status = 'lost', finished_at = now()
  from workflow_jobs as j
  where a.job_id = j.job_id
    and a.status in ('leased', 'running', 'waiting')
    and j.status in ('leased', 'running', 'waiting', 'cancelling')
    and j.lease_expires_at is not null
    and j.lease_expires_at < now();

  update workflow_jobs as j
  set status = case when j.risk = 'read_only' then 'retry_wait' else 'recovery_required' end,
      available_at = case when j.risk = 'read_only' then now() + interval '5 seconds' else j.available_at end,
      lease_owner = '', lease_token = '', lease_expires_at = null,
      error_code = case when j.risk = 'read_only' then 'lease_expired' else 'mutation_lease_expired' end,
      updated_at = now()
  where j.status in ('leased', 'running', 'waiting', 'cancelling')
    and j.lease_expires_at is not null
    and j.lease_expires_at < now();

  get diagnostics recovered = row_count;
  return recovered;
end;
$$;
