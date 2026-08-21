-- Stage 5 follow-up: fix the claim RPC output-column/column-name collision.
-- Apply after migrations 001 through 005.

create or replace function claim_execution_job(
  p_worker_id text,
  p_queues text[] default array['general'],
  p_lease_seconds integer default 60
) returns table(
  job_id uuid,
  attempt_id text,
  attempt_number integer,
  worker_id text,
  lease_token text,
  lease_expires_at timestamptz,
  heartbeat_at timestamptz,
  status text
) language plpgsql security definer as $$
declare
  selected workflow_jobs%rowtype;
  token text := encode(gen_random_bytes(18), 'hex');
  aid text := 'attempt_' || encode(gen_random_bytes(16), 'hex');
  expiry timestamptz := now() + make_interval(secs => greatest(p_lease_seconds, 10));
begin
  select w.* into selected
  from workflow_jobs as w
  where w.queue_name = any(p_queues)
    and w.status in ('queued', 'retry_wait')
    and w.available_at <= now()
    and (w.deadline_at is null or w.deadline_at > now())
  order by w.priority asc, w.created_at asc
  for update skip locked
  limit 1;

  if not found then return; end if;

  update workflow_jobs as w
  set status = 'leased', lease_owner = p_worker_id, lease_token = token,
      lease_expires_at = expiry, heartbeat_at = now(),
      attempt_count = coalesce(w.attempt_count, 0) + 1, updated_at = now()
  where w.job_id = selected.job_id;

  insert into workflow_job_attempts(
    attempt_id, job_id, attempt_number, worker_id, lease_token,
    lease_expires_at, heartbeat_at, status
  ) values (
    aid, selected.job_id, coalesce(selected.attempt_count, 0) + 1,
    p_worker_id, token, expiry, now(), 'leased'
  );

  return query select selected.job_id, aid, coalesce(selected.attempt_count, 0) + 1,
    p_worker_id, token, expiry, now(), 'leased'::text;
end;
$$;
