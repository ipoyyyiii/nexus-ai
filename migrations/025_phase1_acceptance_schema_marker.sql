-- Phase 1 acceptance schema marker.
-- Run after migrations 023 and 024. The marker is written only when
-- PostgreSQL verifies the required columns, enabled trigger wiring, trigger
-- function bodies, and append-only model-call audit trigger.

create table if not exists nexus_schema_migrations (
  migration_id text primary key,
  checksum text not null,
  applied_at timestamptz not null default now()
);

create or replace function public.nexus_phase1_acceptance_status()
returns jsonb
language plpgsql
security definer
set search_path = public, pg_catalog
as $$
declare
  missing text[] := array[]::text[];
  required record;
  candidate_trigger_enabled text;
  candidate_trigger_function text;
  candidate_trigger_def text;
  validation_trigger_enabled text;
  validation_trigger_function text;
  validation_trigger_def text;
  model_call_trigger_enabled text;
  model_call_trigger_function text;
  model_call_trigger_def text;
  candidate_function_def text;
  validation_function_def text;
  append_function_def text;
  expected_023 text;
  expected_024 text;
  marker_023 text;
  marker_024 text;
begin
  for required in
    select * from (values
      ('reasoning_cycles', 'cycle_id'),
      ('reasoning_cycles', 'session_id'),
      ('reasoning_cycles', 'max_cycles'),
      ('reasoning_cycles', 'action_budget'),
      ('reasoning_model_calls', 'call_id'),
      ('reasoning_model_calls', 'cycle_id'),
      ('reasoning_model_calls', 'session_id'),
      ('reasoning_model_calls', 'job_id'),
      ('reasoning_model_calls', 'status'),
      ('reasoning_model_calls', 'input_digest'),
      ('reasoning_model_calls', 'output_digest'),
      ('model_action_traces', 'trace_id'),
      ('model_action_traces', 'cycle_id'),
      ('model_action_traces', 'session_id'),
      ('model_action_traces', 'valid'),
      ('model_action_traces', 'unknown_tool'),
      ('model_action_traces', 'unsupported_capability'),
      ('model_action_traces', 'stale_context'),
      ('validation_traces_v2', 'trace_id'),
      ('candidate_findings', 'candidate_id'),
      ('candidate_findings', 'session_id'),
      ('candidate_findings', 'status'),
      ('validation_runs', 'validation_run_id'),
      ('validation_runs', 'candidate_id'),
      ('validation_runs', 'decision'),
      ('validation_checks', 'validation_run_id'),
      ('validation_checks', 'check_name'),
      ('validation_checks', 'passed')
    ) as required_columns(table_name, column_name)
  loop
    if not exists (
      select 1
      from information_schema.columns
      where table_schema = 'public'
        and table_name = required.table_name
        and column_name = required.column_name
    ) then
      missing := array_append(missing, required.table_name || '.' || required.column_name);
    end if;
  end loop;

  select t.tgenabled::text, p.proname, pg_get_triggerdef(t.oid), pg_get_functiondef(p.oid)
  into candidate_trigger_enabled, candidate_trigger_function, candidate_trigger_def, candidate_function_def
  from pg_trigger t
  join pg_proc p on p.oid = t.tgfoid
  where t.tgrelid = to_regclass('public.candidate_findings')
    and t.tgname = 'candidate_validation_integrity'
    and not t.tgisinternal;
  if not found
     or candidate_trigger_enabled = 'D'
     or candidate_trigger_function <> 'nexus_candidate_validation_integrity'
     or lower(coalesce(candidate_function_def, '')) not like '%validation_checks%'
     or lower(coalesce(candidate_function_def, '')) not like '%passed = true%'
     or lower(coalesce(candidate_function_def, '')) not like '%candidate status validated%' then
    missing := array_append(missing, '024:candidate_validation_integrity_trigger');
  end if;

  select t.tgenabled::text, p.proname, pg_get_triggerdef(t.oid), pg_get_functiondef(p.oid)
  into validation_trigger_enabled, validation_trigger_function, validation_trigger_def, validation_function_def
  from pg_trigger t
  join pg_proc p on p.oid = t.tgfoid
  where t.tgrelid = to_regclass('public.validation_runs')
    and t.tgname = 'validation_run_integrity'
    and not t.tgisinternal;
  if not found
     or validation_trigger_enabled = 'D'
     or validation_trigger_function <> 'nexus_validation_run_integrity'
     or lower(coalesce(validation_function_def, '')) not like '%validation_checks%'
     or lower(coalesce(validation_function_def, '')) not like '%passed = true%' then
    missing := array_append(missing, '024:validation_run_integrity_trigger');
  end if;

  select t.tgenabled::text, p.proname, pg_get_triggerdef(t.oid), pg_get_functiondef(p.oid)
  into model_call_trigger_enabled, model_call_trigger_function, model_call_trigger_def, append_function_def
  from pg_trigger t
  join pg_proc p on p.oid = t.tgfoid
  where t.tgrelid = to_regclass('public.reasoning_model_calls')
    and t.tgname = 'reasoning_model_calls_append_only'
    and not t.tgisinternal;
  if not found
     or model_call_trigger_enabled = 'D'
     or model_call_trigger_function <> 'nexus_append_only'
     or lower(coalesce(append_function_def, '')) not like '%raise exception%' then
    missing := array_append(missing, '023:reasoning_model_calls_append_only_trigger');
  end if;

  expected_023 := md5(coalesce(model_call_trigger_def, '') || '|' || coalesce(append_function_def, ''));
  expected_024 := md5(
    coalesce(candidate_trigger_def, '') || '|' ||
    coalesce(validation_trigger_def, '') || '|' ||
    coalesce(candidate_function_def, '') || '|' ||
    coalesce(validation_function_def, '')
  );

  if to_regclass('public.nexus_schema_migrations') is null then
    missing := array_append(missing, '025:nexus_schema_migrations');
  else
    select checksum into marker_023
    from nexus_schema_migrations
    where migration_id = '023_reasoning_model_calls';
    select checksum into marker_024
    from nexus_schema_migrations
    where migration_id = '024_candidate_validation_integrity';
    if marker_023 is distinct from expected_023 then
      missing := array_append(missing, '025:023_reasoning_model_calls_checksum');
    end if;
    if marker_024 is distinct from expected_024 then
      missing := array_append(missing, '025:024_candidate_validation_integrity_checksum');
    end if;
  end if;

  return jsonb_build_object(
    'ready', cardinality(missing) = 0,
    'missing', to_jsonb(missing),
    'checksums', jsonb_build_object('023', expected_023, '024', expected_024)
  );
end;
$$;

do $$
declare
  expected_023 text;
  expected_024 text;
  status jsonb;
begin
  select md5(pg_get_triggerdef(t.oid) || '|' || pg_get_functiondef(p.oid))
  into expected_023
  from pg_trigger t
  join pg_proc p on p.oid = t.tgfoid
  where t.tgrelid = to_regclass('public.reasoning_model_calls')
    and t.tgname = 'reasoning_model_calls_append_only'
    and not t.tgisinternal;

  select md5(
    coalesce(candidate_def, '') || '|' || coalesce(validation_def, '') || '|' ||
    coalesce(candidate_fn, '') || '|' || coalesce(validation_fn, '')
  )
  into expected_024
  from (
    select
      (select pg_get_triggerdef(t.oid)
       from pg_trigger t
       where t.tgrelid = to_regclass('public.candidate_findings')
         and t.tgname = 'candidate_validation_integrity'
         and not t.tgisinternal) as candidate_def,
      (select pg_get_triggerdef(t.oid)
       from pg_trigger t
       where t.tgrelid = to_regclass('public.validation_runs')
         and t.tgname = 'validation_run_integrity'
         and not t.tgisinternal) as validation_def,
      (select pg_get_functiondef(p.oid)
       from pg_proc p
       join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'public'
         and p.proname = 'nexus_candidate_validation_integrity'
         and p.pronargs = 0) as candidate_fn,
      (select pg_get_functiondef(p.oid)
       from pg_proc p
       join pg_namespace n on n.oid = p.pronamespace
       where n.nspname = 'public'
         and p.proname = 'nexus_validation_run_integrity'
         and p.pronargs = 0) as validation_fn
  ) definitions;

  insert into nexus_schema_migrations (migration_id, checksum)
  values
    ('023_reasoning_model_calls', coalesce(expected_023, 'missing')),
    ('024_candidate_validation_integrity', coalesce(expected_024, 'missing'))
  on conflict (migration_id) do update
    set checksum = excluded.checksum,
        applied_at = nexus_schema_migrations.applied_at;

  status := public.nexus_phase1_acceptance_status();
  if coalesce((status ->> 'ready')::boolean, false) is not true then
    raise exception using
      errcode = '55000',
      message = 'Phase 1 acceptance schema is incomplete: ' || (status ->> 'missing');
  end if;
end;
$$;

do $$
begin
  if exists (select 1 from pg_roles where rolname = 'anon') then
    grant execute on function public.nexus_phase1_acceptance_status() to anon;
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    grant execute on function public.nexus_phase1_acceptance_status() to authenticated;
  end if;
end;
$$;
