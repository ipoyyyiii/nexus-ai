-- Stage 24: candidate/validation referential integrity.
-- Apply after migrations 001 and 009.  The application stages a candidate as
-- inconclusive, writes validation_runs and validation_checks, then promotes
-- the candidate only after those durable rows exist.

create or replace function nexus_candidate_validation_integrity() returns trigger
language plpgsql as $$
begin
  if new.status = 'validated' and not exists (
    select 1
    from validation_runs as vr
      where vr.candidate_id = new.candidate_id
      and vr.decision = 'validated'
      and exists (
        select 1
        from validation_checks as vc
        where vc.validation_run_id = vr.validation_run_id
          and vc.passed = true
      )
      and not exists (
        select 1
        from validation_checks as vc
        where vc.validation_run_id = vr.validation_run_id
          and vc.passed = false
      )
  ) then
    raise exception using
      errcode = '23514',
      constraint = 'candidate_validated_requires_validation',
      message = 'candidate status validated requires a durable successful validation run and check';
  end if;
  return new;
end;
$$;

drop trigger if exists candidate_validation_integrity on candidate_findings;
create constraint trigger candidate_validation_integrity
after insert or update of status on candidate_findings
deferrable initially immediate
for each row execute function nexus_candidate_validation_integrity();

create or replace function nexus_validation_run_integrity() returns trigger
language plpgsql as $$
begin
  if (tg_op = 'DELETE' or (tg_op = 'UPDATE' and new.decision <> 'validated'))
     and exists (
       select 1
       from candidate_findings as cf
       where cf.candidate_id = old.candidate_id
         and cf.status = 'validated'
     )
     and not exists (
       select 1
       from validation_runs as vr
       where vr.candidate_id = old.candidate_id
         and vr.decision = 'validated'
         and vr.validation_run_id <> old.validation_run_id
         and exists (
           select 1
           from validation_checks as vc
           where vc.validation_run_id = vr.validation_run_id
             and vc.passed = true
         )
         and not exists (
           select 1
           from validation_checks as vc
           where vc.validation_run_id = vr.validation_run_id
             and vc.passed = false
         )
     ) then
    raise exception using
      errcode = '23514',
      constraint = 'validated_candidate_requires_validation',
      message = 'cannot remove the last successful validation for a validated candidate';
  end if;
  if tg_op = 'DELETE' then
    return old;
  end if;
  return new;
end;
$$;

drop trigger if exists validation_run_integrity on validation_runs;
create constraint trigger validation_run_integrity
after delete or update of decision on validation_runs
deferrable initially immediate
for each row execute function nexus_validation_run_integrity();
