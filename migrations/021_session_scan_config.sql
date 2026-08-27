-- Tahap 20 prerequisite: persist interactive-session scan configuration.
-- Additive and safe to run once after the existing migrations.

begin;

alter table if exists public.session_context
  add column if not exists scan_preset text not null default 'full';

alter table if exists public.session_context
  add column if not exists scan_vuln_types jsonb not null default '[]'::jsonb;

create index if not exists idx_session_context_scan_preset
  on public.session_context (scan_preset);

commit;
