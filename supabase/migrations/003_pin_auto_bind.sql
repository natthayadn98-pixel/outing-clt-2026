-- TEST FIRST. PIN-only auto-binding is vulnerable to employee-code guessing / impersonation.
-- This does not alter guests or check-in history.
create unique index if not exists employee_line_bindings_employee_unique on public.employee_line_bindings(employee_code);
create unique index if not exists employee_line_bindings_line_unique on public.employee_line_bindings(line_user_id);
create table if not exists public.line_pin_bind_attempts (
  id bigint generated always as identity primary key,
  line_hash text not null,
  employee_code text not null,
  attempted_at timestamptz not null default now()
);
create index if not exists line_pin_bind_attempts_line_time on public.line_pin_bind_attempts(line_hash,attempted_at desc);
create index if not exists line_pin_bind_attempts_emp_time on public.line_pin_bind_attempts(employee_code,attempted_at desc);
alter table public.line_pin_bind_attempts enable row level security;
revoke all on public.line_pin_bind_attempts from public,anon,authenticated;
create or replace function public.bind_employee_line_pin_once(p_employee_code text,p_line_user_id text)
returns text language plpgsql security definer set search_path = public, extensions, pg_temp as $$
declare v_line_hash text; v_existing_employee text; v_existing_line text;
begin
 if p_employee_code !~ '^[0-9]{6}$' or length(coalesce(p_line_user_id,'')) < 5 then return 'invalid'; end if;
 v_line_hash := encode(digest(p_line_user_id,'sha256'),'hex');
 perform pg_advisory_xact_lock(hashtextextended(p_line_user_id,0));
 perform pg_advisory_xact_lock(hashtextextended(p_employee_code,1));
 select employee_code into v_existing_employee from public.employee_line_bindings where line_user_id=p_line_user_id;
 if found then
   if v_existing_employee=p_employee_code then return 'already_bound'; end if;
   return 'line_in_use';
 end if;
 select line_user_id into v_existing_line from public.employee_line_bindings where employee_code=p_employee_code;
 if found then return 'employee_in_use'; end if;
 if (select count(*) from public.line_pin_bind_attempts where line_hash=v_line_hash and attempted_at>now()-interval '1 hour')>=5
 or (select count(*) from public.line_pin_bind_attempts where employee_code=p_employee_code and attempted_at>now()-interval '1 hour')>=10
 then return 'rate_limited'; end if;
 insert into public.line_pin_bind_attempts(line_hash,employee_code) values(v_line_hash,p_employee_code);
 if not exists(select 1 from public.guests where employee_code=p_employee_code) then return 'employee_not_found'; end if;
 insert into public.employee_line_bindings(employee_code,line_user_id) values(p_employee_code,p_line_user_id);
 return 'bound';
exception when unique_violation then return 'conflict';
end $$;
revoke all on function public.bind_employee_line_pin_once(text,text) from public,anon,authenticated;
grant execute on function public.bind_employee_line_pin_once(text,text) to service_role;
