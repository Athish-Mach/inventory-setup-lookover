create table if not exists public.cisco_security_advisories (
    id bigint generated always as identity primary key,
    name text not null,
    summary text not null default '',
    workarounds text not null default '',
    affected_products jsonb not null default '[]'::jsonb,
    fixed_software text not null default '',
    fixed_releases jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now()
);

alter table public.cisco_security_advisories enable row level security;
alter table public.cisco_security_advisories force row level security;

-- Safe to rerun against an existing advisory table created by an earlier version.
alter table public.cisco_security_advisories
    add column if not exists created_at timestamptz not null default now();

revoke all on public.cisco_security_advisories from public, anon, authenticated;
grant select, insert, update, delete on public.cisco_security_advisories to service_role;

create table if not exists public.app_users (
    id bigint generated always as identity primary key,
    username text not null unique,
    password_hash text not null,
    role text not null default 'analyst' check (role in ('analyst', 'admin')),
    is_active boolean not null default true,
    created_at timestamptz not null default now(),
    constraint app_users_username_format check (
        username = lower(username)
        and username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'
    )
);

create table if not exists public.app_sessions (
    session_id uuid primary key,
    username text not null references public.app_users(username) on delete cascade,
    expires_at timestamptz not null,
    revoked_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists app_sessions_username_idx
    on public.app_sessions (username);
create index if not exists app_sessions_expiration_idx
    on public.app_sessions (expires_at);

create table if not exists public.auth_login_limits (
    key_hash text primary key,
    window_started_at timestamptz not null default now(),
    attempts integer not null default 1 check (attempts > 0)
);

create table if not exists public.tracked_products (
    id bigint generated always as identity primary key,
    name text not null,
    notes text not null default '',
    is_active boolean not null default true,
    created_by text references public.app_users(username) on delete set null,
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create unique index if not exists tracked_products_name_lower_idx
    on public.tracked_products (lower(name));

create table if not exists public.scraper_settings (
    id integer primary key check (id = 1),
    enabled boolean not null default true,
    interval_minutes integer not null default 60 check (interval_minutes in (60, 360, 1440)),
    last_run_at timestamptz,
    updated_by text references public.app_users(username) on delete set null,
    updated_at timestamptz not null default now()
);

insert into public.scraper_settings (id, enabled, interval_minutes)
values (1, true, 60)
on conflict (id) do nothing;

create table if not exists public.scraper_runs (
    id bigint generated always as identity primary key,
    run_source text not null check (run_source in ('manual', 'scheduled')),
    status text not null check (status in ('queued', 'running', 'succeeded', 'failed')),
    requested_by text references public.app_users(username) on delete set null,
    started_at timestamptz,
    finished_at timestamptz,
    advisory_count integer,
    message text not null default '',
    created_at timestamptz not null default now()
);

create index if not exists scraper_runs_created_at_idx
    on public.scraper_runs (created_at desc);

alter table public.app_users enable row level security;
alter table public.app_users force row level security;
alter table public.app_sessions enable row level security;
alter table public.app_sessions force row level security;
alter table public.auth_login_limits enable row level security;
alter table public.auth_login_limits force row level security;
alter table public.tracked_products enable row level security;
alter table public.tracked_products force row level security;
alter table public.scraper_settings enable row level security;
alter table public.scraper_settings force row level security;
alter table public.scraper_runs enable row level security;
alter table public.scraper_runs force row level security;

-- The browser never receives the service role key. Only the API runtime can
-- access these tables; there are deliberately no anon/authenticated policies.
revoke all on public.app_users from public, anon, authenticated;
revoke all on public.app_sessions from public, anon, authenticated;
revoke all on public.auth_login_limits from public, anon, authenticated;
revoke all on public.tracked_products from public, anon, authenticated;
revoke all on public.scraper_settings from public, anon, authenticated;
revoke all on public.scraper_runs from public, anon, authenticated;
grant select, insert, update, delete on public.app_users to service_role;
grant select, insert, update, delete on public.app_sessions to service_role;
grant select, insert, update, delete on public.auth_login_limits to service_role;
grant select, insert, update, delete on public.tracked_products to service_role;
grant select, insert, update, delete on public.scraper_settings to service_role;
grant select, insert, update, delete on public.scraper_runs to service_role;
grant usage, select on sequence public.cisco_security_advisories_id_seq to service_role;
grant usage, select on sequence public.app_users_id_seq to service_role;
grant usage, select on sequence public.tracked_products_id_seq to service_role;
grant usage, select on sequence public.scraper_runs_id_seq to service_role;

create or replace function public.consume_login_attempt(
    p_key_hash text,
    p_window_seconds integer default 900,
    p_max_attempts integer default 8
)
returns boolean
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
    attempt_count integer;
begin
    insert into public.auth_login_limits (key_hash, window_started_at, attempts)
    values (p_key_hash, now(), 1)
    on conflict (key_hash) do update
    set attempts = case
            when auth_login_limits.window_started_at <= now() - make_interval(secs => p_window_seconds)
                then 1
            else auth_login_limits.attempts + 1
        end,
        window_started_at = case
            when auth_login_limits.window_started_at <= now() - make_interval(secs => p_window_seconds)
                then now()
            else auth_login_limits.window_started_at
        end
    returning attempts into attempt_count;

    -- Periodic cleanup bounds session and limiter table growth.
    delete from public.app_sessions
    where expires_at < now() - interval '30 days';
    delete from public.auth_login_limits
    where window_started_at < now() - interval '1 day';

    return attempt_count <= greatest(1, least(p_max_attempts, 20));
end;
$$;

revoke all on function public.consume_login_attempt(text, integer, integer) from public, anon, authenticated;
grant execute on function public.consume_login_attempt(text, integer, integer) to service_role;
