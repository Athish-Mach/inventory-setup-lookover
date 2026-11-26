begin;

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
    add column if not exists created_at timestamptz not null default now(),
    add column if not exists source_url text;

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
create index if not exists scraper_runs_active_idx
    on public.scraper_runs (status) where status in ('queued', 'running');
create index if not exists scraper_runs_failed_start_idx
    on public.scraper_runs (started_at) where status = 'failed';

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

-- Serialize scheduling, manual queueing, and worker claims on the settings row.
create or replace function public.claim_scraper_run(
    p_source text,
    p_run_id bigint default null,
    p_requested_by text default null
)
returns bigint
language plpgsql
set search_path = ''
as $$
declare
    settings public.scraper_settings%rowtype;
    claimed_id bigint;
    current_time_utc timestamptz := statement_timestamp();
begin
    if p_source is null or p_source not in ('manual', 'scheduled')
        or (p_source = 'scheduled' and (p_run_id is not null or p_requested_by is not null))
        or (p_run_id is not null and p_requested_by is not null) then
        raise exception 'Invalid scraper claim';
    end if;

    select * into strict settings from public.scraper_settings where id = 1 for update;

    update public.scraper_runs
    set status = 'failed', finished_at = current_time_utc,
        message = 'The worker did not finish within the expected time.'
    where status in ('queued', 'running')
        and coalesce(started_at, created_at) < current_time_utc - interval '45 minutes';

    if p_run_id is not null then
        update public.scraper_runs
        set status = 'running', started_at = current_time_utc, message = 'Scrape is in progress.'
        where id = p_run_id and status = 'queued' and run_source = 'manual'
            and not exists (select 1 from public.scraper_runs where status = 'running')
        returning id into claimed_id;
    else
        if exists (select 1 from public.scraper_runs where status in ('queued', 'running')) then
            return null;
        end if;

        if p_source = 'scheduled' and (
            not settings.enabled or settings.last_run_at + case
                when exists (select 1 from public.scraper_runs where status = 'failed'
                    and started_at = settings.last_run_at) then interval '45 minutes'
                else make_interval(mins => settings.interval_minutes)
            end > current_time_utc
        ) then
            return null;
        end if;

        insert into public.scraper_runs (run_source, status, requested_by, started_at, message)
        values (p_source,
            case when p_requested_by is null then 'running' else 'queued' end,
            p_requested_by,
            case when p_requested_by is null then current_time_utc end,
            case when p_requested_by is null then 'Scrape is in progress.' else 'Queued from the dashboard.' end)
        returning id into claimed_id;
    end if;

    if claimed_id is not null and p_requested_by is null then
        update public.scraper_settings set last_run_at = current_time_utc where id = 1;
    end if;
    return claimed_id;
end;
$$;

-- An unsuccessful publication rolls back both the replacement and the run update.
create or replace function public.publish_advisory_snapshot(p_run_id bigint, p_items jsonb)
returns integer
language plpgsql
set search_path = ''
as $$
declare
    item_count integer;
    finished timestamptz := statement_timestamp();
begin
    if p_items is null or jsonb_typeof(p_items) <> 'array' then
        raise exception 'Expected an advisory array';
    end if;
    item_count := jsonb_array_length(p_items);
    if item_count = 0 then
        raise exception 'Cannot publish an empty advisory snapshot';
    end if;
    if exists (
        select 1 from jsonb_array_elements(p_items) as item
        where coalesce(btrim(item->>'name'), '') = ''
            or coalesce(btrim(item->>'summary'), '') = ''
            or jsonb_typeof(item->'affected_products') is distinct from 'array'
            or jsonb_typeof(item->'fixed_releases') is distinct from 'array'
    ) then
        raise exception 'Cannot publish an incomplete advisory snapshot';
    end if;

    update public.scraper_runs
    set status = 'succeeded', finished_at = finished, advisory_count = item_count,
        message = 'Scrape completed successfully.'
    where id = p_run_id and status = 'running'
        and started_at >= finished - interval '45 minutes';
    if not found then
        raise exception 'Scraper run is no longer active';
    end if;

    -- Supabase can require an explicit predicate on deletes, including inside RPCs.
    delete from public.cisco_security_advisories where id is not null;
    insert into public.cisco_security_advisories
        (name, summary, workarounds, affected_products, fixed_software, fixed_releases, source_url, created_at)
    select name, summary, workarounds, affected_products, fixed_software, fixed_releases, source_url, finished
    from jsonb_to_recordset(p_items) as advisory(
        name text, summary text, workarounds text, affected_products jsonb,
        fixed_software text, fixed_releases jsonb, source_url text
    );
    return item_count;
end;
$$;

-- Read rows and feed metadata from a single database snapshot.
create or replace function public.read_advisory_feed(p_limit integer)
returns jsonb
language sql stable
set search_path = ''
as $$
    with feed as (
        select id, name, summary, workarounds, affected_products, fixed_software,
            fixed_releases, source_url, created_at
        from public.cisco_security_advisories
        order by created_at desc, id asc
        limit least(greatest(p_limit, 1), 500)
    ), snapshot as (
        select
            coalesce(jsonb_agg(to_jsonb(feed) order by created_at desc, id asc), '[]'::jsonb) as items,
            max(created_at) as fetched_at
        from feed
    )
    select jsonb_build_object(
        'items', snapshot.items,
        'total', (select count(*) from public.cisco_security_advisories),
        'fetched_at', snapshot.fetched_at,
        'schedule_enabled', settings.enabled,
        'stale', settings.enabled and coalesce(snapshot.fetched_at <
            statement_timestamp() - make_interval(mins => settings.interval_minutes + 75), false),
        'latest_run_status', (select status from public.scraper_runs order by id desc limit 1)
    )
    from snapshot cross join public.scraper_settings as settings where settings.id = 1;
$$;

revoke all on function public.claim_scraper_run(text, bigint, text) from public, anon, authenticated;
revoke all on function public.publish_advisory_snapshot(bigint, jsonb) from public, anon, authenticated;
revoke all on function public.read_advisory_feed(integer) from public, anon, authenticated;
grant execute on function public.claim_scraper_run(text, bigint, text) to service_role;
grant execute on function public.publish_advisory_snapshot(bigint, jsonb) to service_role;
grant execute on function public.read_advisory_feed(integer) to service_role;

notify pgrst, 'reload schema';
commit;
