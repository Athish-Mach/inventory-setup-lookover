create table if not exists public.cisco_security_advisories (
    id bigint generated always as identity primary key,
    name text not null,
    summary text not null default '',
    workarounds text not null default '',
    affected_products jsonb not null default '[]'::jsonb,
    fixed_software text not null default '',
    fixed_releases jsonb not null default '[]'::jsonb
);

alter table public.cisco_security_advisories enable row level security;
