-- Run against an empty, disposable database after applying supabase_schema.sql.
begin;
set local role service_role;

do $$
declare
    first_run bigint;
    second_run bigint;
    feed jsonb;
    items jsonb := '[{
        "name": "Cisco example advisory",
        "summary": "Example advisory for regression testing.",
        "workarounds": "",
        "affected_products": ["Cisco Example Product"],
        "fixed_software": "12.3.4",
        "fixed_releases": ["12.3.4"],
        "source_url": "https://www.cisco.com/security/center/content/example"
    }]';
begin
    insert into public.app_users (username, password_hash, role)
    values ('test-admin', 'fixture-only', 'admin');

    update public.scraper_settings set enabled = false where id = 1;
    assert public.claim_scraper_run('scheduled') is null, 'Paused schedule started a run';
    first_run := public.claim_scraper_run('manual', p_requested_by => 'test-admin');
    assert first_run is not null, 'Manual request could not queue a run';
    assert public.claim_scraper_run('manual') is null, 'An active run allowed a second launch';
    assert public.claim_scraper_run('manual', first_run) = first_run, 'Worker could not claim queued run';
    assert public.claim_scraper_run('manual', first_run) is null, 'A running job could be claimed twice';
    assert public.publish_advisory_snapshot(first_run, items) = 1, 'First publication failed';
    feed := public.read_advisory_feed(500);
    assert feed->'items'->0->>'name' = 'Cisco example advisory';
    assert feed->>'fetched_at' is not null;
    assert feed->>'latest_run_status' = 'succeeded';
    assert feed->>'schedule_enabled' = 'false';

    update public.scraper_settings set enabled = true where id = 1;
    assert public.claim_scraper_run('scheduled') is null, 'Cadence was ignored';
    second_run := public.claim_scraper_run('manual');
    assert second_run is not null;
    begin
        perform public.publish_advisory_snapshot(second_run, jsonb_build_array((items->0) - 'fixed_software'));
        raise exception 'Invalid rows were accepted';
    exception when not_null_violation then
        null;
    end;
    assert (select status = 'running' from public.scraper_runs where id = second_run);
    assert public.read_advisory_feed(500)->'items' = feed->'items', 'Failed publication erased the previous snapshot';

    update public.scraper_runs set status = 'failed', finished_at = now() where id = second_run;
    begin
        perform public.publish_advisory_snapshot(second_run, items);
        raise exception 'An inactive run could overwrite the snapshot';
    exception when raise_exception then
        if sqlerrm <> 'Scraper run is no longer active' then
            raise;
        end if;
    end;
    assert public.read_advisory_feed(500)->>'latest_run_status' = 'failed';

    update public.cisco_security_advisories set created_at = now() - interval '3 hours';
    assert public.read_advisory_feed(500)->>'stale' = 'true';
    update public.scraper_runs set started_at = now() - interval '46 minutes' where id = second_run;
    update public.scraper_settings set last_run_at =
        (select started_at from public.scraper_runs where id = second_run)
        where id = 1;
    assert public.claim_scraper_run('scheduled') is not null, 'A failed scrape could not retry';
end;
$$;

reset role;
do $$
begin
    assert not has_function_privilege('anon', 'public.claim_scraper_run(text,bigint,text)', 'execute');
    assert not has_function_privilege('authenticated', 'public.publish_advisory_snapshot(bigint,jsonb)', 'execute');
    assert not has_function_privilege('anon', 'public.read_advisory_feed(integer)', 'execute');
end;
$$;
rollback;
