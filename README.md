# Cisco advisory scraper

## Supabase setup

1. Open the SQL Editor in the Supabase project used by `SUPABASE_URL`.
2. Run the contents of [`supabase_schema.sql`](supabase_schema.sql). This creates
   the `public.cisco_security_advisories` table expected by the scraper.
3. Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `.env`. The scraper
   defaults to the `cisco_security_advisories` table; set `SUPABASE_TABLE` only
   if you created a table with a different name.
4. Start the scraper again. If the table was created but remains unavailable,
   check that the `.env` URL points to the same Supabase project and that the
   table is in the `public` schema.
