# Signal Desk

A Cisco advisory dashboard with a FastAPI backend, Supabase storage, and a responsive browser interface. The project is structured as a single Vercel deployment. The scraper in `main.py` writes advisory snapshots to the same Supabase table and records operational runs.

## 1. Set up Supabase

Open the SQL Editor in your Supabase project and run [`supabase_schema.sql`](supabase_schema.sql). It creates the advisory, account, session, product watchlist, schedule, run-history, and rate-limit tables, plus the restricted login-rate-limit function. The script can be rerun after updates.

Create a Supabase **service role** key for the backend. Never put it in browser code or a `NEXT_PUBLIC_*` variable. The dashboard reads data only through FastAPI.

## 2. Configure secrets

Copy `.env.example` to `.env` for local development and fill in the Supabase URL and service role key. Generate a distinct signing secret with `openssl rand -hex 32` and use it for `JWT_SECRET`. Vercel needs the same values entered as server-side Environment Variables for Preview and Production.

Required server variables:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `JWT_SECRET` (at least 32 bytes; use a random value with at least 256 bits of entropy)

The API signs short lived (15 minute) HS256 JWTs. Browser sessions use an HttpOnly, Secure-on-deployment, SameSite=Strict cookie. JWT claims are validated for signature algorithm, issuer, audience, issue time, expiry, and session ID; session IDs are stored server side and revoked at logout. API clients can send `{"token_mode":"bearer"}` to the login endpoint and use the returned token as `Authorization: Bearer <token>`. Keep bearer tokens in memory and never put them in URLs or logs. Passwords are stored as Argon2id hashes; they are never reversibly encoded or returned by the API.

## 3. Local demo login

The requested `admin / admin123` account is for local demonstration only. It is never seeded at app startup and the seed script exits if it detects Vercel, a production environment, or a non-local Supabase URL.

1. Start local Supabase and set `SUPABASE_URL=http://127.0.0.1:54321`, its local service role key, and `DEMO_MODE=true` in `.env`.
2. Run `python3 scripts/seed_demo_admin.py` once. It stores an Argon2id hash, refuses to overwrite an existing admin, and refuses to run in deployment environments.
3. Create an isolated Python environment and install the project requirements:

   ```sh
   python3 -m venv .venv
   source .venv/bin/activate
   python -m pip install -r requirements.txt
   ```

4. Start the app with `python app.py` (or `uvicorn app:app --reload`) and sign in at `http://127.0.0.1:8000`.

Use the virtual environment for the app. A `RequestsDependencyWarning` from the system Python usually means its globally installed `requests`, `urllib3`, `chardet`, or `charset-normalizer` packages are out of sync; it is separate from the FastAPI startup and does not by itself stop the app.

For a real deployment, set the production Supabase URL and service role key in local `.env`, then run `python3 scripts/provision_admin.py` from a trusted machine. It prompts for a unique username and a minimum 14-character password, hashes it, and refuses to overwrite an account. Do not use the demo password in a deployed environment.

## 4. Deploy to Vercel

Import the repository in Vercel. FastAPI is exposed from the root `app.py`, while `public/` contains the static page assets. Add the three server environment variables above, then deploy. Vercel serves the page and assets from its CDN and routes API requests to FastAPI.

### Enable Operations

The browser scraper runs in GitHub Actions, outside the Vercel request. Add these GitHub **Actions repository secrets** so the scheduled worker can reach Supabase:

- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`

Commit and push `.github/workflows/cisco-scraper.yml` to the repository's default branch and enable GitHub Actions. It checks hourly in UTC; the Operations page can set the effective cadence to hourly, every 6 hours, daily, or paused. The hourly check skips runs until the saved interval has elapsed.

For **Run scraper now**, add these server-side Vercel environment variables:

- `SCRAPER_GITHUB_REPOSITORY` — `owner/repository`
- `SCRAPER_GITHUB_TOKEN` — a fine-grained token restricted to this repository with **Actions: write** permission
- `SCRAPER_GITHUB_BRANCH` — optional, defaults to `main`
- `SCRAPER_GITHUB_WORKFLOW` — optional, defaults to `cisco-scraper.yml`

For local app testing, put the same variables in `.env` and restart `python app.py`. Set `SCRAPER_GITHUB_REPOSITORY` to the actual `owner/repository`; create a fine-grained token restricted to that repository with **Actions: write** permission. Keep the token in `.env` or Vercel's server environment and never paste it into chat or browser code.

When those GitHub dispatch variables are absent and the app is not running on Vercel, **Run scraper now** starts `main.py` locally in the background (Playwright + Chromium must be installed: `python -m playwright install chromium`). On Vercel, configure the GitHub token so manual runs can leave the serverless request. Scheduled cadence still relies on the hourly GitHub Actions check. Tracked products are a separate team watchlist and do not change which Cisco advisories the scraper retrieves. The dashboard refresh button reloads the latest completed snapshot.

## API

- `GET /api/health` — health check
- `POST /api/auth/login` — verify credentials, rate limited to 8 attempts per 15 minute window per username and client address
- `POST /api/auth/logout` — revoke the current session
- `GET /api/auth/session` — current authenticated user
- `GET /api/advisories?limit=100` — latest advisory records and aggregate counts; requires authentication
- `GET /api/admin/overview` — admin-only access check
- `/api/admin/products` — add, list, pause/resume, and remove tracked products
- `GET/PUT /api/admin/scraper/settings` — read or change cadence and automatic refresh
- `POST /api/admin/scraper/run` — dispatch an immediate GitHub Actions scrape

The API does not enable cross-origin access. It adds content security, framing, MIME sniffing, referrer, permissions, and cache-control headers. Supabase account/session tables have RLS enabled and no anon/authenticated access grants. As with any deployed application, security still depends on protecting the Vercel/Supabase secrets, applying provider updates, and keeping the demo account out of production.
