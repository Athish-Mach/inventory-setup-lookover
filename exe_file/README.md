# Cisco Security Advisory Monitor

A Windows desktop application built with Python 3.13 and CustomTkinter. It monitors an existing Supabase `cisco_security_advisories` table and notifies the user when advisories match products they care about.

The app does not create, update, or delete Cisco advisories. It only reads the Supabase advisory table. Monitored products are stored locally on the Windows PC in `data/monitored_products.json`.

## Supabase

The advisory table must already exist:

```text
cisco_security_advisories
- id bigint
- name text
- summary text
- workarounds text
- affected_products jsonb
```

No `monitored_products` table is required in Supabase.

Cards display Fixed Releases when the source table provides `fixed_releases`, `fixed_release`, `fixed_software`, or `fixed_versions`.

## Setup

1. Create a virtual environment.

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

2. Install dependencies.

```powershell
pip install -r requirements.txt
```

3. Create `.env` from `.env.example`.

```powershell
Copy-Item .env.example .env
```

4. Edit `.env` and set:

```text
SUPABASE_URL=...
SUPABASE_KEY=...
SUPABASE_TABLE=cisco_security_advisories
SUPABASE_TABLES=cisco_security_advisories,my_advisories
```

Never hardcode Supabase credentials in source code.

## Run

```powershell
python app.py
```

## Monitoring Behavior

The app polls `cisco_security_advisories` every 15 seconds. This is the reliable fallback path for Supabase Python applications because Supabase Realtime support and setup requirements can vary by SDK version and project configuration.

On each check, the app:

- Reads every row from each table listed in `SUPABASE_TABLES`, including tables with more than 1,000 rows.
- Parses `affected_products` whether it is stored as JSON, a JSON string, a list, or an object.
- Rebuilds the full product list from the latest advisory rows.
- Filters cards when a product is clicked.
- Reads monitored notification products from local file storage.
- Matches monitored product names case-insensitively against affected products.
- Displays advisories as cards.
- Highlights newly inserted or changed matching advisories as `NEW`.
- Sends one Windows notification per product and advisory version.

## Logging

Logs are written to:

```text
logs/application.log
```

The application logs connection events, products added, update checks, matching advisories, and errors.

## PyInstaller Build

From the activated virtual environment:

```powershell
pyinstaller --noconfirm --clean --windowed --name "Cisco Security Advisory Monitor" app.py
```

The executable will be created under:

```text
dist\Cisco Security Advisory Monitor\
```

Place a `.env` file beside the executable or provide `SUPABASE_URL` and `SUPABASE_KEY` as Windows environment variables.

## Project Structure

```text
app.py              Application entry point
config.py           Environment loading, constants, logging setup
database.py         Supabase access layer
monitor.py          Polling monitor and notification logic
ui.py               CustomTkinter desktop interface
product_store.py    Local JSON-backed monitored product storage
utils.py            Validation, JSON parsing, matching, notifications
requirements.txt    Python dependencies
.env.example        Environment variable template
README.md           Setup and build instructions
```
