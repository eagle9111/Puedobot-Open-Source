# PuedoBot Management & Operational Scripts

This directory houses administrative, maintenance, and standalone utility scripts supporting PuedoBot operations.

---

## Script Catalog

| Script | Purpose | Execution |
| :--- | :--- | :--- |
| `scripts/init_db.py` | Asynchronously connects to PostgreSQL and creates the relational database tables defined in `app/db/models.py`. | `python -m scripts.init_db` |
| `scripts/export_open_core.py` | Generates the clean standalone Open-Source repository (`puedobot-core`) containing only safe local SAST auditing engines. | `python scripts/export_open_core.py` |
| `scripts/legacy_redirect.py` | Legacy standalone redirect server that forwards historical port/dashboard requests to the unified FastAPI service at `/dashboard/`. | `python -m scripts.legacy_redirect` |

---

## Usage Guidelines

### 1. Database Initialization
Before starting the backend or running live scans, initialize the PostgreSQL tables:
```bash
# Ensure PostgreSQL credentials are set in .env
python -m scripts.init_db
```
*Note: For backward compatibility with deployment setups, `init_db.py` in the repository root forwards directly to `scripts/init_db.py`.*

### 2. Standalone Legacy Redirect
If transitioning older deployment monitors or bookmarks that point to port 3000:
```bash
python -m scripts.legacy_redirect
```
*Note: `dashboard/serve.py` forwards directly to `scripts/legacy_redirect.py`.*
