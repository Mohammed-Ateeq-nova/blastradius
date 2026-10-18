# BlastRadius (M1 slice)

Local-first npm vulnerability triage. This directory is the product app. The workspace root remains the FalkorDB skills demo and is not overwritten.

**FalkorDB is required.** The backend talks to it over `127.0.0.1:6379` with Redis `GRAPH.*` commands. **MCP is optional** and is not used by the app.

## Prerequisites

- Running FalkorDB (workspace root: `docker compose up -d`)
- Python 3.11+ (project venv under `backend/.venv`)
- Node 18+ for the UI

## Run

`ERR_CONNECTION_REFUSED` on port 5173 means the Vite UI is not running. FalkorDB being up is not enough.

```powershell
# from blast-radius/
.\start.ps1

# or manually:
# Backend
cd blast-radius\backend
.\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Frontend
cd blast-radius\frontend
npm install
npm run dev
```

- API: http://127.0.0.1:8000/api/health
- UI: http://127.0.0.1:5173
- Load fixture: `POST /api/scans` with `{"source":"fixture"}` (labelled demo data, not a live CVE feed)

## Tests

```powershell
cd blast-radius/backend
.\.venv\Scripts\python.exe -m pytest
```
