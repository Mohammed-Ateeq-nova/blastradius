# Start BlastRadius locally. FalkorDB must already be running (workspace docker compose).
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\backend'; .\.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", "Set-Location '$root\frontend'; npm run dev"
Write-Host "API http://127.0.0.1:8000/api/health"
Write-Host "UI  http://127.0.0.1:5173"
