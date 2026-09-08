[CmdletBinding()]
param(
    [switch]$NoBrowser
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$backendRoot = Join-Path $projectRoot "backend"
$backendPython = Join-Path $backendRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $backendPython)) {
    throw "Missing backend virtual environment. Run: py -m venv backend\.venv; backend\.venv\Scripts\python -m pip install -r backend\requirements.txt"
}
if (-not (Get-Command npm.cmd -ErrorAction SilentlyContinue)) {
    throw "Node.js/npm is required. Install Node.js, then run npm install in $projectRoot."
}
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot "node_modules"))) {
    Write-Host "Installing frontend dependencies..."
    & npm.cmd install --prefix $projectRoot
}

function Test-LocalPort([int]$Port) {
    return [bool](Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue)
}

if (-not (Test-LocalPort 8000)) {
    Write-Host "Starting local analysis backend on http://127.0.0.1:8000..."
    Start-Process -FilePath $backendPython -ArgumentList "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000" -WorkingDirectory $backendRoot -WindowStyle Hidden
}
if (-not (Test-LocalPort 5173)) {
    Write-Host "Starting local investigator UI on http://127.0.0.1:5173/ForenSight/..."
    Start-Process -FilePath "npm.cmd" -ArgumentList "run", "dev", "--", "--host", "127.0.0.1" -WorkingDirectory $projectRoot -WindowStyle Hidden
}

$deadline = (Get-Date).AddSeconds(20)
while ((Get-Date) -lt $deadline) {
    if ((Test-LocalPort 8000) -and (Test-LocalPort 5173)) { break }
    Start-Sleep -Milliseconds 300
}
if (-not ((Test-LocalPort 8000) -and (Test-LocalPort 5173))) {
    throw "ForenSight did not start both services within 20 seconds. Check backend/.env and your installed dependencies."
}

$url = "http://127.0.0.1:5173/ForenSight/"
Write-Host "ForenSight is ready at $url"
if (-not $NoBrowser) { Start-Process $url }
