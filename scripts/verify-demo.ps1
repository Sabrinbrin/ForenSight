[CmdletBinding()]
param()

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$demoPath = Join-Path $projectRoot "examples\usb-transfer-demo.json"

$health = Invoke-RestMethod http://127.0.0.1:8000/health
if ($health.status -ne "ok") { throw "The backend health check failed." }
if (-not (Test-Path -LiteralPath $demoPath)) { throw "Known-good demo evidence is missing: $demoPath" }

$case = Get-Content -Raw -LiteralPath $demoPath | ConvertFrom-Json
$body = @{ case = $case } | ConvertTo-Json -Depth 10
$analysis = Invoke-RestMethod -Uri http://127.0.0.1:8000/analyze/investigate -Method Post -ContentType "application/json" -Body $body
if (-not $analysis.generated_by -or -not $analysis.evidence_basis) { throw "The investigation response did not include validated provenance." }

Write-Host "Demo verification passed."
Write-Host "Engine: $($analysis.generated_by)"
Write-Host "Cited evidence records: $(@($analysis.evidence_basis).Count)"
