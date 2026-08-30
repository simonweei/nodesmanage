param(
  [string]$DatabaseName = 'nodemanage',
  [string]$OutputDirectory = ''
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not $OutputDirectory) { $OutputDirectory = Join-Path $projectRoot 'backups' }
$resolvedOutput = [System.IO.Path]::GetFullPath($OutputDirectory)
New-Item -ItemType Directory -Force -Path $resolvedOutput | Out-Null
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd-HHmmss')
$outputFile = Join-Path $resolvedOutput "$DatabaseName-$timestamp.sql"

& npx wrangler d1 export $DatabaseName --remote --skip-confirmation --output $outputFile
if ($LASTEXITCODE -ne 0) { throw "D1 export failed with exit code $LASTEXITCODE" }
Write-Output "D1 backup created: $outputFile"
