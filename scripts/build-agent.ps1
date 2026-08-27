$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$agentSource = Get-Content (Join-Path $projectRoot 'agent\main.go') -Raw
$agentVersion = [regex]::Match($agentSource, 'version\s*=\s*"([^"]+)"').Groups[1].Value
if (-not $agentVersion) { throw 'Cannot read Agent version' }
$outputDir = Join-Path $projectRoot "public\downloads\v$agentVersion"
New-Item -ItemType Directory -Force -Path $outputDir | Out-Null
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$previousLocation = Get-Location
Set-Location -LiteralPath (Join-Path $projectRoot 'agent')
$env:GOARCH = 'amd64'
go build -trimpath -ldflags='-s -w' -o (Join-Path $outputDir 'nodemanage-agent-linux-amd64') .
$env:GOARCH = 'arm64'
go build -trimpath -ldflags='-s -w' -o (Join-Path $outputDir 'nodemanage-agent-linux-arm64') .
Set-Location -LiteralPath $previousLocation
Get-ChildItem -LiteralPath $outputDir -Filter 'nodemanage-agent-linux-*' | Get-FileHash -Algorithm SHA256 | ForEach-Object { "$($_.Hash.ToLower())  $($_.Path | Split-Path -Leaf)" } | Set-Content -Encoding ascii (Join-Path $outputDir 'SHA256SUMS')
node (Join-Path $PSScriptRoot 'generate-release-manifest.mjs')
