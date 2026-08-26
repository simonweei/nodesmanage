$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$outputDir = Join-Path $projectRoot 'public\downloads'
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
