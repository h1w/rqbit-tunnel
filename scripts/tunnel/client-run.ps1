# ── rqbit tunnel — client launcher (Windows / PowerShell) ───────────────────
#
#   .\client-run.ps1 <server-host:port>
#
# Expects client.key and server.pub next to this script (as printed by the
# server quickstart). Then point your browser/app SOCKS5 proxy at 127.0.0.1:1080.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$bin = Join-Path $here "rqbit.exe"
if (-not (Test-Path $bin)) { $bin = "rqbit.exe" }  # fall back to PATH

$server = if ($args.Count -ge 1) { $args[0] } elseif ($env:TUNNEL_SERVER) { $env:TUNNEL_SERVER } else { $null }
if (-not $server) { $server = Read-Host "Server address (host:port)" }

$socks = if ($env:SOCKS_LISTEN) { $env:SOCKS_LISTEN } else { "127.0.0.1:1080" }
$data = Join-Path $here "client-data"
New-Item -ItemType Directory -Force -Path $data | Out-Null

foreach ($f in @("client.key", "server.pub")) {
    if (-not (Test-Path (Join-Path $here $f))) {
        Write-Error "$f not found next to this script — copy it from the server quickstart output"
        exit 1
    }
}

$httpApi = if ($env:RQBIT_HTTP_API) { $env:RQBIT_HTTP_API } else { "127.0.0.1:3030" }

Write-Host "Tunnel client -> $server"
Write-Host "Point your browser/app SOCKS5 proxy at $socks"
& $bin `
    --disable-dht --disable-dht-persistence `
    --disable-tcp-listen --disable-upnp-port-forward `
    --http-api-listen-addr $httpApi `
    server start --disable-persistence $data `
    --tunnel-mode client `
    --tunnel-socks-listen $socks `
    --tunnel-server-addr $server `
    --tunnel-client-key (Join-Path $here "client.key") `
    --tunnel-server-key (Join-Path $here "server.pub")
