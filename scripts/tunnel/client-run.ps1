# rqbit tunnel - client launcher (Windows / PowerShell)
#
#   .\client-run.ps1 [server-host:port]
#
# The server address is OPTIONAL. If you pass it (or type it at the prompt) it is
# used as a fast, reliable path. If you leave it empty, the client finds the
# server purely via the DHT (using the pinned server key) - handy when the
# server's IP changes, but it needs the server to be publicly reachable on its
# tunnel port and can take up to ~1 minute to discover.
#
# Expects client.key and server.pub next to this script. Then point your
# browser/app SOCKS5 proxy at 127.0.0.1:1080.
#
# The argument list is built as an array and splatted (`@rqbitArgs`) instead of
# using backtick line-continuations, which mis-parse under Windows PowerShell
# 5.1 when the script has LF line endings. Kept ASCII-only for the same reason.

$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path

$bin = Join-Path $here "rqbit.exe"
if (-not (Test-Path $bin)) { $bin = "rqbit.exe" }  # fall back to PATH

$server = if ($args.Count -ge 1) { $args[0] } elseif ($env:TUNNEL_SERVER) { $env:TUNNEL_SERVER } else { $null }
if (-not $server) {
    $server = Read-Host "Server address host:port (or press Enter to find it via DHT)"
}

$socks = if ($env:SOCKS_LISTEN) { $env:SOCKS_LISTEN } else { "127.0.0.1:1080" }
$httpApi = if ($env:RQBIT_HTTP_API) { $env:RQBIT_HTTP_API } else { "127.0.0.1:3030" }
$data = Join-Path $here "client-data"
New-Item -ItemType Directory -Force -Path $data | Out-Null

foreach ($f in @("client.key", "server.pub")) {
    if (-not (Test-Path (Join-Path $here $f))) {
        Write-Error "$f not found next to this script - copy it from the server quickstart output"
        exit 1
    }
}

$rqbitArgs = @(
    "--disable-tcp-listen", "--disable-upnp-port-forward",
    "--http-api-listen-addr", $httpApi,
    "server", "start", "--disable-persistence", $data,
    "--tunnel-mode", "client",
    "--tunnel-socks-listen", $socks,
    "--tunnel-client-key", (Join-Path $here "client.key"),
    "--tunnel-server-key", (Join-Path $here "server.pub")
)
if ($server) {
    $rqbitArgs += @("--tunnel-server-addr", $server)
    Write-Host "Tunnel client -> $server (with DHT)"
} else {
    Write-Host "Tunnel client -> discovering the server via DHT (can take up to ~1 min)"
}
Write-Host "Point your browser/app SOCKS5 proxy at $socks"

& $bin @rqbitArgs
