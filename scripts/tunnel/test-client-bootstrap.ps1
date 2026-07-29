param(
    [Parameter(Mandatory = $true)]
    [string]$Installer
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw "installer is absent: $Installer"
}

$workspace = Join-Path ([IO.Path]::GetTempPath()) "rqbit-tunnel-client-bootstrap-$([Guid]::NewGuid().ToString('N'))"
try {
    $bundle = Join-Path $workspace 'bundle'
    $root = Join-Path $workspace 'install'
    New-Item -ItemType Directory -Path $bundle -Force | Out-Null
    Copy-Item -LiteralPath $Installer -Destination (Join-Path $bundle 'install-client.ps1')
    $clientRunSource = Join-Path (Split-Path -Parent $Installer) 'client-run.ps1'
    if (-not (Test-Path -LiteralPath $clientRunSource -PathType Leaf)) {
        throw "client control wrapper is absent: $clientRunSource"
    }
    Copy-Item -LiteralPath $clientRunSource -Destination (Join-Path $bundle 'client-run.ps1')
    $clientRun = Join-Path $bundle 'client-run.ps1'
    & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $clientRun -SelfTest
    if ($LASTEXITCODE -ne 0) {
        throw "client control wrapper self-test failed with $LASTEXITCODE"
    }
    foreach ($name in @('rqbit-tunnel.exe', 'rqbit-tunnel-updater.exe', 'rqbit-tunnel-tray.exe', 'launcher.exe')) {
        [IO.File]::WriteAllBytes((Join-Path $bundle $name), [byte[]](0x4d, 0x5a))
    }
    [IO.File]::WriteAllText((Join-Path $bundle 'release-version.txt'), "1.2.3`n", [Text.UTF8Encoding]::new($false))

    & (Join-Path $bundle 'install-client.ps1') -InstallRoot $root -SkipService
    if (-not $?) {
        throw 'bootstrap failed'
    }

    foreach ($path in @(
        (Join-Path $root 'launcher.exe'),
        (Join-Path $root 'client-run.ps1'),
        (Join-Path $root 'releases\1.2.3\payload\rqbit-tunnel.exe'),
        (Join-Path $root 'releases\1.2.3\payload\rqbit-tunnel-updater.exe'),
        (Join-Path $root 'releases\1.2.3\payload\rqbit-tunnel-tray.exe')
    )) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "bootstrap missed expected file: $path"
        }
    }

    $active = Get-Content -LiteralPath (Join-Path $root 'active.json') -Raw | ConvertFrom-Json
    if ($active.version -ne '1.2.3' -or $active.payload_dir -ne 'releases/1.2.3/payload' -or $active.launcher_abi -ne 1) {
        throw 'bootstrap wrote an unexpected active release pointer'
    }

    [IO.File]::WriteAllText((Join-Path $bundle 'release-version.txt'), "1.2.4`n", [Text.UTF8Encoding]::new($false))
    & (Join-Path $bundle 'install-client.ps1') -InstallRoot $root -SkipService
    if (-not $?) {
        throw 'managed release upgrade failed'
    }

    $upgradedActive = Get-Content -LiteralPath (Join-Path $root 'active.json') -Raw | ConvertFrom-Json
    if ($upgradedActive.version -ne '1.2.4' -or $upgradedActive.payload_dir -ne 'releases/1.2.4/payload' -or $upgradedActive.launcher_abi -ne 1) {
        throw 'upgrade wrote an unexpected active release pointer'
    }
    if (-not (Test-Path -LiteralPath (Join-Path $root 'releases\1.2.4\payload\rqbit-tunnel.exe') -PathType Leaf)) {
        throw 'upgrade missed the new immutable payload'
    }

    $failed = $false
    try {
        & (Join-Path $bundle 'install-client.ps1') -InstallRoot $root -SkipService
        $failed = -not $?
    }
    catch {
        $failed = $true
    }
    if (-not $failed) {
        throw 'bootstrap must not overwrite an immutable existing release directory'
    }

    Write-Host 'Windows client bootstrap contract passed'
}
finally {
    Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
}
