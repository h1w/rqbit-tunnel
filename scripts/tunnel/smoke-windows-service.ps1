param(
    [string]$Bundle,
    [switch]$Help
)

$ErrorActionPreference = 'Stop'

function Show-Usage {
    Write-Host 'usage: smoke-windows-service.ps1 -Bundle PATH'
    Write-Host 'Runs only on a disposable elevated Windows CI runner.'
}

function Test-RegularFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
}

function Wait-ServiceState([string]$Expected) {
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        $query = & sc.exe query $serviceName 2>&1
        if ($LASTEXITCODE -eq 0 -and ($query -join "`n") -match "STATE\s*:\s*\d+\s+$Expected") {
            return
        }
        Start-Sleep -Seconds 1
    }
    throw "service did not reach $Expected state: $(& sc.exe query $serviceName 2>&1)"
}

function Describe-DirectorySecurity([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Container)) {
        return 'missing'
    }
    try {
        $acl = Get-Acl -LiteralPath $Path
        return "owner=$($acl.Owner); protected=$($acl.AreAccessRulesProtected); sddl=$($acl.Sddl)"
    }
    catch {
        return "unavailable: $($_.Exception.Message)"
    }
}

if ($Help) {
    Show-Usage
    exit 0
}
$serviceName = 'rqbit-tunnel-client'
$installRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'rqbit-tunnel'
$dataRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'rqbit-tunnel'
$workspace = Join-Path ([IO.Path]::GetTempPath()) "rqbit-tunnel-windows-smoke-$([Guid]::NewGuid().ToString('N'))"
if ([string]::IsNullOrWhiteSpace($Bundle)) {
    Show-Usage
    throw 'Bundle is required'
}
if (-not (Test-RegularFile $Bundle)) {
    throw "bundle is not a regular file: $Bundle"
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = [Security.Principal.WindowsPrincipal]::new($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'this smoke test must run elevated on a disposable Windows runner'
}
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $dataRoot)) {
    throw 'refusing to overwrite existing managed client paths'
}
$existing = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
if ($null -ne $existing) {
    throw "refusing to overwrite existing service: $serviceName"
}

try {
    $extract = Join-Path $workspace 'extract'
    Expand-Archive -LiteralPath $Bundle -DestinationPath $extract
    $entries = @(Get-ChildItem -LiteralPath $extract -Force)
    if ($entries.Count -ne 1 -or -not $entries[0].PSIsContainer) {
        throw 'release archive must contain exactly one wrapper directory'
    }
    $wrapper = $entries[0].FullName
    $installer = Join-Path $wrapper 'install-client.ps1'
    $tray = Join-Path $wrapper 'rqbit-tunnel-tray.exe'
    if (-not (Test-RegularFile $installer) -or -not (Test-RegularFile $tray)) {
        throw 'release archive has no managed Windows client bootstrap assets'
    }

    $firstVersionPath = Join-Path $wrapper 'release-version.txt'
    if (-not (Test-RegularFile $firstVersionPath)) {
        throw 'release archive has no managed Windows client release version'
    }
    $firstVersion = [IO.File]::ReadAllText($firstVersionPath) -replace '\r?\n$', ''

    & $installer -SkipService
    if (-not $?) {
        throw 'client bootstrap failed'
    }

    $enrollment = [ordered]@{
        schema_version = 1
        user_name = 'smoke-client'
        client_private_key = ('01' * 32)
        server_public_key = ('02' * 32)
        server_addr = '127.0.0.1:4242'
        socks_listen = '127.0.0.1:1080'
        carriers = 1
    } | ConvertTo-Json -Compress
    $enrollmentPath = Join-Path $workspace 'smoke-client.rqbt'
    [IO.File]::WriteAllText($enrollmentPath, $enrollment, [Text.UTF8Encoding]::new($false))
    & $launcher client import --bundle $enrollmentPath
    if ($LASTEXITCODE -ne 0) {
        $dataRootSecurity = Describe-DirectorySecurity $dataRoot
        throw "client enrollment import exited with $LASTEXITCODE; data root security: $dataRootSecurity"
    }
    & $launcher client service install
    if ($LASTEXITCODE -ne 0) {
        throw "client service install exited with $LASTEXITCODE"
    }
    & $launcher client service install
    if ($LASTEXITCODE -ne 0) {
        throw "client service reinstall exited with $LASTEXITCODE"
    }
    & $launcher client service enable-autostart
    if ($LASTEXITCODE -ne 0) {
        throw "client service autostart enable exited with $LASTEXITCODE"
    }
    & $launcher client service start
    if ($LASTEXITCODE -ne 0) {
        throw "client service start exited with $LASTEXITCODE"
    }

    Wait-ServiceState 'RUNNING'
    $status = & $launcher client service status --json
    if ($LASTEXITCODE -ne 0 -or ($status -join "`n") -notmatch '"service":"running"') {
        throw "client status did not report running: $status"
    }

    $secondVersion = if ($firstVersion -ceq '9.0.1') { '9.0.2' } else { '9.0.1' }
    $secondWrapper = Join-Path $workspace 'second-bundle'
    Copy-Item -LiteralPath $wrapper -Destination $secondWrapper -Recurse -Force
    $secondInstaller = Join-Path $secondWrapper 'install-client.ps1'
    $secondVersionPath = Join-Path $secondWrapper 'release-version.txt'
    if (-not (Test-RegularFile $secondInstaller) -or -not (Test-RegularFile $secondVersionPath)) {
        throw 'second local bundle has no managed Windows client bootstrap assets'
    }
    [IO.File]::WriteAllText($secondVersionPath, "$secondVersion`n", [Text.UTF8Encoding]::new($false))

    & $secondInstaller
    if (-not $?) {
        throw 'second client bootstrap failed'
    }

    $activePath = Join-Path $installRoot 'active.json'
    if (-not (Test-RegularFile $activePath)) {
        throw 'second client bootstrap did not write an active release pointer'
    }
    $active = [IO.File]::ReadAllText($activePath) | ConvertFrom-Json
    if ($active.version -cne $secondVersion) {
        throw "active release version did not upgrade to $secondVersion"
    }
    Wait-ServiceState 'RUNNING'

    & $launcher client service disable-autostart
    & $launcher client service stop
    Wait-ServiceState 'STOPPED'
    Write-Host 'Windows service release smoke passed'
}
finally {
    & sc.exe stop $serviceName 2>$null | Out-Null
    & sc.exe delete $serviceName 2>$null | Out-Null
    Remove-Item -LiteralPath $installRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $dataRoot -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $workspace -Recurse -Force -ErrorAction SilentlyContinue
}
