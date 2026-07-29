# Interactive control menu for the managed rqbit tunnel client.
param(
    [switch]$SelfTest,
    [switch]$OpenDashboard
)

$ErrorActionPreference = "Stop"

function New-ElevatedClientEncodedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$ClientArguments,
        [Parameter(Mandatory = $true)]
        [string]$StatusOwnerSid
    )

    $payload = [pscustomobject]@{
        executable = [string]$Executable
        arguments = [string[]]$ClientArguments
        status_owner_sid = [string]$StatusOwnerSid
    }
    $payloadJson = ConvertTo-Json -InputObject $payload -Compress
    $payloadBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payloadJson))
    $decoder = [string]::Join(
        [Environment]::NewLine,
        @(
            '$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''__RQBIT_CLIENT_PAYLOAD__''))',
            '$payload = $payloadJson | ConvertFrom-Json',
            'if ([string]::IsNullOrWhiteSpace([string]$payload.status_owner_sid)) { throw ''missing desktop status owner SID'' }',
            '$env:RQBIT_TUNNEL_STATUS_OWNER_SID = [string]$payload.status_owner_sid',
            '& $payload.executable @([string[]]$payload.arguments)',
            'exit $LASTEXITCODE'
        )
    ).Replace('__RQBIT_CLIENT_PAYLOAD__', $payloadBase64)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decoder))
}

function New-ElevatedClientStartProcessArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,
        [Parameter(Mandatory = $true)]
        [string[]]$ClientArguments,
        [Parameter(Mandatory = $true)]
        [string]$StatusOwnerSid
    )

    return @(
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        (New-ElevatedClientEncodedCommand -Executable $Executable -ClientArguments $ClientArguments -StatusOwnerSid $StatusOwnerSid)
    )
}

function Read-ElevatedClientEncodedPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EncodedCommand
    )

    $decoder = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand))
    $match = [regex]::Match($decoder, "FromBase64String\('(?<payload>[A-Za-z0-9+/=]+)'\)")
    if (-not $match.Success) {
        throw "encoded elevation command does not contain a base64 JSON payload"
    }
    $payloadJson = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($match.Groups['payload'].Value)
    )
    return $payloadJson | ConvertFrom-Json
}
function New-ElevatedInstallerEncodedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Installer
    )

    $payload = [pscustomobject]@{
        executable = [string]$Installer
        arguments = [string[]]@()
    }
    $payloadJson = ConvertTo-Json -InputObject $payload -Compress
    $payloadBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payloadJson))
    $decoder = [string]::Join(
        [Environment]::NewLine,
        @(
            '$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''__RQBIT_INSTALLER_PAYLOAD__''))',
            '$payload = $payloadJson | ConvertFrom-Json',
            '& $payload.executable @([string[]]$payload.arguments)',
            'exit $LASTEXITCODE'
        )
    ).Replace('__RQBIT_INSTALLER_PAYLOAD__', $payloadBase64)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decoder))
}

function New-ElevatedInstallerStartProcessArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Installer
    )

    return @(
        '-NoProfile',
        '-NonInteractive',
        '-EncodedCommand',
        (New-ElevatedInstallerEncodedCommand -Installer $Installer)
    )
}

function Read-ElevatedInstallerEncodedPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EncodedCommand
    )

    $decoder = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand))
    $match = [regex]::Match($decoder, "FromBase64String\('(?<payload>[A-Za-z0-9+/=]+)'\)")
    if (-not $match.Success) {
        throw "encoded installer elevation command does not contain a base64 JSON payload"
    }
    $payloadJson = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($match.Groups['payload'].Value)
    )
    return $payloadJson | ConvertFrom-Json
}

function Get-ElevatedPowerShellHost {
    $hostPath = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($hostPath)) {
        throw "could not determine the current PowerShell host path"
    }
    return $hostPath
}

function Get-ClientTuiMenuAction {
    return [pscustomobject]@{
        ClientArguments = @("client", "tui")
        Protected = $true
    }
}

function Get-ClientConfigShowMenuAction {
    return [pscustomobject]@{
        ClientArguments = @("client", "config", "show")
        Protected = $true
    }
}

if ($SelfTest) {
    $expectedElevatedHost = (Get-Process -Id $PID).Path
    $actualElevatedHost = Get-ElevatedPowerShellHost
    if ($actualElevatedHost -cne $expectedElevatedHost) {
        throw "elevated PowerShell host must come from the current process"
    }
    $tuiAction = Get-ClientTuiMenuAction
    if (-not $tuiAction.Protected -or @($tuiAction.ClientArguments).Count -ne 2 -or $tuiAction.ClientArguments[0] -cne "client" -or $tuiAction.ClientArguments[1] -cne "tui") {
        throw "Windows dashboard launch must use the protected client tui invocation"
    }
    $configShowAction = Get-ClientConfigShowMenuAction
    if (-not $configShowAction.Protected -or @($configShowAction.ClientArguments).Count -ne 3 -or $configShowAction.ClientArguments[0] -cne "client" -or $configShowAction.ClientArguments[1] -cne "config" -or $configShowAction.ClientArguments[2] -cne "show") {
        throw "Windows configuration display must use the protected client config show invocation"
    }
    $expectedExecutable = "C:\Program Files\Rqbit Tunnel\rqbit-tunnel.exe"
    $expectedArguments = @(
        "client",
        "import",
        "--bundle",
        "C:\Users\Alice Example\Bundles\client bundle.json",
        '--literal=$(Get-Date);$HOME'
    )
    $expectedStatusOwnerSid = "S-1-5-21-42424-42425-42426-1001"
    $startProcessArguments = New-ElevatedClientStartProcessArguments -Executable $expectedExecutable -ClientArguments $expectedArguments -StatusOwnerSid $expectedStatusOwnerSid
    if ($startProcessArguments.Count -ne 4 -or $startProcessArguments[0] -cne "-NoProfile" -or $startProcessArguments[1] -cne "-NonInteractive" -or $startProcessArguments[2] -cne "-EncodedCommand") {
        throw "elevated invocation must pass only fixed PowerShell flags and one encoded payload"
    }
    $payload = Read-ElevatedClientEncodedPayload -EncodedCommand $startProcessArguments[3]
    $decoder = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($startProcessArguments[3]))
    if (-not $decoder.Contains('$env:RQBIT_TUNNEL_STATUS_OWNER_SID = [string]$payload.status_owner_sid')) {
        throw "elevated invocation must propagate the desktop status owner SID"
    }
    $actualArguments = [string[]]@($payload.arguments)
    if ($payload.executable -cne $expectedExecutable -or $actualArguments.Count -ne $expectedArguments.Count) {
        throw "elevated invocation payload did not preserve its executable and argument count"
    }
    if ($payload.status_owner_sid -cne $expectedStatusOwnerSid) {
        throw "elevated invocation payload changed the desktop status owner SID"
    }
    for ($index = 0; $index -lt $expectedArguments.Count; $index++) {
        if ($actualArguments[$index] -cne $expectedArguments[$index]) {
            throw "elevated invocation payload changed argument $index"
        }
    }
    $expectedInstaller = "C:\Users\Alice Example\Tunnel Bundle\install-client.ps1"
    $installerStartProcessArguments = New-ElevatedInstallerStartProcessArguments -Installer $expectedInstaller
    if ($installerStartProcessArguments.Count -ne 4 -or $installerStartProcessArguments[0] -cne "-NoProfile" -or $installerStartProcessArguments[1] -cne "-NonInteractive" -or $installerStartProcessArguments[2] -cne "-EncodedCommand") {
        throw "elevated installer invocation must pass only fixed PowerShell flags and one encoded payload"
    }
    $installerPayload = Read-ElevatedInstallerEncodedPayload -EncodedCommand $installerStartProcessArguments[3]
    $actualInstallerArguments = [string[]]@($installerPayload.arguments)
    if ($installerPayload.executable -cne $expectedInstaller -or $actualInstallerArguments.Count -ne 0) {
        throw "elevated installer invocation payload did not preserve its executable and empty argument array"
    }
    if ($installerPayload.PSObject.Properties.Name -contains 'status_owner_sid') {
        throw "elevated installer payload must not carry a desktop status owner SID"
    }
    exit 0
}
function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$managedRoot = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'rqbit-tunnel'
$managedLauncher = Join-Path $managedRoot 'launcher.exe'
$managedActive = Join-Path $managedRoot 'active.json'
if ((Test-Path -LiteralPath $managedLauncher -PathType Leaf) -and (Test-Path -LiteralPath $managedActive -PathType Leaf)) {
    $bin = $managedLauncher
}
else {
    $installer = Join-Path $here 'install-client.ps1'
    $releaseVersion = Join-Path $here 'release-version.txt'
    if ((Test-Path -LiteralPath $installer -PathType Leaf) -and (Test-Path -LiteralPath $releaseVersion -PathType Leaf)) {
        Write-Host 'Installing the managed client release from this bundle...'
        if (Test-Administrator) {
            & $installer
            if (-not $?) {
                throw 'client bootstrap failed'
            }
        }
        else {
            $elevatedHost = Get-ElevatedPowerShellHost
            $process = Start-Process -FilePath $elevatedHost -Verb RunAs -ArgumentList (New-ElevatedInstallerStartProcessArguments -Installer $installer) -Wait -PassThru
            if ($process.ExitCode -ne 0) {
                throw "elevated client bootstrap exited with $($process.ExitCode)"
            }
        }
        if (-not (Test-Path -LiteralPath $managedLauncher -PathType Leaf)) {
            throw "client bootstrap did not install $managedLauncher"
        }
        $bin = $managedLauncher
    }
    else {
        $bin = Join-Path $here "rqbit-tunnel.exe"
        if (-not (Test-Path -LiteralPath $bin -PathType Leaf)) {
            $command = Get-Command "rqbit-tunnel.exe" -ErrorAction SilentlyContinue
            if ($null -eq $command) {
                throw "rqbit-tunnel.exe was not found; use a complete release bundle or add it to PATH"
            }
            $bin = $command.Path
        }
    }
}

function Invoke-ClientCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ClientArguments,
        [switch]$Protected
    )

    if ($Protected -and -not (Test-Administrator)) {
        $desktopSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
        if ($null -eq $desktopSid -or [string]::IsNullOrWhiteSpace($desktopSid.Value)) {
            throw "could not determine the desktop status owner SID before elevation"
        }
        $elevationArguments = New-ElevatedClientStartProcessArguments -Executable $bin -ClientArguments $ClientArguments -StatusOwnerSid $desktopSid.Value
        $elevatedHost = Get-ElevatedPowerShellHost
        # The only Start-Process arguments are fixed flags and one base64 token.
        $process = Start-Process -FilePath $elevatedHost -Verb RunAs -ArgumentList $elevationArguments -Wait -PassThru
        if ($process.ExitCode -ne 0) {
            throw "Elevated rqbit-tunnel command exited with $($process.ExitCode)"
        }
        return
    }

    & $bin @ClientArguments
    if ($LASTEXITCODE -ne 0) {
        throw "rqbit-tunnel command exited with $LASTEXITCODE"
    }
}

if ($OpenDashboard) {
    $tuiAction = Get-ClientTuiMenuAction
    Invoke-ClientCommand -ClientArguments $tuiAction.ClientArguments -Protected:$tuiAction.Protected
    exit 0
}

function Invoke-MenuCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ClientArguments,
        [switch]$Protected,
        [switch]$PassThru
    )

    try {
        Invoke-ClientCommand -ClientArguments $ClientArguments -Protected:$Protected
        if ($PassThru) {
            return $true
        }
    }
    catch {
        Write-Host "error: $($_.Exception.Message)" -ForegroundColor Red
        if ($PassThru) {
            return $false
        }
    }
}

function Set-ClientConfiguration {
    $configArguments = @("client", "config", "set")
    $endpoint = Read-Host "Server endpoint HOST:PORT (blank keeps current)"
    $socks = Read-Host "SOCKS bind HOST:PORT (blank keeps current)"
    $carriers = Read-Host "Carrier count (blank keeps current)"
    $allowLan = Read-Host "Allow unauthenticated LAN SOCKS [true/false, blank keeps current]"

    if (-not [string]::IsNullOrWhiteSpace($endpoint)) {
        $configArguments += @("--server-addr", $endpoint)
    }
    if (-not [string]::IsNullOrWhiteSpace($socks)) {
        $configArguments += @("--socks-listen", $socks)
    }
    if (-not [string]::IsNullOrWhiteSpace($carriers)) {
        $configArguments += @("--carriers", $carriers)
    }
    if (-not [string]::IsNullOrWhiteSpace($allowLan)) {
        if ($allowLan -ne "true" -and $allowLan -ne "false") {
            Write-Host "Allow unauthenticated LAN SOCKS must be true, false, or blank" -ForegroundColor Red
            return
        }
        $configArguments += @("--allow-unauthenticated-lan-socks", $allowLan)
    }

    if ($configArguments.Count -eq 3) {
        Write-Host "No configuration changes selected"
        return
    }
    Invoke-MenuCommand -ClientArguments $configArguments -Protected
}

function Invoke-ServiceMenu {
    Write-Host "Service actions:"
    Write-Host "  1) install/reload service definition"
    Write-Host "  2) start"
    Write-Host "  3) stop"
    Write-Host "  4) restart"
    Write-Host "  5) enable autostart"
    Write-Host "  6) disable autostart"
    $selection = Read-Host "Select service action"
    switch ($selection) {
        "1" { Invoke-MenuCommand -ClientArguments @("client", "service", "install") -Protected }
        "2" { Invoke-MenuCommand -ClientArguments @("client", "service", "start") -Protected }
        "3" { Invoke-MenuCommand -ClientArguments @("client", "service", "stop") -Protected }
        "4" { Invoke-MenuCommand -ClientArguments @("client", "service", "restart") -Protected }
        "5" { Invoke-MenuCommand -ClientArguments @("client", "service", "enable-autostart") -Protected }
        "6" { Invoke-MenuCommand -ClientArguments @("client", "service", "disable-autostart") -Protected }
        default { Write-Host "Unknown service action" -ForegroundColor Red }
    }
}

while ($true) {
    Write-Host ""
    Write-Host "rqbit tunnel client"
    Write-Host "  1) open client dashboard"
    Write-Host "  2) import enrollment bundle"
    Write-Host "  3) show configuration"
    Write-Host "  4) configure client"
    Write-Host "  5) manage service"
    Write-Host "  6) show service status"
    Write-Host "  q) quit"
    $selection = Read-Host "Select action"

    switch ($selection) {
        "1" {
            $tuiAction = Get-ClientTuiMenuAction
            Invoke-MenuCommand -ClientArguments $tuiAction.ClientArguments -Protected:$tuiAction.Protected
        }
        "2" {
            $bundle = Read-Host "Enrollment bundle path"
            if (-not [string]::IsNullOrWhiteSpace($bundle) -and
                (Invoke-MenuCommand -ClientArguments @("client", "import", "--bundle", $bundle) -Protected -PassThru)) {
                if (Invoke-MenuCommand -ClientArguments @("client", "service", "install") -Protected -PassThru) {
                    if (Invoke-MenuCommand -ClientArguments @("client", "service", "enable-autostart") -Protected -PassThru) {
                        Invoke-MenuCommand -ClientArguments @("client", "service", "start") -Protected | Out-Null
                    }
                }
            }
        }
        "3" {
            $configShowAction = Get-ClientConfigShowMenuAction
            Invoke-MenuCommand -ClientArguments $configShowAction.ClientArguments -Protected:$configShowAction.Protected
        }
        "4" { Set-ClientConfiguration }
        "5" { Invoke-ServiceMenu }
        "6" { Invoke-MenuCommand -ClientArguments @("client", "service", "status") }
        "q" { exit 0 }
        "Q" { exit 0 }
        default { Write-Host "Unknown action" -ForegroundColor Red }
    }
}
