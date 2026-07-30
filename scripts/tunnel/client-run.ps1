# Interactive control menu for the managed rqbit tunnel client.
param(
    [switch]$SelfTest,
    [switch]$OpenDashboard,
    [switch]$ElevatedMenu,
    [string]$StatusOwnerSid
)

$ErrorActionPreference = "Stop"

function New-ElevatedMenuEncodedCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$StatusOwnerSid,
        [switch]$OpenDashboard
    )

    $payload = [pscustomobject]@{
        script_path = [string]$ScriptPath
        status_owner_sid = [string]$StatusOwnerSid
        open_dashboard = [bool]$OpenDashboard
    }
    $payloadJson = ConvertTo-Json -InputObject $payload -Compress
    $payloadBase64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payloadJson))
    $decoder = [string]::Join(
        [Environment]::NewLine,
        @(
            '$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''__RQBIT_MENU_PAYLOAD__''))',
            '$payload = $payloadJson | ConvertFrom-Json',
            'if ([string]::IsNullOrWhiteSpace([string]$payload.script_path)) { throw ''missing client control script path'' }',
            'if ([string]::IsNullOrWhiteSpace([string]$payload.status_owner_sid)) { throw ''missing desktop status owner SID'' }',
            '$ErrorActionPreference = ''Stop''',
            '$scriptArguments = @{',
            '    ElevatedMenu = $true',
            '    StatusOwnerSid = [string]$payload.status_owner_sid',
            '}',
            'if ([bool]$payload.open_dashboard) {',
            '    $scriptArguments.OpenDashboard = $true',
            '}',
            'try {',
            '    & ([string]$payload.script_path) @scriptArguments',
            '}',
            'catch {',
            '    [Console]::Error.WriteLine("could not launch elevated client control script: $($_.Exception.Message)")',
            '    exit 1',
            '}',
            'exit $LASTEXITCODE'
        )
    ).Replace('__RQBIT_MENU_PAYLOAD__', $payloadBase64)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decoder))
}

function New-ElevatedMenuStartProcessArguments {
    param(
        [Parameter(Mandatory = $true)]
        [string]$ScriptPath,
        [Parameter(Mandatory = $true)]
        [string]$StatusOwnerSid,
        [switch]$OpenDashboard
    )

    return @(
        '-NoProfile',
        '-ExecutionPolicy',
        'Bypass',
        '-EncodedCommand',
        (New-ElevatedMenuEncodedCommand -ScriptPath $ScriptPath -StatusOwnerSid $StatusOwnerSid -OpenDashboard:$OpenDashboard)
    )
}

function Read-ElevatedMenuEncodedPayload {
    param(
        [Parameter(Mandatory = $true)]
        [string]$EncodedCommand
    )

    $decoder = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand))
    $match = [regex]::Match($decoder, "FromBase64String\('(?<payload>[A-Za-z0-9+/=]+)'\)")
    if (-not $match.Success) {
        throw "encoded menu elevation command does not contain a base64 JSON payload"
    }
    $payloadJson = [Text.Encoding]::UTF8.GetString(
        [Convert]::FromBase64String($match.Groups['payload'].Value)
    )
    return $payloadJson | ConvertFrom-Json
}

function Get-ClientMenuLaunchMode {
    param(
        [Parameter(Mandatory = $true)]
        [bool]$Administrator,
        [Parameter(Mandatory = $true)]
        [bool]$ElevatedMenu
    )

    if ($ElevatedMenu -and -not $Administrator) {
        return 'reject'
    }
    if ($Administrator) {
        return 'run'
    }
    return 'elevate'
}

function Get-CurrentUserSid {
    try {
        $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
        $sid = $identity.User
    }
    catch {
        throw "could not determine the current user SID: $($_.Exception.Message)"
    }
    if ($null -eq $sid -or [string]::IsNullOrWhiteSpace($sid.Value)) {
        throw 'could not determine the current user SID'
    }
    return $sid.Value
}

function ConvertTo-StatusOwnerSid {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    if ([string]::IsNullOrWhiteSpace($Value)) {
        throw 'status owner SID must not be empty'
    }
    try {
        $sid = [Security.Principal.SecurityIdentifier]::new($Value)
    }
    catch {
        throw "invalid status owner SID '$Value': $($_.Exception.Message)"
    }
    return $sid.Value
}

function Get-ElevatedPowerShellHost {
    $hostPath = (Get-Process -Id $PID).Path
    if ([string]::IsNullOrWhiteSpace($hostPath)) {
        throw "could not determine the current PowerShell host path"
    }
    return $hostPath
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-ClientTuiMenuAction {
    return [pscustomobject]@{
        ClientArguments = @("client", "tui")
    }
}

function Get-ClientConfigShowMenuAction {
    return [pscustomobject]@{
        ClientArguments = @("client", "config", "show")
    }
}

function Test-RegularEnrollmentBundleCandidate {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Item
    )

    $stream = $null
    try {
        if ([bool]$Item.PSIsContainer) {
            return $false
        }
        $attributes = [IO.FileAttributes]$Item.Attributes
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            return $false
        }
        $stream = [IO.File]::Open(
            [string]$Item.FullName,
            [IO.FileMode]::Open,
            [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite
        )
        return $true
    }
    catch {
        return $false
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
    }
}

function Get-EnrollmentBundleCandidates {
    param(
        [string]$Directory
    )

    if ([string]::IsNullOrWhiteSpace($Directory) -or
        -not (Test-Path -LiteralPath $Directory -PathType Container)) {
        return @()
    }

    try {
        $items = @(Get-ChildItem -LiteralPath $Directory -Filter '*.rqbt' -Force)
    }
    catch {
        return @()
    }

    return @(
        foreach ($item in $items) {
            if (Test-RegularEnrollmentBundleCandidate -Item $item) {
                $item.FullName
            }
        }
    )
}

function Resolve-EnrollmentBundlePath {
    param(
        [AllowEmptyString()]
        [string]$EnteredPath,
        [string[]]$Candidates
    )

    if (-not [string]::IsNullOrWhiteSpace($EnteredPath)) {
        return $EnteredPath
    }
    if (@($Candidates).Count -eq 1) {
        return $Candidates[0]
    }
    return $null
}

function Read-EnrollmentBundlePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Directory
    )

    $candidates = @(Get-EnrollmentBundleCandidates -Directory $Directory)
    if ($candidates.Count -eq 0) {
        Write-Host 'No .rqbt was found beside client-run.ps1. Enter an explicit enrollment bundle path.'
        $enteredPath = Read-Host 'Enrollment bundle path'
    }
    elseif ($candidates.Count -eq 1) {
        $candidateName = [IO.Path]::GetFileName($candidates[0])
        $enteredPath = Read-Host "Enrollment bundle path (press Enter to use $candidateName)"
    }
    else {
        Write-Host 'Multiple .rqbt enrollment bundles were found beside client-run.ps1:'
        foreach ($candidate in $candidates) {
            Write-Host "  $([IO.Path]::GetFileName($candidate))"
        }
        Write-Host 'Enter an explicit enrollment bundle path.'
        $enteredPath = Read-Host 'Enrollment bundle path'
    }

    $bundle = Resolve-EnrollmentBundlePath -EnteredPath $enteredPath -Candidates $candidates
    if (-not [string]::IsNullOrWhiteSpace($enteredPath)) {
        return $bundle
    }
    if ($null -ne $bundle) {
        Write-Host "Using enrollment bundle: $bundle"
        return $bundle
    }
    Write-Host 'Enrollment bundle was not selected'
    return $null
}

if ($SelfTest) {
    $expectedElevatedHost = (Get-Process -Id $PID).Path
    $actualElevatedHost = Get-ElevatedPowerShellHost
    if ($actualElevatedHost -cne $expectedElevatedHost) {
        throw "elevated PowerShell host must come from the current process"
    }
    $launchCases = @(
        [pscustomobject]@{ Administrator = $false; ElevatedMenu = $false; Expected = 'elevate' },
        [pscustomobject]@{ Administrator = $false; ElevatedMenu = $true; Expected = 'reject' },
        [pscustomobject]@{ Administrator = $true; ElevatedMenu = $false; Expected = 'run' },
        [pscustomobject]@{ Administrator = $true; ElevatedMenu = $true; Expected = 'run' }
    )
    foreach ($case in $launchCases) {
        $actual = Get-ClientMenuLaunchMode -Administrator:$case.Administrator -ElevatedMenu:$case.ElevatedMenu
        if ($actual -cne $case.Expected) {
            throw "unexpected menu launch mode: expected $($case.Expected), got $actual"
        }
    }

    $expectedStatusOwnerSid = 'S-1-5-21-42424-42425-42426-1001'
    $captureDirectory = Join-Path ([IO.Path]::GetTempPath()) ("rqbit tunnel menu self test " + [Guid]::NewGuid().ToString("N"))
    $captureScriptPath = Join-Path $captureDirectory 'capture-menu-invocation.ps1'
    $captureResultPath = Join-Path $captureDirectory 'capture-menu-invocation.json'
    $captureEnvironmentVariable = 'RQBIT_TUNNEL_MENU_CAPTURE_PATH'
    $previousCaptureResultPath = [Environment]::GetEnvironmentVariable($captureEnvironmentVariable, 'Process')
    [IO.Directory]::CreateDirectory($captureDirectory) | Out-Null
    Set-Content -LiteralPath $captureScriptPath -Value @'
[CmdletBinding(PositionalBinding = $false)]
param(
    [switch]$ElevatedMenu,
    [string]$StatusOwnerSid,
    [switch]$OpenDashboard
)

[pscustomobject]@{
    ElevatedMenu = [bool]$ElevatedMenu
    StatusOwnerSid = $StatusOwnerSid
    OpenDashboard = [bool]$OpenDashboard
    UnexpectedArgumentCount = $args.Count
} | ConvertTo-Json -Compress | Set-Content -LiteralPath $env:RQBIT_TUNNEL_MENU_CAPTURE_PATH -NoNewline
'@
    try {
        [Environment]::SetEnvironmentVariable($captureEnvironmentVariable, $captureResultPath, 'Process')
        foreach ($openDashboard in @($false, $true)) {
            $menuArguments = New-ElevatedMenuStartProcessArguments `
                -ScriptPath $captureScriptPath `
                -StatusOwnerSid $expectedStatusOwnerSid `
                -OpenDashboard:$openDashboard
            if ($menuArguments.Count -ne 5 -or
                $menuArguments[0] -cne '-NoProfile' -or
                $menuArguments[1] -cne '-ExecutionPolicy' -or
                $menuArguments[2] -cne 'Bypass' -or
                $menuArguments[3] -cne '-EncodedCommand') {
                throw 'elevated menu invocation must contain only fixed PowerShell flags and one encoded payload'
            }
            $menuPayload = Read-ElevatedMenuEncodedPayload -EncodedCommand $menuArguments[4]
            if ($menuPayload.script_path -cne $captureScriptPath -or
                $menuPayload.status_owner_sid -cne $expectedStatusOwnerSid -or
                $menuPayload.PSObject.Properties.Name -notcontains 'open_dashboard' -or
                [bool]$menuPayload.open_dashboard -ne $openDashboard) {
                throw 'elevated menu payload did not preserve the script, desktop SID, and dashboard mode'
            }

            $captureProcess = Start-Process -FilePath $actualElevatedHost -ArgumentList $menuArguments -Wait -PassThru
            if ($captureProcess.ExitCode -ne 0) {
                throw "elevated menu payload execution exited with $($captureProcess.ExitCode)"
            }
            if (-not (Test-Path -LiteralPath $captureResultPath -PathType Leaf)) {
                throw 'elevated menu payload execution did not write its invocation capture'
            }
            $menuCapture = Get-Content -LiteralPath $captureResultPath -Raw | ConvertFrom-Json
            if (-not [bool]$menuCapture.ElevatedMenu -or
                $menuCapture.StatusOwnerSid -cne $expectedStatusOwnerSid -or
                [bool]$menuCapture.OpenDashboard -ne $openDashboard -or
                [int]$menuCapture.UnexpectedArgumentCount -ne 0) {
                throw 'elevated menu payload did not bind its internal menu parameters exactly'
            }
            Remove-Item -LiteralPath $captureResultPath -Force
        }
        $missingScriptPath = Join-Path $captureDirectory 'missing menu target.ps1'
        $missingArguments = New-ElevatedMenuStartProcessArguments `
            -ScriptPath $missingScriptPath `
            -StatusOwnerSid $expectedStatusOwnerSid
        $missingProcess = Start-Process -FilePath $actualElevatedHost -ArgumentList $missingArguments -Wait -PassThru
        if ($missingProcess.ExitCode -eq 0) {
            throw 'elevated menu payload must fail when its target script is missing'
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable($captureEnvironmentVariable, $previousCaptureResultPath, 'Process')
        Remove-Item -LiteralPath $captureDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }

    $tuiAction = Get-ClientTuiMenuAction
    if (@($tuiAction.ClientArguments).Count -ne 2 -or $tuiAction.ClientArguments[0] -cne "client" -or $tuiAction.ClientArguments[1] -cne "tui") {
        throw "Windows dashboard launch must use the client tui invocation"
    }
    if ($tuiAction.PSObject.Properties.Name -contains 'Protected') {
        throw 'dashboard actions must not create an action-specific elevation boundary'
    }

    $configShowAction = Get-ClientConfigShowMenuAction
    if (@($configShowAction.ClientArguments).Count -ne 3 -or $configShowAction.ClientArguments[0] -cne "client" -or $configShowAction.ClientArguments[1] -cne "config" -or $configShowAction.ClientArguments[2] -cne "show") {
        throw "Windows configuration display must use the client config show invocation"
    }
    if ($configShowAction.PSObject.Properties.Name -contains 'Protected') {
        throw 'configuration display actions must not create an action-specific elevation boundary'
    }
    $bundleTestDirectory = Join-Path ([IO.Path]::GetTempPath()) ("rqbit tunnel enrollment bundles " + [Guid]::NewGuid().ToString("N"))
    [IO.Directory]::CreateDirectory($bundleTestDirectory) | Out-Null
    try {
        $noCandidates = @(Get-EnrollmentBundleCandidates -Directory $bundleTestDirectory)
        if ($noCandidates.Count -ne 0) {
            throw 'an empty bundle directory must not produce enrollment candidates'
        }

        $aliceBundle = Join-Path $bundleTestDirectory 'alice bundle.rqbt'
        [IO.File]::WriteAllText($aliceBundle, 'alice')
        $singleCandidate = @(Get-EnrollmentBundleCandidates -Directory $bundleTestDirectory)
        if ($singleCandidate.Count -ne 1 -or $singleCandidate[0] -cne $aliceBundle) {
            throw 'the single adjacent enrollment bundle must be returned exactly'
        }
        $singleBlankResolution = Resolve-EnrollmentBundlePath -EnteredPath '' -Candidates $singleCandidate
        if ($singleBlankResolution -cne $aliceBundle) {
            throw 'a blank bundle path must resolve the sole adjacent enrollment bundle'
        }

        $explicitBundle = 'C:\explicit path\bob.rqbt'
        $explicitResolution = Resolve-EnrollmentBundlePath -EnteredPath $explicitBundle -Candidates $singleCandidate
        if ($explicitResolution -cne $explicitBundle) {
            throw 'an explicit enrollment bundle path must win over an adjacent candidate'
        }

        $bobBundle = Join-Path $bundleTestDirectory 'bob.rqbt'
        [IO.File]::WriteAllText($bobBundle, 'bob')
        $multipleCandidates = @(Get-EnrollmentBundleCandidates -Directory $bundleTestDirectory)
        if ($multipleCandidates.Count -ne 2) {
            throw 'two adjacent enrollment bundles must remain two candidates'
        }
        $multipleBlankResolution = Resolve-EnrollmentBundlePath -EnteredPath '' -Candidates $multipleCandidates
        if ($null -ne $multipleBlankResolution) {
            throw 'a blank bundle path must not guess among multiple adjacent candidates'
        }

        $syntheticDirectoryItem = [pscustomobject]@{
            PSIsContainer = $true
            Attributes = [IO.FileAttributes]::Normal
            FullName = $aliceBundle
        }
        if (Test-RegularEnrollmentBundleCandidate -Item $syntheticDirectoryItem) {
            throw 'a directory item must not be an enrollment bundle candidate'
        }

        $syntheticReparsePointItem = [pscustomobject]@{
            PSIsContainer = $false
            Attributes = [IO.FileAttributes]::ReparsePoint
            FullName = $aliceBundle
        }
        if (Test-RegularEnrollmentBundleCandidate -Item $syntheticReparsePointItem) {
            throw 'a reparse-point item must not be an enrollment bundle candidate'
        }

        $missingItem = [pscustomobject]@{
            PSIsContainer = $false
            Attributes = [IO.FileAttributes]::Normal
            FullName = (Join-Path $bundleTestDirectory 'missing bundle.rqbt')
        }
        if (Test-RegularEnrollmentBundleCandidate -Item $missingItem) {
            throw 'a missing regular-looking item must not be an enrollment bundle candidate'
        }

        $unreadableBundle = Join-Path $bundleTestDirectory 'unreadable bundle.rqbt'
        [IO.File]::WriteAllText($unreadableBundle, 'unreadable')
        $unreadableStream = [IO.File]::Open(
            $unreadableBundle,
            [IO.FileMode]::Open,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
        try {
            if (Test-RegularEnrollmentBundleCandidate -Item (Get-Item -LiteralPath $unreadableBundle -Force)) {
                throw 'an unreadable regular-looking item must not be an enrollment bundle candidate'
            }
        }
        finally {
            $unreadableStream.Dispose()
        }
    }
    finally {
        Remove-Item -LiteralPath $bundleTestDirectory -Recurse -Force -ErrorAction SilentlyContinue
    }
    $menuOutputSentinel = 'rqbit tunnel menu output self-test'
    $bin = {
        param(
            [Parameter(ValueFromRemainingArguments = $true)]
            [string[]]$Arguments
        )
        Write-Output $menuOutputSentinel
        & $env:ComSpec /d /c exit 0
    }
    $successfulMenuResult = @(Invoke-MenuCommand -ClientArguments @('client', 'import') -PassThru)
    if ($successfulMenuResult.Count -ne 1 -or [bool]$successfulMenuResult[0] -ne $true) {
        throw 'successful menu commands must return only true when their output is displayed'
    }

    $bin = {
        param(
            [Parameter(ValueFromRemainingArguments = $true)]
            [string[]]$Arguments
        )
        Write-Output $menuOutputSentinel
        & $env:ComSpec /d /c exit 1
    }
    $failedMenuResult = @(Invoke-MenuCommand -ClientArguments @('client', 'import') -PassThru)
    if ($failedMenuResult.Count -ne 1 -or [bool]$failedMenuResult[0] -ne $false) {
        throw 'failed menu commands must return only false when their output is displayed'
    }
    exit 0
}

$scriptPath = $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptPath)) {
    throw 'could not resolve the client control script path'
}

$launchMode = Get-ClientMenuLaunchMode `
    -Administrator:(Test-Administrator) `
    -ElevatedMenu:$ElevatedMenu
if ($launchMode -eq 'reject') {
    throw 'client control received -ElevatedMenu without administrator privileges'
}
if ($launchMode -eq 'elevate') {
    $desktopSid = Get-CurrentUserSid
    $arguments = New-ElevatedMenuStartProcessArguments `
        -ScriptPath $scriptPath `
        -StatusOwnerSid $desktopSid `
        -OpenDashboard:$OpenDashboard
    try {
        $process = Start-Process `
            -FilePath (Get-ElevatedPowerShellHost) `
            -Verb RunAs `
            -ArgumentList $arguments `
            -Wait `
            -PassThru
    }
    catch {
        throw "could not open the elevated client control console: $($_.Exception.Message)"
    }
    if ($process.ExitCode -ne 0) {
        throw "elevated client control console exited with $($process.ExitCode)"
    }
    exit 0
}

if ([string]::IsNullOrWhiteSpace($StatusOwnerSid)) {
    $StatusOwnerSid = Get-CurrentUserSid
}
$env:RQBIT_TUNNEL_STATUS_OWNER_SID = ConvertTo-StatusOwnerSid -Value $StatusOwnerSid

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
        & $installer
        if (-not $?) {
            throw 'client bootstrap failed'
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
        [string[]]$ClientArguments
    )

    & $bin @ClientArguments
    if ($LASTEXITCODE -ne 0) {
        throw "rqbit-tunnel command exited with $LASTEXITCODE"
    }
}

if ($OpenDashboard) {
    $tuiAction = Get-ClientTuiMenuAction
    Invoke-ClientCommand -ClientArguments $tuiAction.ClientArguments
    exit 0
}

function Invoke-MenuCommand {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$ClientArguments,
        [switch]$PassThru
    )

    try {
        Invoke-ClientCommand -ClientArguments $ClientArguments
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
    Invoke-MenuCommand -ClientArguments $configArguments
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
        "1" { Invoke-MenuCommand -ClientArguments @("client", "service", "install") }
        "2" { Invoke-MenuCommand -ClientArguments @("client", "service", "start") }
        "3" { Invoke-MenuCommand -ClientArguments @("client", "service", "stop") }
        "4" { Invoke-MenuCommand -ClientArguments @("client", "service", "restart") }
        "5" { Invoke-MenuCommand -ClientArguments @("client", "service", "enable-autostart") }
        "6" { Invoke-MenuCommand -ClientArguments @("client", "service", "disable-autostart") }
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
            Invoke-MenuCommand -ClientArguments $tuiAction.ClientArguments
        }
        "2" {
            $bundle = Read-EnrollmentBundlePath -Directory $here
            if ($null -ne $bundle -and
                (Invoke-MenuCommand -ClientArguments @('client', 'import', '--bundle', $bundle) -PassThru)) {
                if (Invoke-MenuCommand -ClientArguments @('client', 'service', 'install') -PassThru) {
                    if (Invoke-MenuCommand -ClientArguments @('client', 'service', 'enable-autostart') -PassThru) {
                        Invoke-MenuCommand -ClientArguments @('client', 'service', 'start') | Out-Null
                    }
                }
            }
        }
        "3" {
            $configShowAction = Get-ClientConfigShowMenuAction
            Invoke-MenuCommand -ClientArguments $configShowAction.ClientArguments
        }
        "4" { Set-ClientConfiguration }
        "5" { Invoke-ServiceMenu }
        "6" { Invoke-MenuCommand -ClientArguments @("client", "service", "status") }
        "q" { exit 0 }
        "Q" { exit 0 }
        default { Write-Host "Unknown action" -ForegroundColor Red }
    }
}
