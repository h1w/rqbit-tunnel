# Bootstrap one trusted rqbit-tunnel client release into the managed layout.
param(
    [string]$InstallRoot = (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'rqbit-tunnel'),
    [switch]$SkipService
)

$ErrorActionPreference = 'Stop'
$scriptDirectory = Split-Path -Parent $MyInvocation.MyCommand.Path
$launcherAbi = 1

function Fail([string]$Message) {
    throw "rqbit-tunnel client bootstrap: $Message"
}

function Test-RegularFile([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        return $false
    }
    $item = Get-Item -LiteralPath $Path -Force
    return (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0)
}

function Require-RegularFile([string]$Path) {
    if (-not (Test-RegularFile $Path)) {
        Fail "required regular file is missing: $Path"
    }
}

function Require-ExecutableFile([string]$Path) {
    Require-RegularFile $Path
}

function Ensure-Directory([string]$Path) {
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
            Fail "expected a non-reparse directory: $Path"
        }
        return
    }
    New-Item -ItemType Directory -Path $Path -Force | Out-Null
}

function Write-AtomicFile {
    param(
        [Parameter(Mandatory = $true)] [string]$Source,
        [Parameter(Mandatory = $true)] [string]$Destination
    )

    $parent = Split-Path -Parent $Destination
    $name = Split-Path -Leaf $Destination
    if (Test-Path -LiteralPath $Destination) {
        if (-not (Test-RegularFile $Destination)) {
            Fail "destination is not a replaceable regular file: $Destination"
        }
    }
    $temporary = Join-Path $parent ".${name}.$([Guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::Copy($Source, $temporary, $false)
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}
function Write-AtomicTextFile {
    param(
        [Parameter(Mandatory = $true)] [string]$Content,
        [Parameter(Mandatory = $true)] [string]$Destination
    )

    if (Test-Path -LiteralPath $Destination) {
        if (-not (Test-RegularFile $Destination)) {
            Fail "destination is not a replaceable regular file: $Destination"
        }
    }
    $parent = Split-Path -Parent $Destination
    $name = Split-Path -Leaf $Destination
    $temporary = Join-Path $parent ".${name}.$([Guid]::NewGuid().ToString('N'))"
    try {
        [IO.File]::WriteAllText($temporary, $Content, [Text.UTF8Encoding]::new($false))
        Move-Item -LiteralPath $temporary -Destination $Destination -Force
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function New-RollbackFileSnapshot {
    param(
        [Parameter(Mandatory = $true)] [string]$Path,
        [Parameter(Mandatory = $true)] [string]$RollbackDirectory,
        [Parameter(Mandatory = $true)] [string]$Name
    )

    $backupPath = Join-Path $RollbackDirectory $Name
    $existed = Test-Path -LiteralPath $Path
    if ($existed) {
        Require-RegularFile $Path
        [IO.File]::Copy($Path, $backupPath, $false)
    }
    return [pscustomobject]@{
        Path = $Path
        Existed = $existed
        BackupPath = $backupPath
    }
}

function Restore-RollbackFileSnapshot {
    param(
        [Parameter(Mandatory = $true)] [object]$Snapshot
    )

    if ($Snapshot.Existed) {
        Require-RegularFile $Snapshot.BackupPath
        Write-AtomicFile -Source $Snapshot.BackupPath -Destination $Snapshot.Path
        return
    }
    if (Test-Path -LiteralPath $Snapshot.Path) {
        if (-not (Test-RegularFile $Snapshot.Path)) {
            Fail "rollback target is not a removable regular file: $($Snapshot.Path)"
        }
        Remove-Item -LiteralPath $Snapshot.Path -Force
    }
}

function Remove-OwnedDirectory([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    $item = Get-Item -LiteralPath $Path -Force
    if (-not $item.PSIsContainer -or (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
        Fail "refusing to remove a non-owned directory: $Path"
    }
    Remove-Item -LiteralPath $Path -Recurse -Force
}

function Invoke-ClientServiceCommand {
    param(
        [Parameter(Mandatory = $true)] [string]$Launcher,
        [Parameter(Mandatory = $true)] [string[]]$Arguments,
        [Parameter(Mandatory = $true)] [string]$Description
    )

    Require-ExecutableFile $Launcher
    & $Launcher @Arguments
    if ($LASTEXITCODE -ne 0) {
        Fail "$Description exited with $LASTEXITCODE"
    }
}

function Test-ServiceMayHoldStableFiles([object]$Service) {
    if ($null -eq $Service) {
        return $false
    }
    return $Service.Status.ToString() -ne 'Stopped'
}

function Wait-ForManagedLauncherUnlock {
    param(
        [Parameter(Mandatory = $true)] [string]$Path
    )

    Require-RegularFile $Path
    $timeout = [TimeSpan]::FromSeconds(15)
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    $lastError = $null
    do {
        try {
            $handle = [IO.File]::Open(
                $Path,
                [IO.FileMode]::Open,
                [IO.FileAccess]::ReadWrite,
                [IO.FileShare]::None
            )
            try {
                return
            }
            finally {
                $handle.Dispose()
            }
        }
        catch [IO.IOException] {
            $lastError = $_.Exception
        }

        if ($stopwatch.Elapsed -ge $timeout) {
            break
        }
        Start-Sleep -Milliseconds 100
    } while ($true)

    Fail "managed launcher remains locked after service stop: $Path ($lastError)"
}

function Get-ClientServiceIfPresent {
    try {
        $service = Get-Service -Name 'rqbit-tunnel-client' -ErrorAction Stop
        return $service
    }
    catch {
        if (
            $_.FullyQualifiedErrorId -like 'NoServiceFoundForGivenName,*' -or
            $_.CategoryInfo.Category -eq [System.Management.Automation.ErrorCategory]::ObjectNotFound
        ) {
            return $null
        }
        throw
    }
}
function Remove-ClientServiceAndVerifyAbsence {
    $service = Get-ClientServiceIfPresent
    if ($null -eq $service) {
        return
    }

    $scExe = Join-Path ([Environment]::SystemDirectory) 'sc.exe'
    Require-ExecutableFile $scExe
    & $scExe delete 'rqbit-tunnel-client'
    if ($LASTEXITCODE -ne 0) {
        Fail "client service removal exited with $LASTEXITCODE"
    }

    $deadline = [DateTime]::UtcNow.AddSeconds(10)
    do {
        if ($null -eq (Get-ClientServiceIfPresent)) {
            return
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)

    if ($null -eq (Get-ClientServiceIfPresent)) {
        return
    }
    Fail 'client service remains registered after removal request'
}




function Invoke-RollbackStep {
    param(
        [Parameter(Mandatory = $true)] [string]$Description,
        [Parameter(Mandatory = $true)] [scriptblock]$Action
    )

    try {
        $null = & $Action
        return [pscustomobject]@{
            Description = $Description
            Succeeded = $true
            Error = $null
        }
    }
    catch {
        return [pscustomobject]@{
            Description = $Description
            Succeeded = $false
            Error = $_.Exception.Message
        }
    }
}



if (-not [IO.Path]::IsPathRooted($InstallRoot)) {
    Fail "install root must be absolute: $InstallRoot"
}

$versionPath = Join-Path $scriptDirectory 'release-version.txt'
Require-RegularFile $versionPath
$releaseVersion = [IO.File]::ReadAllText($versionPath) -replace '\r?\n$', ''
if ($releaseVersion -notmatch '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$') {
    Fail 'release-version.txt must contain one canonical semantic version'
}

$payloadSource = Join-Path $scriptDirectory 'rqbit-tunnel.exe'
$updaterSource = Join-Path $scriptDirectory 'rqbit-tunnel-updater.exe'
$traySource = Join-Path $scriptDirectory 'rqbit-tunnel-tray.exe'
$launcherSource = Join-Path $scriptDirectory 'launcher.exe'
$clientRunSource = Join-Path $scriptDirectory 'client-run.ps1'
Require-ExecutableFile $payloadSource
Require-ExecutableFile $updaterSource
Require-ExecutableFile $traySource
Require-ExecutableFile $launcherSource
Require-RegularFile $clientRunSource

Ensure-Directory $InstallRoot
$releasesDirectory = Join-Path $InstallRoot 'releases'
Ensure-Directory $releasesDirectory
$releaseDirectory = Join-Path $releasesDirectory $releaseVersion
if (Test-Path -LiteralPath $releaseDirectory) {
    Fail "immutable release already exists: $releaseDirectory"
}

$stageDirectory = Join-Path $InstallRoot ".release.$releaseVersion.$([Guid]::NewGuid().ToString('N'))"
$rollbackDirectory = Join-Path $InstallRoot ".rollback.$([Guid]::NewGuid().ToString('N'))"
$stableLauncher = Join-Path $InstallRoot 'launcher.exe'
$stableClientRun = Join-Path $InstallRoot 'client-run.ps1'
$activePath = Join-Path $InstallRoot 'active.json'
$newImmutableReleaseCreated = $false
$activationSucceeded = $false
$activationError = $null
$launcherSnapshot = $null
$clientRunSnapshot = $null
$activeSnapshot = $null
$serviceWasRunningOrPending = $false
$serviceExistedBeforeInstall = $false
$rollbackSnapshotsReady = $false
$replacementServiceStartAttempted = $false
$previousServiceStopAttempted = $false
$serviceInstallAttempted = $false
$replacementServiceStoppedOrAbsent = $false
$activePointerSwitched = $false
$stableLauncherSwitched = $false
$stableClientRunSwitched = $false
$activePointerWriteAttempted = $false

$activePointerRestoreSucceeded = $false
$rollbackOutcomes = [System.Collections.Generic.List[object]]::new()


try {
    try {
        $payloadDirectory = Join-Path $stageDirectory 'payload'
        New-Item -ItemType Directory -Path $payloadDirectory -Force | Out-Null
        [IO.File]::Copy($payloadSource, (Join-Path $payloadDirectory 'rqbit-tunnel.exe'), $false)
        [IO.File]::Copy($updaterSource, (Join-Path $payloadDirectory 'rqbit-tunnel-updater.exe'), $false)
        [IO.File]::Copy($traySource, (Join-Path $payloadDirectory 'rqbit-tunnel-tray.exe'), $false)
        Move-Item -LiteralPath $stageDirectory -Destination $releaseDirectory -ErrorAction Stop
        $newImmutableReleaseCreated = $true
    }
    finally {
        Remove-OwnedDirectory $stageDirectory
    }

    $existingService = Get-ClientServiceIfPresent
    if (-not $SkipService) {
        $serviceExistedBeforeInstall = $null -ne $existingService
        $serviceWasRunningOrPending = Test-ServiceMayHoldStableFiles $existingService
        $replacementServiceStoppedOrAbsent = (
            $null -eq $existingService -or
            $existingService.Status.ToString() -eq 'Stopped'
        )
    }
    elseif ($null -eq $existingService -or $existingService.Status.ToString() -eq 'Stopped') {
        $replacementServiceStoppedOrAbsent = $true
    }
    else {
        Fail "--SkipService cannot replace stable files while client service is $($existingService.Status)"
    }

    New-Item -ItemType Directory -Path $rollbackDirectory -ErrorAction Stop | Out-Null
    $launcherSnapshot = New-RollbackFileSnapshot -Path $stableLauncher -RollbackDirectory $rollbackDirectory -Name 'launcher.exe'
    $clientRunSnapshot = New-RollbackFileSnapshot -Path $stableClientRun -RollbackDirectory $rollbackDirectory -Name 'client-run.ps1'
    $activeSnapshot = New-RollbackFileSnapshot -Path $activePath -RollbackDirectory $rollbackDirectory -Name 'active.json'
    $rollbackSnapshotsReady = $true


    if ($serviceWasRunningOrPending) {
        $previousServiceStopAttempted = $true
        Invoke-ClientServiceCommand -Launcher $stableLauncher -Arguments @('client', 'service', 'stop') -Description 'client service stop'
        $stoppedService = Get-ClientServiceIfPresent
        if ($null -ne $stoppedService -and $stoppedService.Status.ToString() -ne 'Stopped') {
            Fail "client service remains $($stoppedService.Status) after stop request"
        }
        $replacementServiceStoppedOrAbsent = $true
    }

    if ($launcherSnapshot.Existed) {
        Wait-ForManagedLauncherUnlock -Path $stableLauncher
    }

    Write-AtomicFile -Source $launcherSource -Destination $stableLauncher
    $stableLauncherSwitched = $true

    Write-AtomicFile -Source $clientRunSource -Destination $stableClientRun
    $stableClientRunSwitched = $true

    $active = [ordered]@{
        version = $releaseVersion
        payload_dir = "releases/$releaseVersion/payload"
        launcher_abi = $launcherAbi
    } | ConvertTo-Json -Compress
    $activePointerWriteAttempted = $true

    Write-AtomicTextFile -Content $active -Destination $activePath
    $activePointerSwitched = $true


    if (-not $SkipService) {
        $serviceInstallAttempted = $true
        Invoke-ClientServiceCommand -Launcher $stableLauncher -Arguments @('client', 'service', 'install') -Description 'client service installation'
    }
    if ($serviceWasRunningOrPending) {
        $replacementServiceStartAttempted = $true
        $replacementServiceStoppedOrAbsent = $false

        Invoke-ClientServiceCommand -Launcher $stableLauncher -Arguments @('client', 'service', 'start') -Description 'client service start'
    }
    $activationSucceeded = $true
}
catch {
    $activationError = $_
    $allOldSnapshotsRestored = $false
    $priorServiceRestartReady = $false
    $launcherRestoreSucceeded = $false
    $clientRunRestoreSucceeded = $false
    $activePointerRestoreSucceeded = $false
    $serviceCleanupVerifiedAbsent = $true
    $activePointerRestoreRequired = $activePointerWriteAttempted -or $activePointerSwitched

    $stableFilesUntouched = (
        -not $stableLauncherSwitched -and
        -not $stableClientRunSwitched -and
        -not $activePointerWriteAttempted
    )
    if (
        $serviceWasRunningOrPending -and
        $previousServiceStopAttempted -and
        $stableFilesUntouched
    ) {
        $initialStopRecoveryOutcome = Invoke-RollbackStep -Description 'initial client service stop recovery' -Action {
            Invoke-ClientServiceCommand -Launcher $stableLauncher -Arguments @('client', 'service', 'start') -Description 'previous client service start'
        }
        $null = $rollbackOutcomes.Add($initialStopRecoveryOutcome)
    }

    if ($replacementServiceStartAttempted) {
        $replacementStopOutcome = Invoke-RollbackStep -Description 'replacement client service stop request' -Action {
            Invoke-ClientServiceCommand -Launcher $stableLauncher -Arguments @('client', 'service', 'stop') -Description 'replacement client service stop'
        }
        $null = $rollbackOutcomes.Add($replacementStopOutcome)

        $replacementStateOutcome = Invoke-RollbackStep -Description 'replacement client service stop verification' -Action {
            $replacementService = Get-ClientServiceIfPresent
            if ($null -ne $replacementService -and $replacementService.Status.ToString() -ne 'Stopped') {
                Fail "replacement client service remains $($replacementService.Status) after stop request"
            }
        }
        $null = $rollbackOutcomes.Add($replacementStateOutcome)
        $replacementServiceStoppedOrAbsent = $replacementStateOutcome.Succeeded
    }

    if ($serviceInstallAttempted -and (-not $serviceExistedBeforeInstall)) {
        $newServiceRemovalOutcome = Invoke-RollbackStep -Description 'new client service removal and absence verification' -Action {
            Remove-ClientServiceAndVerifyAbsence
        }
        $null = $rollbackOutcomes.Add($newServiceRemovalOutcome)
        $serviceCleanupVerifiedAbsent = $newServiceRemovalOutcome.Succeeded
        $replacementServiceStoppedOrAbsent = $newServiceRemovalOutcome.Succeeded
    }

    if ($serviceCleanupVerifiedAbsent -and $replacementServiceStoppedOrAbsent -and $rollbackSnapshotsReady) {
        $launcherRestoreSucceeded = -not $stableLauncherSwitched
        if ($stableLauncherSwitched) {
            $launcherRestoreOutcome = Invoke-RollbackStep -Description 'launcher restore' -Action {
                Wait-ForManagedLauncherUnlock -Path $stableLauncher
                Restore-RollbackFileSnapshot $launcherSnapshot
            }
            $null = $rollbackOutcomes.Add($launcherRestoreOutcome)
            $launcherRestoreSucceeded = $launcherRestoreOutcome.Succeeded
        }

        $clientRunRestoreSucceeded = -not $stableClientRunSwitched
        if ($stableClientRunSwitched) {
            $clientRunRestoreOutcome = Invoke-RollbackStep -Description 'client wrapper restore' -Action {
                Restore-RollbackFileSnapshot $clientRunSnapshot
            }
            $null = $rollbackOutcomes.Add($clientRunRestoreOutcome)
            $clientRunRestoreSucceeded = $clientRunRestoreOutcome.Succeeded
        }

        $activePointerRestoreSucceeded = -not $activePointerRestoreRequired
        if ($activePointerRestoreRequired) {
            $activeRestoreOutcome = Invoke-RollbackStep -Description 'active pointer restore' -Action {
                Restore-RollbackFileSnapshot $activeSnapshot
            }
            $null = $rollbackOutcomes.Add($activeRestoreOutcome)
            $activePointerRestoreSucceeded = $activeRestoreOutcome.Succeeded
        }

        $allOldSnapshotsRestored = (
            $launcherRestoreSucceeded -and
            $clientRunRestoreSucceeded -and
            $activePointerRestoreSucceeded
        )
        $priorServiceRestartReady = (
            $serviceCleanupVerifiedAbsent -and
            $replacementServiceStoppedOrAbsent -and
            $launcherRestoreSucceeded -and
            $activePointerRestoreSucceeded
        )
    }

    if ($serviceWasRunningOrPending -and $priorServiceRestartReady) {
        $previousServiceRestartOutcome = Invoke-RollbackStep -Description 'previous service restart' -Action {
            Invoke-ClientServiceCommand -Launcher $stableLauncher -Arguments @('client', 'service', 'start') -Description 'previous client service start'
        }
        $null = $rollbackOutcomes.Add($previousServiceRestartOutcome)
    }

    $newReleaseIsProvablyInactive = (
        $serviceCleanupVerifiedAbsent -and
        (-not $activePointerRestoreRequired)
    )
    if ($activePointerRestoreRequired) {
        $newReleaseIsProvablyInactive = (
            $serviceCleanupVerifiedAbsent -and
            $activePointerRestoreSucceeded -and
            $replacementServiceStoppedOrAbsent
        )
    }
    if ($newImmutableReleaseCreated -and $newReleaseIsProvablyInactive) {
        $newReleaseRemovalOutcome = Invoke-RollbackStep -Description 'new immutable release removal' -Action {
            Remove-OwnedDirectory $releaseDirectory
        }
        $null = $rollbackOutcomes.Add($newReleaseRemovalOutcome)
    }
}
finally {
    if ($activationSucceeded) {
        try {
            Remove-OwnedDirectory $rollbackDirectory
        }
        catch {
            Write-Warning "rollback directory cleanup after successful activation failed: $($_.Exception.Message)"
        }
    }
    elseif ($null -ne $activationError) {
        $rollbackFailuresBeforeCleanup = @($rollbackOutcomes | Where-Object { -not $_.Succeeded })
        if ($rollbackFailuresBeforeCleanup.Count -eq 0) {
            $rollbackDirectoryCleanupOutcome = Invoke-RollbackStep -Description 'rollback directory cleanup' -Action {
                Remove-OwnedDirectory $rollbackDirectory
            }
            $null = $rollbackOutcomes.Add($rollbackDirectoryCleanupOutcome)
        }
    }
}

if ($null -ne $activationError) {
    $rollbackFailureDetails = @(
        $rollbackOutcomes |
            Where-Object { -not $_.Succeeded } |
            ForEach-Object { "$($_.Description): $($_.Error)" }
    )
    if ($rollbackFailureDetails.Count -gt 0) {
        throw "rqbit-tunnel client bootstrap: activation failed: $($activationError.Exception.Message)`nRollback safety or recovery failure: $($rollbackFailureDetails -join '; ')"
    }
    throw $activationError
}

Write-Host "Installed managed client release $releaseVersion at $InstallRoot"
