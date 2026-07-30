# Windows Client Control Console Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Windows client wrapper request UAC once per menu launch, keep all menu/TUI output in one elevated console, and import the sole adjacent enrollment bundle when the operator presses Enter.

**Architecture:** `client-run.ps1` becomes a small elevation boundary: a non-administrator bootstrap captures the desktop SID and safely self-relaunches the script once; the elevated child invokes `launcher.exe` directly for every menu action. Bundle discovery is a pure, testable resolver rooted at the wrapper directory, while the existing managed service, stable launcher, tray, signed-update, and protected IPC boundaries remain unchanged.

**Tech Stack:** Windows PowerShell 5.1-compatible scripting, `cmd.exe` batch wrapper, existing Windows SCM service smoke test, GitHub Actions Windows runner.

---

## File map

| File | Change |
| --- | --- |
| `scripts/tunnel/client-run.ps1` | Replace per-action elevation with one safe self-elevation handoff; add menu-launch helpers and enrollment candidate resolution; extend `-SelfTest`. |
| `scripts/tunnel/client-run.bat` | Close the bootstrap console after a successful elevated menu and retain diagnostics only on failure. |
| `scripts/tunnel/test-client-bootstrap.ps1` | Stage and assert the batch wrapper along with the PowerShell wrapper. |
| `.github/workflows/tunnel-harness-smoke.yml` | Assemble the batch wrapper in the release-like Windows smoke bundle. |
| `scripts/tunnel/README.md` | Tell Windows operators exactly when UAC appears and how Enter chooses a single adjacent `.rqbt` file. |

No Rust production source changes are needed. `crates/rqbit-tunnel/src/tray/agent.rs` continues launching the stable `client-run.ps1` wrapper with `-OpenDashboard`; the wrapper itself supplies the visible elevated console.

### Task 1: Write failing tests for one-time elevation control flow

**Files:**
- Modify: `scripts/tunnel/client-run.ps1:2-208`
- Test: `scripts/tunnel/test-client-bootstrap.ps1:1-85`

- [ ] **Step 1: Replace the obsolete per-command elevation self-test with menu-launch assertions.**

  In the existing `$SelfTest` block, delete assertions for `New-ElevatedClientStartProcessArguments`, `Read-ElevatedClientEncodedPayload`, and the installer payload. Add assertions for a new menu-level API that does not yet exist:

  ```powershell
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
  $captureRoot = Join-Path ([IO.Path]::GetTempPath()) "rqbit tunnel menu capture $([Guid]::NewGuid().ToString('N'))"
  $previousCapturePath = $env:RQBIT_TUNNEL_MENU_CAPTURE
  try {
      New-Item -ItemType Directory -Path $captureRoot -Force | Out-Null
      $capturePath = Join-Path $captureRoot 'capture.json'
      $captureScript = Join-Path $captureRoot 'capture.ps1'
      @'
  [CmdletBinding(PositionalBinding = $false)]
  param(
      [switch]$ElevatedMenu,
      [string]$StatusOwnerSid,
      [switch]$OpenDashboard
  )
  [pscustomobject]@{
      elevated_menu = [bool]$ElevatedMenu
      status_owner_sid = $StatusOwnerSid
      open_dashboard = [bool]$OpenDashboard
      unexpected_argument_count = @($args).Count
  } | ConvertTo-Json -Compress | Set-Content -LiteralPath $env:RQBIT_TUNNEL_MENU_CAPTURE -Encoding UTF8
'@ | Set-Content -LiteralPath $captureScript -Encoding UTF8
      $env:RQBIT_TUNNEL_MENU_CAPTURE = $capturePath

      foreach ($menuCase in @(
          [pscustomobject]@{ OpenDashboard = $false },
          [pscustomobject]@{ OpenDashboard = $true }
      )) {
          Remove-Item -LiteralPath $capturePath -Force -ErrorAction SilentlyContinue
          $menuArguments = New-ElevatedMenuStartProcessArguments `
              -ScriptPath $captureScript `
              -StatusOwnerSid $expectedStatusOwnerSid `
              -OpenDashboard:$menuCase.OpenDashboard
          if ($menuArguments.Count -ne 5 -or
              $menuArguments[0] -cne '-NoProfile' -or
              $menuArguments[1] -cne '-ExecutionPolicy' -or
              $menuArguments[2] -cne 'Bypass' -or
              $menuArguments[3] -cne '-EncodedCommand') {
              throw 'elevated menu invocation must contain only fixed PowerShell flags and one encoded payload'
          }
          $menuPayload = Read-ElevatedMenuEncodedPayload -EncodedCommand $menuArguments[4]
          if ($menuPayload.script_path -cne $captureScript -or
              $menuPayload.status_owner_sid -cne $expectedStatusOwnerSid -or
              ([bool]$menuPayload.open_dashboard -ne [bool]$menuCase.OpenDashboard)) {
              throw 'elevated menu payload did not preserve the script, desktop SID, and dashboard mode'
          }
          & $expectedElevatedHost @menuArguments
          if ($LASTEXITCODE -ne 0) {
              throw "encoded menu payload exited with $LASTEXITCODE"
          }
          $captured = Get-Content -LiteralPath $capturePath -Raw | ConvertFrom-Json
          if (-not [bool]$captured.elevated_menu -or
              $captured.status_owner_sid -cne $expectedStatusOwnerSid -or
              ([bool]$captured.open_dashboard -ne [bool]$menuCase.OpenDashboard) -or
              $captured.unexpected_argument_count -ne 0) {
              throw 'encoded menu payload did not bind the elevated-menu parameters correctly'
          }
      }
  }
  finally {
      if ($null -eq $previousCapturePath) {
          Remove-Item Env:RQBIT_TUNNEL_MENU_CAPTURE -ErrorAction SilentlyContinue
      }
      else {
          $env:RQBIT_TUNNEL_MENU_CAPTURE = $previousCapturePath
      }
      Remove-Item -LiteralPath $captureRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  ```

  Retain the existing `Get-ElevatedPowerShellHost` assertion. Change the dashboard/config action assertions so they verify the same argument arrays but reject a `Protected` property:

  ```powershell
  if ($tuiAction.PSObject.Properties.Name -contains 'Protected') {
      throw 'dashboard actions must not create an action-specific elevation boundary'
  }
  ```

- [ ] **Step 2: Run the bootstrap contract test and confirm it fails for the missing menu-level helper.**

  Run on Windows or a host with PowerShell available:

  ```powershell
  pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 `
    -Installer scripts/tunnel/install-client.ps1
  ```

  Expected: failure naming `Get-ClientMenuLaunchMode` or `New-ElevatedMenuStartProcessArguments`; the old script does not implement the approved one-time elevation contract.

- [ ] **Step 3: Commit the red test state.**

  ```bash
  git add scripts/tunnel/client-run.ps1
  git commit -m "test: define Windows single-UAC control contract"
  ```

### Task 2: Replace action-level UAC with a single safe menu relaunch

**Files:**
- Modify: `scripts/tunnel/client-run.ps1:2-404`
- Test: `scripts/tunnel/test-client-bootstrap.ps1:1-85`

- [ ] **Step 1: Add the elevation payload and launch-mode helpers before the `$SelfTest` block.**

  Delete the old `New-ElevatedClientEncodedCommand`, `New-ElevatedClientStartProcessArguments`, `Read-ElevatedClientEncodedPayload`, `New-ElevatedInstallerEncodedCommand`, `New-ElevatedInstallerStartProcessArguments`, and `Read-ElevatedInstallerEncodedPayload` functions. Replace them with this menu-scoped protocol:

  ```powershell
  function New-ElevatedMenuEncodedCommand {
      param(
          [Parameter(Mandatory = $true)] [string]$ScriptPath,
          [Parameter(Mandatory = $true)] [string]$StatusOwnerSid,
          [switch]$OpenDashboard
      )

      $payload = [pscustomobject]@{
          script_path = [string]$ScriptPath
          status_owner_sid = [string]$StatusOwnerSid
          open_dashboard = [bool]$OpenDashboard
      }
      $payloadBase64 = [Convert]::ToBase64String(
          [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $payload -Compress))
      )
      $decoder = [string]::Join([Environment]::NewLine, @(
          '$ErrorActionPreference = ''Stop''',
          '$payloadJson = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(''__RQBIT_MENU_PAYLOAD__''))',
          '$payload = $payloadJson | ConvertFrom-Json',
          'if ([string]::IsNullOrWhiteSpace([string]$payload.script_path)) { throw ''missing client control script path'' }',
          'if ([string]::IsNullOrWhiteSpace([string]$payload.status_owner_sid)) { throw ''missing desktop status owner SID'' }',
          '$scriptArguments = @{ ElevatedMenu = $true; StatusOwnerSid = [string]$payload.status_owner_sid }',
          'if ([bool]$payload.open_dashboard) { $scriptArguments.OpenDashboard = $true }',
          'try {',
          '    & ([string]$payload.script_path) @scriptArguments',
          '    if ($null -eq $LASTEXITCODE) { exit 0 }',
          '    exit $LASTEXITCODE',
          '}',
          'catch {',
          '    [Console]::Error.WriteLine($_.Exception.Message)',
          '    exit 1',
          '}'
      )).Replace('__RQBIT_MENU_PAYLOAD__', $payloadBase64)
      return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($decoder))
  }

  function New-ElevatedMenuStartProcessArguments {
      param(
          [Parameter(Mandatory = $true)] [string]$ScriptPath,
          [Parameter(Mandatory = $true)] [string]$StatusOwnerSid,
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
      param([Parameter(Mandatory = $true)] [string]$EncodedCommand)

      $decoder = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($EncodedCommand))
      $match = [regex]::Match($decoder, "FromBase64String\('(?<payload>[A-Za-z0-9+/=]+)'\)")
      if (-not $match.Success) {
          throw 'encoded menu elevation command does not contain a base64 JSON payload'
      }
      $payloadJson = [Text.Encoding]::UTF8.GetString(
          [Convert]::FromBase64String($match.Groups['payload'].Value)
      )
      return $payloadJson | ConvertFrom-Json
  }

  function Get-ClientMenuLaunchMode {
      param([bool]$Administrator, [bool]$ElevatedMenu)

      if ($ElevatedMenu -and -not $Administrator) { return 'reject' }
      if ($Administrator) { return 'run' }
      return 'elevate'
  }

  function Get-CurrentUserSid {
      $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
      if ($null -eq $sid -or [string]::IsNullOrWhiteSpace($sid.Value)) {
          throw 'could not determine the desktop status owner SID'
      }
      return $sid.Value
  }

  function ConvertTo-StatusOwnerSid {
      param([Parameter(Mandatory = $true)] [string]$Value)

      try {
          return ([Security.Principal.SecurityIdentifier]::new($Value)).Value
      }
      catch {
          throw "invalid desktop status owner SID: $Value"
      }
  }
  ```

  Before implementing the decoder catch path, add a red SelfTest assertion that a nonexistent script path produces a nonzero process exit. Reuse the temporary capture directory and status SID from the binding fixture:

  ```powershell
  $missingScriptPath = Join-Path $captureDirectory 'missing elevated control.ps1'
  $failureArguments = New-ElevatedMenuStartProcessArguments `
      -ScriptPath $missingScriptPath `
      -StatusOwnerSid $expectedStatusOwnerSid
  $failureProcess = Start-Process `
      -FilePath $actualElevatedHost `
      -ArgumentList $failureArguments `
      -Wait `
      -PassThru
  if ($failureProcess.ExitCode -eq 0) {
      throw 'encoded menu payload must fail when its target script cannot be invoked'
  }
  ```

  The current decoder fails this assertion because it calls `exit $LASTEXITCODE` after a PowerShell script-resolution failure. The `try`/`catch` in the replacement above is the minimal green change; it emits the original error message and exits `1` instead of reporting a false success.

  Keep `Get-ElevatedPowerShellHost` and `Test-Administrator`; move `Test-Administrator` above the startup branch if needed so both runtime control flow and `-SelfTest` can call it.

- [ ] **Step 2: Add internal parameters and a single startup elevation boundary.**

  Extend the script parameter block:

  ```powershell
  param(
      [switch]$SelfTest,
      [switch]$OpenDashboard,
      [switch]$ElevatedMenu,
      [string]$StatusOwnerSid
  )
  ```

  After the `$SelfTest` early exit and before selecting/installing the managed launcher, add this startup branch:

  ```powershell
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
  ```

  The child has no `-NonInteractive` flag: it must inherit a usable console for Ratatui. A direct administrator launch derives its own SID; a non-administrator launch preserves the pre-elevation SID through the encoded payload.

- [ ] **Step 3: Make installer bootstrap and all menu actions direct calls in the elevated console.**

  In the release-bundle bootstrap block, remove the `if (Test-Administrator) ... else Start-Process -Verb RunAs` split. The startup branch already guarantees elevation before this block, so invoke the installer directly:

  ```powershell
  Write-Host 'Installing the managed client release from this bundle...'
  & $installer
  if (-not $?) {
      throw 'client bootstrap failed'
  }
  ```

  Remove the `Protected` parameter from `Invoke-ClientCommand` and `Invoke-MenuCommand`. `Invoke-ClientCommand` becomes:

  ```powershell
  function Invoke-ClientCommand {
      param([Parameter(Mandatory = $true)] [string[]]$ClientArguments)

      & $bin @ClientArguments
      if ($LASTEXITCODE -ne 0) {
          throw "rqbit-tunnel command exited with $LASTEXITCODE"
      }
  }
  ```

  Remove the `Protected` property from `Get-ClientTuiMenuAction` and `Get-ClientConfigShowMenuAction`, then remove every `-Protected` and `-Protected:$action.Protected` argument from the dashboard, configuration, service, import, and status call sites. Preserve `-PassThru` chaining in the import action. `-OpenDashboard` must call the same direct `client tui` action and exit after it returns.

- [ ] **Step 4: Run the red test from Task 1 again and confirm it passes.**

  ```powershell
  pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 `
    -Installer scripts/tunnel/install-client.ps1
  ```

  Expected: `Windows client bootstrap contract passed` and exit code `0`.

- [ ] **Step 5: Commit the single-UAC refactor.**

  ```bash
  git add scripts/tunnel/client-run.ps1
  git commit -m "fix: elevate Windows client control once"
  ```

### Task 3: Add deterministic adjacent enrollment-bundle selection

**Files:**
- Modify: `scripts/tunnel/client-run.ps1:151-405`
- Test: `scripts/tunnel/test-client-bootstrap.ps1:1-85`

- [ ] **Step 1: Add failing resolver tests to the script self-test.**

  Add this isolated filesystem fixture before `exit 0` in the `$SelfTest` block. It covers zero, one, and many candidates plus regular/readable-file filtering without requiring UAC:

  ```powershell
  $candidateRoot = Join-Path ([IO.Path]::GetTempPath()) "rqbit-tunnel-bundle-candidates-$([Guid]::NewGuid().ToString('N'))"
  try {
      New-Item -ItemType Directory -Path $candidateRoot -Force | Out-Null
      if (@(Get-EnrollmentBundleCandidates -Directory $candidateRoot).Count -ne 0) {
          throw 'empty bundle directory must have no enrollment candidates'
      }

      $singleBundle = Join-Path $candidateRoot 'alice bundle.rqbt'
      [IO.File]::WriteAllText($singleBundle, '{}', [Text.UTF8Encoding]::new($false))
      $singleCandidates = @(Get-EnrollmentBundleCandidates -Directory $candidateRoot)
      if ($singleCandidates.Count -ne 1 -or $singleCandidates[0] -cne $singleBundle) {
          throw 'single regular enrollment bundle was not discovered exactly'
      }
      if ((Resolve-EnrollmentBundlePath -EnteredPath '' -Candidates $singleCandidates) -cne $singleBundle) {
          throw 'empty input must select the sole adjacent enrollment bundle'
      }
      if ((Resolve-EnrollmentBundlePath -EnteredPath 'C:\explicit path\bob.rqbt' -Candidates $singleCandidates) -cne 'C:\explicit path\bob.rqbt') {
          throw 'explicit enrollment path must take precedence over the adjacent candidate'
      }

      [IO.File]::WriteAllText((Join-Path $candidateRoot 'bob.rqbt'), '{}', [Text.UTF8Encoding]::new($false))
      $multipleCandidates = @(Get-EnrollmentBundleCandidates -Directory $candidateRoot)
      if ($multipleCandidates.Count -ne 2 -or $null -ne (Resolve-EnrollmentBundlePath -EnteredPath '' -Candidates $multipleCandidates)) {
          throw 'empty input must not choose among multiple enrollment bundles'
      }

      $directoryCandidate = [pscustomobject]@{
          PSIsContainer = $true
          Attributes = [IO.FileAttributes]::Directory
          FullName = $singleBundle
      }
      $reparseCandidate = [pscustomobject]@{
          PSIsContainer = $false
          Attributes = [IO.FileAttributes]::ReparsePoint
          FullName = $singleBundle
      }
      $missingCandidate = [pscustomobject]@{
          PSIsContainer = $false
          Attributes = [IO.FileAttributes]::Normal
          FullName = (Join-Path $candidateRoot 'missing.rqbt')
      }
      if ((Test-RegularEnrollmentBundleCandidate -Item $directoryCandidate) -or
          (Test-RegularEnrollmentBundleCandidate -Item $reparseCandidate) -or
          (Test-RegularEnrollmentBundleCandidate -Item $missingCandidate)) {
          throw 'directories, reparse points, and unreadable files must not be enrollment candidates'
      }
  }
  finally {
      Remove-Item -LiteralPath $candidateRoot -Recurse -Force -ErrorAction SilentlyContinue
  }
  ```

- [ ] **Step 2: Run the bootstrap contract test and confirm the new resolver tests fail.**

  ```powershell
  pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 `
    -Installer scripts/tunnel/install-client.ps1
  ```

  Expected: failure naming `Get-EnrollmentBundleCandidates`, `Resolve-EnrollmentBundlePath`, or `Test-RegularEnrollmentBundleCandidate`.

- [ ] **Step 3: Implement the candidate helpers and wire them into menu action 2.**

  Add these helpers before the menu loop:

  ```powershell
  function Test-RegularEnrollmentBundleCandidate {
      param([Parameter(Mandatory = $true)] [object]$Item)

      if ([bool]$Item.PSIsContainer -or
          (($Item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0)) {
          return $false
      }
      try {
          $stream = [IO.File]::Open(
              [string]$Item.FullName,
              [IO.FileMode]::Open,
              [IO.FileAccess]::Read,
              [IO.FileShare]::ReadWrite
          )
          try {
              return $true
          }
          finally {
              $stream.Dispose()
          }
      }
      catch {
          return $false
      }
  }

  function Get-EnrollmentBundleCandidates {
      param([Parameter(Mandatory = $true)] [string]$Directory)

      if (-not (Test-Path -LiteralPath $Directory -PathType Container)) {
          return @()
      }
      return @(
          Get-ChildItem -LiteralPath $Directory -Filter '*.rqbt' -Force -ErrorAction Stop |
              Where-Object { Test-RegularEnrollmentBundleCandidate -Item $_ } |
              ForEach-Object { [string]$_.FullName }
      )
  }

  function Resolve-EnrollmentBundlePath {
      param(
          [AllowEmptyString()] [string]$EnteredPath,
          [Parameter(Mandatory = $true)] [string[]]$Candidates
      )

      if (-not [string]::IsNullOrWhiteSpace($EnteredPath)) {
          return $EnteredPath
      }
      if ($Candidates.Count -eq 1) {
          return $Candidates[0]
      }
      return $null
  }

  function Read-EnrollmentBundlePath {
      param([Parameter(Mandatory = $true)] [string]$Directory)

      $candidates = @(Get-EnrollmentBundleCandidates -Directory $Directory)
      if ($candidates.Count -eq 1) {
          $fileName = Split-Path -Leaf $candidates[0]
          $enteredPath = Read-Host "Enrollment bundle path (blank uses $fileName)"
      }
      else {
          if ($candidates.Count -eq 0) {
              Write-Host 'No .rqbt enrollment bundle was found beside client-run.ps1; enter an explicit path.' -ForegroundColor Yellow
          }
          else {
              Write-Host 'Multiple .rqbt enrollment bundles were found; enter an explicit path:' -ForegroundColor Yellow
              foreach ($candidate in $candidates) {
                  Write-Host "  $(Split-Path -Leaf $candidate)"
              }
          }
          $enteredPath = Read-Host 'Enrollment bundle path'
      }

      $bundle = Resolve-EnrollmentBundlePath -EnteredPath $enteredPath -Candidates $candidates
      if ([string]::IsNullOrWhiteSpace($bundle)) {
          Write-Host 'Enrollment bundle was not selected' -ForegroundColor Yellow
          return $null
      }
      if ([string]::IsNullOrWhiteSpace($enteredPath)) {
          Write-Host "Using enrollment bundle: $bundle"
      }
      return $bundle
  }
  ```

  Replace menu case `"2"` with a null-safe call that retains the existing import → service install → enable autostart → start sequence:

  ```powershell
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
  ```

- [ ] **Step 4: Run the bootstrap contract test and confirm the resolver cases pass.**

  ```powershell
  pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 `
    -Installer scripts/tunnel/install-client.ps1
  ```

  Expected: `Windows client bootstrap contract passed` and exit code `0`.

- [ ] **Step 5: Commit deterministic bundle selection.**

  ```bash
  git add scripts/tunnel/client-run.ps1
  git commit -m "feat: default Windows enrollment bundle"
  ```

### Task 4: Package the wrapper faithfully and remove the empty bootstrap console

**Files:**
- Modify: `scripts/tunnel/client-run.bat:1-9`
- Modify: `scripts/tunnel/test-client-bootstrap.ps1:13-47`
- Modify: `.github/workflows/tunnel-harness-smoke.yml:120-135`

- [ ] **Step 1: Extend the staged-bundle bootstrap test to require the batch wrapper.**

  Near the existing PowerShell wrapper copy, add:

  ```powershell
  $clientRunBatchSource = Join-Path (Split-Path -Parent $Installer) 'client-run.bat'
  if (-not (Test-Path -LiteralPath $clientRunBatchSource -PathType Leaf)) {
      throw "batch client control wrapper is absent: $clientRunBatchSource"
  }
  $clientRunBatch = Join-Path $bundle 'client-run.bat'
  Copy-Item -LiteralPath $clientRunBatchSource -Destination $clientRunBatch
  $clientRunBatchItem = Get-Item -LiteralPath $clientRunBatch -Force
  if ($clientRunBatchItem.PSIsContainer -or
      ($clientRunBatchItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
      throw "batch client control wrapper is not a regular staged file: $clientRunBatch"
  }
  ```

  The batch wrapper remains in the extracted release bundle; `install-client.ps1` intentionally installs only `client-run.ps1` as the stable managed wrapper. Do not add the batch file to the managed install-root assertion.

- [ ] **Step 2: Update the Windows smoke bundle assembly.**

  Add this exact copy beside the `client-run.ps1` copy in `tunnel-harness-smoke.yml`:

  ```powershell
  Copy-Item scripts/tunnel/client-run.bat "$bundle/client-run.bat"
  ```

  The workflow's existing call to `smoke-windows-service.ps1` must continue to use the resulting `$bundle.zip`; Task 5 validates the complete job on Windows.

- [ ] **Step 3: Make the batch wrapper pause only after failure.**

  Replace the unconditional tail of `client-run.bat` with:

  ```bat
  powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0client-run.ps1" %*
  set "EXITCODE=%ERRORLEVEL%"
  if not "%EXITCODE%"=="0" (
    echo.
    echo rqbit tunnel client control failed with exit code %EXITCODE%.
    pause
  )
  exit /b %EXITCODE%
  ```

  Keep `@echo off` and the wrapper comment. A successful parent bootstrap waits for the elevated child, receives exit code `0`, and closes instead of leaving a second blank console behind. A declined UAC prompt or failed elevated menu leaves diagnostics visible.

- [ ] **Step 4: Run the Windows bootstrap contract test after staging changes.**

  ```powershell
  pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 `
    -Installer scripts/tunnel/install-client.ps1
  ```

  Expected: `Windows client bootstrap contract passed` and exit code `0`.

- [ ] **Step 5: Commit wrapper packaging and console behavior.**

  ```bash
  git add scripts/tunnel/client-run.bat \
    scripts/tunnel/test-client-bootstrap.ps1 \
    .github/workflows/tunnel-harness-smoke.yml
  git commit -m "fix: streamline Windows client control wrapper"
  ```

### Task 5: Document the exact Windows interaction and verify end to end

**Files:**
- Modify: `scripts/tunnel/README.md:176-203`
- Test: `scripts/tunnel/test-client-bootstrap.ps1`
- Test: `scripts/tunnel/smoke-windows-service.ps1`
- Modify: `.github/workflows/tunnel-harness-smoke.yml:120-142`

- [ ] **Step 1: Update the Windows usage section with the menu’s privilege and bundle rules.**

  After the existing paragraph about `client-run.ps1` / `client-run.bat`, add this operator-facing text:

  ```markdown
  Double-click `client-run.bat` as the desktop user. It opens one elevated
  control console after one UAC confirmation; all menu actions, configuration
  output, and the client TUI run in that console without additional UAC prompts.
  Closing it ends that elevated session, so the next launch asks once again.

  When importing an enrollment bundle, press Enter at the path prompt if the
  extracted bundle folder contains exactly one readable, non-reparse regular
  `*.rqbt` file. The menu names and imports that file automatically, then
  installs the client service definition, enables its autostart, and starts it.
  With no bundle or multiple bundles, it prints the discovered state and
  requires an explicit path; it never guesses.
  ```

- [ ] **Step 2: Run local PowerShell contract coverage.**

  ```powershell
  pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 `
    -Installer scripts/tunnel/install-client.ps1
  ```

  Expected: `Windows client bootstrap contract passed` and exit code `0`.

- [ ] **Step 3: Run the existing Windows service smoke job on the feature branch.**

  ```bash
  gh workflow run tunnel-harness-smoke.yml --ref feature/tunnel-harness
  gh run watch --exit-status
  ```

  Expected: the `windows-service` job completes successfully, including `Assemble and test Windows bundle`; the `linux-systemd` job remains green because this change does not alter Linux assets.

  The workflow must explicitly exit with each child `pwsh` command’s
  `$LASTEXITCODE`; PowerShell otherwise permits a later successful command to
  mask a failed bootstrap contract.

- [ ] **Step 4: Perform the desktop acceptance scenario from the specification.**

  On Windows, put exactly one `alice.rqbt` next to `client-run.bat` in an extracted release bundle, then:

  ```text
  1. Double-click client-run.bat.
  2. Accept the one UAC request.
  3. Select 2) import enrollment bundle and press Enter at the path prompt.
  4. Select 3) show configuration, 6) show service status, and 1) open client dashboard.
  5. Select a service action, then quit and relaunch the wrapper.
  ```

  Expected: the chosen path is printed; all command and Ratatui output appears in the one elevated console; actions create no additional UAC prompts; the next wrapper launch produces one new UAC request.

- [ ] **Step 5: Commit documentation.**

  ```bash
  git add scripts/tunnel/README.md
  git commit -m "docs: explain Windows client control elevation"
  ```

## Final verification checklist

- [ ] `pwsh -NoProfile -File scripts/tunnel/test-client-bootstrap.ps1 -Installer scripts/tunnel/install-client.ps1` exits `0`.
- [ ] GitHub Actions `tunnel-harness-smoke.yml` is green, including the Windows service smoke job.
- [ ] Manual desktop acceptance demonstrates exactly one UAC request per wrapper launch, visible action output, and correct Enter-to-import behavior.
- [ ] The final Windows release archive still contains regular `client-run.ps1`, `client-run.bat`, `install-client.ps1`, `README.md`, and all managed executables.
