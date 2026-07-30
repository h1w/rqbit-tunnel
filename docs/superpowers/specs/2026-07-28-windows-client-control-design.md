# rqbit tunnel: Windows client control console design

## Status

Approved architecture. This specification narrows and supersedes the Windows launcher behavior described in `2026-07-27-tunnel-harness-design.md`: the interactive Windows client control menu uses one elevation boundary per launch, not one boundary per action.

## Problem

The extracted Windows bundle exposes `client-run.bat`, which starts `client-run.ps1`. The current script invokes every protected action through a separate `Start-Process -Verb RunAs` child. That produces two user-visible failures:

- each action that touches protected client configuration or the Service Control Manager asks for UAC again;
- interactive output from a child action, especially the client TUI and configuration display, is not rendered in the menu console that launched the action.

The managed service and its protected files are correct Windows privilege boundaries. The flaw is the control-console process boundary, not the service architecture.

## Decision

`client-run.bat` opens one elevated Windows control console for each menu launch. The user accepts UAC once when the console starts. The elevated console owns the full interactive menu and runs every menu action directly, so all output and TUI input remain visible in that console.

Closing the console drops its elevated token. A later invocation requires a new UAC consent. The design does not install a permanent privileged control agent, grant the ordinary user additional privileges, or attempt to cache UAC consent.

## Goals

- One UAC consent at most for a successful `client-run.bat` menu launch.
- A single visible elevated console owns menu prompts, command output, TUI rendering, and TUI keyboard input.
- An empty enrollment-path input imports the only regular `*.rqbt` file beside the extracted wrapper when exactly one candidate exists.
- Service status and tray status remain associated with the original non-elevated desktop user after elevation.
- Paths containing spaces, quotes, Unicode, and PowerShell metacharacters cannot change the elevated command being executed.
- Existing install, service, update, tray, and bundle-validation behavior remains unchanged apart from the launcher control flow.

## Non-goals

- Never asking for UAC after installation.
- A background Windows control service, a scheduled privileged task, or an IPC endpoint that accepts arbitrary user commands.
- Changing service privileges, service account identity, bundle cryptography, or the client runtime protocol.
- Guessing among multiple enrollment bundles.
- Supporting unattended menu automation through the interactive wrapper; non-interactive `launcher.exe client ...` commands remain the automation interface.

## Process model

```text
ordinary client-run.bat / client-run.ps1
  │
  ├─ capture desktop-user SID
  ├─ encode fixed self-relaunch payload
  ├─ one Start-Process -Verb RunAs request
  │
  └─ elevated client-run.ps1 control console
       ├─ restore original desktop-user SID
       ├─ show the interactive menu
       ├─ run launcher/TUI commands directly in this console
       └─ exit when the user selects quit
```

Windows cannot upgrade the token of the already-running non-elevated PowerShell process. Therefore the initial bootstrap console and the elevated control console are distinct processes. The bootstrap process waits for the elevated child, forwards its exit code, and does not invoke an action-specific UAC child. The elevated child is the only console the user uses for menu interaction.

The batch wrapper must not leave an unnecessary blank parent console after a successful elevated session. It may keep a failure message visible when UAC is denied or the elevated session exits unsuccessfully.

## Launcher contract

`client-run.ps1` gains internal parameters equivalent to:

```text
-ElevatedMenu
-StatusOwnerSid <original desktop user SID>
```

They are an internal self-relaunch protocol, not a public service-management API.

### Initial non-elevated launch

1. Resolve the script path and current desktop SID from the initial process token.
2. Build a JSON payload containing only the resolved script path, the fixed internal menu switch, and the original desktop SID.
3. Encode that payload in a PowerShell `-EncodedCommand` invocation for the current PowerShell host.
4. Start the host exactly once with `-Verb RunAs` and wait for it.
5. Propagate the child exit code to `client-run.bat`.

The initial process never appends untrusted text to a PowerShell command string. It must reject a missing SID, an unresolvable script path, or an unavailable PowerShell host before attempting elevation.

### Elevated child launch

The encoded payload decodes to a fixed script invocation that passes the resolved script path, `-ElevatedMenu`, and the captured SID as typed argument values. The child must verify that it actually has an administrator token before showing a protected menu. A direct non-administrator invocation with `-ElevatedMenu` fails clearly; it must not recurse into another elevation attempt.

The elevated child sets the existing status-owner environment/argument value from the captured SID before it reads service status or starts a tray-related command. It must never derive that owner from the elevated administrator token, which may belong to a different account.

### Menu actions

The elevated menu invokes the stable managed `launcher.exe` directly for every action. It does not call the old per-action `-Protected` elevation path. That includes:

- `client tui`;
- `client config show` and `client config set`;
- `client import`;
- `client service install`, `start`, `stop`, `restart`, `status`, and autostart actions;
- update actions initiated from the menu.

Direct execution preserves standard input, standard output, and standard error, so Ratatui renders in the menu window and configuration/status messages remain readable. The menu redraws only after a foreground action returns.

Read-only status still uses the existing owner-aware behavior. No network management port or new privilege-bearing local IPC interface is introduced.

## Enrollment bundle defaulting

The import action has an explicit candidate resolver rooted at the directory containing the launched `client-run.ps1` / `client-run.bat` bundle.

1. Enumerate immediate `*.rqbt` entries only; do not recurse.
2. Accept only ordinary regular files. Reparse points, directories, and inaccessible entries are not candidates.
3. If the operator supplies a non-empty path, use that path exactly and preserve existing bundle validation.
4. If the operator presses Enter and exactly one candidate exists, print `Using enrollment bundle: <path>` and import it.
5. If Enter is pressed with no candidates, report that no `.rqbt` bundle was found beside the client wrapper and request an explicit path.
6. If Enter is pressed with multiple candidates, list their filenames and request an explicit path. The script must not sort-select or otherwise guess.

This shortcut is intentionally limited to the extracted release folder. An installed `client-run.ps1` under `Program Files` only auto-selects a bundle if an operator deliberately placed exactly one regular `.rqbt` there; it does not scan Downloads, the desktop, or arbitrary drives.

## Error handling and safety invariants

- UAC denial or elevation failure ends the bootstrap with a non-zero exit code and an actionable message. It never silently falls back to a partially privileged menu.
- A failed foreground command remains visible in the elevated console, returns its real exit code/message, and then returns control to the menu without recursive UAC prompts.
- The original status-owner SID is validated as a SID string before use. No supplied path, bundle name, or menu input can alter it.
- The self-relaunch payload carries only fixed fields and is decoded/validated before execution. It contains no secrets and never logs bundle contents or client private keys.
- The launcher remains the stable target for SCM and tray autostart. This change does not replace a running service executable or bypass the immutable-release/update rollback design.
- The menu does not claim that a service is connected merely because the service starts; it preserves the existing `connected`, `reconnecting`, and `failed` status semantics.

## Files and boundaries

| File | Responsibility after change |
| --- | --- |
| `scripts/tunnel/client-run.bat` | Starts the PowerShell bootstrap; closes cleanly after a successful elevated session and preserves failure diagnostics. |
| `scripts/tunnel/client-run.ps1` | Owns the one-time self-elevation protocol, enrollment candidate resolver, and elevated interactive menu. |
| `scripts/tunnel/test-client-bootstrap.ps1` | Executes script self-tests and validates bootstrap packaging behavior. |
| `scripts/tunnel/README.md` | Documents one-UAC-per-menu-launch behavior and the Enter-to-import shortcut. |
| `.github/workflows/release-tunnel.yml` | Continues packaging the changed wrapper files in the Windows bundle; no release format change is required. |

No Rust production source change is required for this correction. The existing `launcher.exe`, Windows service adapter, named-pipe authorization, tray executable, and update orchestrator remain the control/data-plane boundaries.

## Verification

### PowerShell self-tests

Extend `client-run.ps1 -SelfTest` to assert all of the following without invoking UAC:

- the self-elevation argument list contains only fixed PowerShell flags and one encoded payload;
- decoded payload data preserves the resolved script path and original desktop SID;
- the decoded command invokes `-ElevatedMenu`, not an arbitrary client subcommand;
- a direct non-elevated `-ElevatedMenu` entry fails instead of recursing;
- candidate resolution returns zero, one, and multiple candidates correctly and excludes non-regular/reparse entries;
- an empty import input selects only the single-candidate case.

### Windows bootstrap and service smoke coverage

- Keep `scripts/tunnel/test-client-bootstrap.ps1` running the wrapper self-test from a staged release-like bundle.
- Run the existing disposable elevated Windows service smoke test after bootstrap validation. It continues to prove install, configuration import, service start/status, stop, and removal behavior.
- Review the packaged Windows archive to confirm that `client-run.bat`, `client-run.ps1`, and `README.md` are present as regular files.

Manual acceptance on a Windows desktop requires one run from an extracted bundle containing exactly one `.rqbt` file:

1. Double-click `client-run.bat`.
2. Accept UAC once.
3. Select import and press Enter at the path prompt.
4. Observe the selected bundle path, completed import, and visible service/TUI output in the same elevated console.
5. Exercise configuration, status, and at least one service submenu action; no second UAC prompt may appear.
6. Quit, relaunch the wrapper, and observe one new UAC prompt for the new menu session.

## Acceptance criteria

- One UAC consent opens one usable elevated control console; individual menu actions do not create additional UAC prompts.
- `show configuration`, client TUI, status, and service actions render their output in that console.
- Enter imports exactly one adjacent regular `.rqbt` candidate and never selects among zero or multiple candidates.
- The elevated console retains the non-elevated desktop user's SID for owner-scoped status/tray behavior.
- UAC denial, malformed internal payload, a direct non-admin elevated-menu request, and bundle ambiguity fail safely with actionable output.
- Existing Windows installation, SCM service lifecycle, tray ownership, signed update, and release bundle format continue to work.
