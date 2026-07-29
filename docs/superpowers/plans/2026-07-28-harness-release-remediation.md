# Harness Release Remediation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make signed tunnel updates immutable across discovery/download, stable-only, usable over slow links, and make Windows bootstrap/upgrade safe for running services and paths with spaces.

**Architecture:** GitHub discovery produces one selected release—its canonical stable tag version and already-validated asset URL set—which travels with `ReleaseDiscovery` through manifest verification and archive download. The updater rejects a signed manifest whose version differs from the selected GitHub tag. Windows bootstrap stages the immutable release before stopping an existing configured service, then atomically switches stable files and restarts the service only when it was running; its elevation handoff uses encoded JSON instead of a whitespace-sensitive `-File` argument.

**Tech Stack:** Rust 2024, Tokio, Reqwest 0.12, SemVer, PowerShell 5.1+, GitHub Actions.

---

### Task 1: Bind all update assets to one selected GitHub release

**Files:**
- Modify: `crates/rqbit-tunnel/src/update/github.rs`
- Modify: `crates/rqbit-tunnel/src/update/orchestrator.rs`
- Modify: `crates/rqbit-tunnel/src/update/manifest.rs`
- Test: `crates/rqbit-tunnel/src/update/github.rs`
- Test: `crates/rqbit-tunnel/src/update/orchestrator.rs`

- [ ] **Step 1: Write a failing GitHub-client regression test.**

Create a local `TcpListener` test that returns one release-list page followed by manifest, signature, and archive responses. Select the release once, download all three exact asset names through the selected handle, and assert the server receives exactly one `/releases?per_page=100&page=1` request. Use three distinct release asset payloads so a rediscovery cannot pass accidentally.

- [ ] **Step 2: Run the new test and verify the current rediscovery implementation fails.**

Run: `cargo test -p rqbit-tunnel update::github::tests::selected_release_assets_do_not_rediscover_metadata`

Expected: failure because the old API performs one list request per asset download.

- [ ] **Step 3: Replace rediscovery-per-asset with an immutable selected-release handle.**

In `github.rs`, introduce a cloneable selected-release value:

```rust
#[derive(Clone, Debug)]
pub(crate) struct SelectedGithubRelease {
    pub(crate) version: Version,
    pub(crate) assets: ReleaseAssetUrls,
}
```

Make paginated discovery return `SelectedGithubRelease`. Change asset streaming to accept `&ReleaseAssetUrls` and fetch only the exact preselected URL; it must not call discovery. Keep per-asset URL and redirect validation.

Extend `ReleaseDiscovery` with crate-private selected GitHub version and asset URL context plus a public constructor for non-GitHub/fake sources. Change `ReleaseSource::download_asset` to accept `&ReleaseDiscovery`, then have `GitHubReleaseSource` use the discovery’s preselected URL set. Update every `FakeSource` implementation and callsite.

- [ ] **Step 4: Reject signed metadata whose version differs from the selected tag.**

After `verify_manifest` succeeds in `Updater::discover_verified`, compare the selected GitHub tag version when present:

```rust
if let Some(selected) = discovery.selected_github_version() {
    if selected != &manifest.version {
        return Err(UpdateError::GithubReleaseManifestVersionMismatch {
            selected: selected.clone(),
            manifest: manifest.version.clone(),
        });
    }
}
```

Add the typed `UpdateError` variant and map it to `UpdaterFailureCode::InvalidManifest`. Add a FakeSource regression using a selected `2.0.0` tag and a valid signed `1.0.0` manifest; it must return the mismatch error before archive download.

- [ ] **Step 5: Run focused update regressions.**

Run:

```bash
cargo test -p rqbit-tunnel update::github::tests::selected_release_assets_do_not_rediscover_metadata
cargo test -p rqbit-tunnel update::orchestrator::tests::selected_github_tag_must_match_signed_manifest
```

Expected: both pass.

### Task 2: Restrict updates to stable tags and keep large archives streaming

**Files:**
- Modify: `crates/rqbit-tunnel/src/update/github.rs`
- Modify: `.github/workflows/release-tunnel.yml`
- Test: `crates/rqbit-tunnel/src/update/github.rs`

- [ ] **Step 1: Write a failing stable-tag test.**

Add a release-list fixture containing a normal GitHub release tagged `tunnel-v2.0.0-rc.1` and a stable `tunnel-v1.9.0`, both with `prerelease: false`. Assert discovery selects `1.9.0`.

- [ ] **Step 2: Run the test and verify the prerelease is currently selected.**

Run: `cargo test -p rqbit-tunnel update::github::tests::release_discovery_rejects_semantic_prerelease_tags`

Expected: failure before the eligibility condition is changed.

- [ ] **Step 3: Require a stable SemVer tag and split metadata/asset timeout policy.**

Update `parse_tunnel_release_tag` to return `None` unless `version.pre.is_empty()` and the serialized tag body remains canonical. Keep a 15-second total timeout for GitHub release-list metadata. Build the asset client with a bounded connect timeout and per-read timeout, but no total request timeout:

```rust
fn build_release_asset_client<F>(is_safe_redirect: F) -> Result<reqwest::Client, UpdateError>
where
    F: Fn(&reqwest::Url) -> bool + Send + Sync + 'static,
{
    reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .read_timeout(Duration::from_secs(30))
        .user_agent(GITHUB_RELEASE_USER_AGENT)
        .redirect(reqwest::redirect::Policy::custom(move |attempt| {
            if attempt.previous().len() >= MAX_GITHUB_RELEASE_ASSET_REDIRECTS {
                attempt.error("too many GitHub release asset redirects")
            } else if is_safe_redirect(attempt.url()) {
                attempt.follow()
            } else {
                attempt.error("unsafe GitHub release asset redirect")
            }
        }))
        .build()
        .map_err(|source| UpdateError::BuildGithubReleaseClient { source })
}
```

This lets a valid archive exceed 15 seconds while still failing a stalled read. In `release-tunnel.yml`, reject a prerelease delimiter in the version core before `+` metadata so GitHub cannot publish an ordinary release that clients intentionally ignore.

- [ ] **Step 4: Run stable-release regression and parse the workflow.**

Run:

```bash
cargo test -p rqbit-tunnel update::github::tests::release_discovery_rejects_semantic_prerelease_tags
python3 -c 'import yaml; yaml.safe_load(open(".github/workflows/release-tunnel.yml")); print("workflow parsed")'
```

Expected: release regression passes and the workflow parses.

### Task 3: Make Windows bootstrap elevation and active-service upgrades safe

**Files:**
- Modify: `scripts/tunnel/client-run.ps1`
- Modify: `scripts/tunnel/install-client.ps1`
- Modify: `scripts/tunnel/test-client-bootstrap.ps1`
- Modify: `scripts/tunnel/smoke-windows-service.ps1`
- Test: `.github/workflows/tunnel-harness-smoke.yml` (existing Windows runner)

- [ ] **Step 1: Add a failing client-run self-test for a spaced installer path.**

Extend `client-run.ps1 -SelfTest` with `C:\Users\Alice Example\Tunnel Bundle\install-client.ps1`. Assert the elevated bootstrap arguments contain only fixed `-NoProfile`, `-NonInteractive`, `-EncodedCommand` tokens and that decoding the command preserves the complete literal path, not a whitespace-split prefix.

- [ ] **Step 2: Run the PowerShell self-test on Windows and verify the old direct `-File` handoff cannot meet the encoded-payload assertion.**

Run on Windows: `powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/tunnel/client-run.ps1 -SelfTest`

Expected: failure before replacing the direct `Start-Process ... -File $installer` call.

- [ ] **Step 3: Use a separate encoded installer handoff.**

Add a narrow helper that serializes `{ executable: <installer>, arguments: [] }` to UTF-8 JSON, base64-embeds it in a Unicode PowerShell encoded command, invokes `& $payload.executable @([string[]]$payload.arguments)`, and exits with `$LASTEXITCODE`. Use it only for the non-admin installer branch. Preserve the existing status-owner-SID-only client command helper unchanged.

- [ ] **Step 4: Stop and restore a running managed service around the stable-file switch.**

After validating and staging the new immutable payload but before overwriting `launcher.exe`, inspect `rqbit-tunnel-client` with `Get-Service -ErrorAction SilentlyContinue`. Record whether it was running/pending and stop it through the old launcher, waiting for `client service stop` to return. Preserve old `launcher.exe`, `client-run.ps1`, and `active.json` in a private staging rollback directory. If any stable-file write, active-pointer replacement, service reconfiguration, or restart fails, restore those exact old files/pointer and restart the previous service when it was running; remove the newly staged immutable release only when it was never activated. On success, call `client service install`, retain the existing autostart state, and use `client service start` after the new pointer is active only if the service was previously running.

- [ ] **Step 5: Exercise real upgrade behavior in disposable Windows CI.**

Extend `smoke-windows-service.ps1` to install/start a first bundle, construct a second bundle with a distinct release version from the same trusted payload, run its installer without `-SkipService`, then assert `active.json` is the second version and the service returns `RUNNING`. Keep cleanup idempotent. Ensure `test-client-bootstrap.ps1` checks the encoded installer handoff through `client-run.ps1 -SelfTest`.

- [ ] **Step 6: Run the Windows focused checks.**

Run on Windows:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/tunnel/client-run.ps1 -SelfTest
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/tunnel/test-client-bootstrap.ps1 -Installer scripts/tunnel/install-client.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/tunnel/smoke-windows-service.ps1 -Bundle .\rqbit-tunnel-x86_64-pc-windows-msvc.zip
```

Expected: all exit 0; the upgrade assertion observes the second active version and a running service.

### Task 4: Revalidate platform contracts and review the socket feedback

**Files:**
- Inspect: `crates/rqbit-tunnel/src/runtime/server.rs:697-743,2143-2164`
- Test: `crates/rqbit-tunnel/src/runtime/{client,server}.rs`

- [ ] **Step 1: Confirm the server replacement test already keeps its original socket inode live.**

Trace `ManagedServer::shutdown`: cleanup verifies/removes the named control socket before the control task is awaited, so the original task-owned `UnixListener` remains open while the test unlinks and binds the replacement. Do not add an artificial hard link to `shutdown_leaves_a_replacement_control_socket_untouched`; it already protects against inode reuse through the original open listener.

- [ ] **Step 2: Run socket replacement regressions.**

Run:

```bash
cargo test -p rqbit-tunnel --lib cleanup_preserves_a_socket_replaced_after_startup -- --exact
cargo test -p rqbit-tunnel --lib stale_socket_recovery_preserves_a_replacement_listener -- --exact
cargo test -p rqbit-tunnel --lib shutdown_leaves_a_replacement_control_socket_untouched -- --exact
```

Expected: all pass without allocator-dependent failures.

### Task 5: Full verification and final review

**Files:**
- Verify: `crates/rqbit-tunnel`, `scripts/tunnel`, `.github/workflows`

- [ ] **Step 1: Format and run native/feature tests.**

Run:

```bash
cargo fmt -p rqbit-tunnel -- --check
cargo test -p rqbit-tunnel
cargo test -p rqbit-tunnel --features tray-linux
bash -n scripts/tunnel/client-run.sh scripts/tunnel/install-client.sh scripts/tunnel/smoke-systemd.sh scripts/tunnel/test-client-bootstrap.sh
```

- [ ] **Step 2: Cross-compile the Windows test graph.**

Run:

```bash
TMPDIR=/home/bpqvg/t TMP=/home/bpqvg/t TEMP=/home/bpqvg/t \
CARGO_TARGET_DIR="$PWD/target/windows-verify" \
CC_x86_64_pc_windows_gnu="$PWD/.cross/usr/bin/x86_64-w64-mingw32-gcc-posix" \
cargo check -p rqbit-tunnel --tests --features tray-windows --target x86_64-pc-windows-gnu
```

Expected: exit 0. The GitHub Windows workflow remains the runtime proof for service and PowerShell behavior.

- [ ] **Step 3: Request a final read-only reviewer pass.**

Review the selected-release transaction, stable-tag filtering, archive timeout policy, Windows service rollback/restart flow, and release bundle contents. Resolve every Critical or Important finding before completion.
