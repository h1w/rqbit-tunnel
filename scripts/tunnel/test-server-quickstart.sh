#!/usr/bin/env bash
# Exercise server-quickstart.sh against a disposable fake privileged environment.
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    printf 'usage: %s INSTALLER [initial|bundle-layout|rollback|protected-parent|lock|lock-sentinel|lock-path|keygen-privilege|health-journal|all]\n' "${0##*/}" >&2
    exit 64
fi

readonly INSTALLER=$1
readonly SELECTED_TEST=${2:-all}
readonly ORIGINAL_PATH=$PATH

[[ -f "$INSTALLER" ]] || {
    printf 'error: installer is absent: %s\n' "$INSTALLER" >&2
    exit 1
}

workspace=$(mktemp -d "${TMPDIR:-/tmp}/rqbit-tunnel-quickstart.XXXXXX")
cleanup_workspace() {
    chmod 0700 "$workspace"/blocked 2>/dev/null || true
    rm -rf -- "$workspace"
}
trap cleanup_workspace EXIT HUP INT TERM

fail() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

assert_contains() {
    local expected=$1 path=$2
    grep -Fq -- "$expected" "$path" || fail "expected $path to contain: $expected"
}

assert_absent() {
    [[ ! -e "$1" && ! -L "$1" ]] || fail "expected path to be absent: $1"
}

wait_for_path() {
    local path=$1 attempts=0

    while [[ ! -e "$path" ]]; do
        ((attempts += 1))
        (( attempts < 100 )) || fail "timed out waiting for $path"
        sleep 0.05
    done
}

setup_case() {
    local name=$1

    CASE_DIR="$workspace/$name"
    FAKE_ROOT="$CASE_DIR/root"
    export CASE_DIR FAKE_ROOT
    mkdir -p "$CASE_DIR/fake-bin" "$CASE_DIR/release" "$CASE_DIR/tmp" "$FAKE_ROOT/run"

    cat >"$CASE_DIR/fake-bin/sudo" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

while (($#)); do
    case "$1" in
        -v)
            exit 0
            ;;
        -n)
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            break
            ;;
    esac
done
command_name=${1:?missing privileged command}
shift

map_path() {
    local path=$1

    if [[ -n ${FAKE_LOGICAL_PREFIX:-} && "$path" == "$FAKE_LOGICAL_PREFIX"* ]]; then
        printf '%s%s\n' "$FAKE_BACKING_PREFIX" "${path#"$FAKE_LOGICAL_PREFIX"}"
        return
    fi

    case "$path" in
        /opt/rqbit-tunnel|/opt/rqbit-tunnel/*|/etc/rqbit-tunnel|/etc/rqbit-tunnel/*|/var/lib/rqbit-tunnel|/var/lib/rqbit-tunnel/*|/run/rqbit-tunnel|/run/rqbit-tunnel/*|/run/rqbit-tunnel-server.install.lock|/etc/systemd/system|/etc/systemd/system/*|/var/lock/rqbit-tunnel-server.install.lock)
            printf '%s%s\n' "$FAKE_ROOT" "$path"
            ;;
        *)
            printf '%s\n' "$path"
            ;;
    esac
}

map_last_path() {
    local -n target=$1
    local index=$((${#target[@]} - 1))
    target[$index]=$(map_path "${target[$index]}")
}

case "$command_name" in
    test)
        arguments=("$@")
        map_last_path arguments
        test "${arguments[@]}"
        ;;
    install)
        arguments=("$@")
        original_destination=${arguments[$((${#arguments[@]} - 1))]}
        if [[ ${FAIL_INSTALL_DEST:-} == "$original_destination" ]]; then
            exit 42
        fi
        mapped=()
        for ((index = 0; index < ${#arguments[@]}; index += 1)); do
            argument=${arguments[$index]}
            case "$argument" in
                -o|-g)
                    ((index += 1))
                    ;;
                *)
                    if (( index == ${#arguments[@]} - 1 )); then
                        argument=$(map_path "$argument")
                    fi
                    mapped+=("$argument")
                    ;;
            esac
        done
        /usr/bin/install "${mapped[@]}"
        ;;
    chmod)
        arguments=("$@")
        map_last_path arguments
        /bin/chmod "${arguments[@]}"
        ;;
    chown)
        # Ownership is not relevant inside the unprivileged fake root.
        ;;
    mkdir|rmdir)
        arguments=("$@")
        map_last_path arguments
        "$command_name" "${arguments[@]}"
        ;;
    rm)
        arguments=()
        for argument in "$@"; do
            arguments+=("$(map_path "$argument")")
        done
        rm "${arguments[@]}"
        ;;
    systemctl|flock)
        FAKE_SUDO_CONTEXT=1 exec "$command_name" "$@"
        ;;
    bash)
        if [[ ${1:-} == -c ]]; then
            script=$2
            shift 2
            arguments=()
            for argument in "$@"; do
                arguments+=("$(map_path "$argument")")
            done
            exec env FAKE_SUDO_CONTEXT=1 /bin/bash -c "$script" "${arguments[@]}"
        fi
        exec env FAKE_SUDO_CONTEXT=1 /bin/bash "$@"
        ;;
    /opt/rqbit-tunnel/rqbit-tunnel)
        exec env FAKE_SUDO_CONTEXT=1 "$(map_path "$command_name")" "$@"
        ;;
    *)
        exec env FAKE_SUDO_CONTEXT=1 "$command_name" "$@"
        ;;
esac
EOF

    cat >"$CASE_DIR/fake-bin/flock" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

while (($#)); do
    case "$1" in
        -n)
            shift
            ;;
        -E)
            shift 2
            ;;
        --)
            shift
            break
            ;;
        -*)
            printf 'unsupported fake flock option: %s\n' "$1" >&2
            exit 64
            ;;
        *)
            break
            ;;
    esac
done

lock_path=${1:?missing lock path}
shift
if [[ "$lock_path" =~ ^[0-9]+$ && $# -eq 0 ]]; then
    exec /usr/bin/flock -n "$lock_path"
fi
if [[ ${REJECT_WORLD_WRITABLE_LOCK:-} == 1 && "$lock_path" == /var/lock/* ]]; then
    printf 'unsafe lock path: %s\n' "$lock_path" >&2
    exit 65
fi
case "$lock_path" in
    /var/lock/rqbit-tunnel-server.install.lock|/run/rqbit-tunnel-server.install.lock)
        lock_path="$FAKE_ROOT$lock_path"
        ;;
esac
mkdir -p "$(dirname "$lock_path")"
if ! mkdir "$lock_path.lock" 2>/dev/null; then
    exit 75
fi
trap 'rmdir "$lock_path.lock"' EXIT
"$@"
EOF

    cat >"$CASE_DIR/fake-bin/systemctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

case " $* " in
    *' is-active '*)
        [[ -e "$FAKE_ROOT/service.active" ]]
        ;;
    *' stop '*)
        rm -f "$FAKE_ROOT/service.active" "$FAKE_ROOT/run/rqbit-tunnel/server.sock"
        ;;
    *' enable '*|*' restart '*)
        touch "$FAKE_ROOT/service.active"
        ;;
    *' daemon-reload '*|*' status '*)
        ;;
    *)
        printf 'unexpected fake systemctl call: %s\n' "$*" >&2
        exit 64
        ;;
esac
EOF

    cat >"$CASE_DIR/fake-bin/journalctl" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

printf 'synthetic server journal: bind: Address already in use\n'
EOF

    cat >"$CASE_DIR/release/rqbit-tunnel" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ "$*" == 'server users list --json' ]]; then
    if [[ ${FAKE_HEALTH_FAIL:-} == 1 ]]; then
        exit 1
    fi
    printf '[]\n'
fi
EOF

    cat >"$CASE_DIR/release/rqbit" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail

if [[ ${REJECT_ROOT_KEYGEN:-} == 1 && ${FAKE_SUDO_CONTEXT:-} == 1 ]]; then
    printf 'key generation unexpectedly ran in the elevated installer context\n' >&2
    exit 43
fi
[[ ${1:-} == tunnel && ${2:-} == keygen && ${3:-} == --output-dir ]] || exit 64
output_dir=${4:?missing output directory}
if [[ ${BLOCK_FIRST_KEYGEN:-} == 1 ]] && mkdir "$FAKE_ROOT/first-keygen.lock" 2>/dev/null; then
    touch "$FAKE_ROOT/first-keygen.started"
    while [[ ! -e "$FAKE_ROOT/release-first-keygen" ]]; do
        sleep 0.05
    done
fi
mkdir -p "$output_dir"
printf '%064d\n' 0 >"$output_dir/server.key"
printf '%064d\n' 1 >"$output_dir/client.key"
EOF

    chmod 0755 "$CASE_DIR/fake-bin/"* "$CASE_DIR/release/"*
}

run_installer() {
    env \
        PATH="$CASE_DIR/fake-bin:$ORIGINAL_PATH" \
        FAKE_ROOT="$FAKE_ROOT" \
        RQBIT_TUNNEL_BIN="$CASE_DIR/release/rqbit-tunnel" \
        RQBIT_KEYGEN_BIN="$CASE_DIR/release/rqbit" \
        RQBIT_TUNNEL_UNIT="$(dirname "$INSTALLER")/../../systemd/rqbit-tunnel-server.service" \
        SERVER_IP=8.8.8.8 \
        TMPDIR="$CASE_DIR/tmp" \
        "$INSTALLER" --skip-tui
}

test_initial_config_uses_wildcard_bind_and_managed_export_directory() {
    setup_case initial
    run_installer >/dev/null

    config="$FAKE_ROOT/etc/rqbit-tunnel/server.json"
    assert_contains '"peer_listen": "0.0.0.0:4242"' "$config"
    assert_contains '"advertised_peer": "8.8.8.8:4242"' "$config"
    [[ -d "$FAKE_ROOT/var/lib/rqbit-tunnel/enrollments" ]] ||
        fail 'quickstart must create the service-visible enrollment export directory'
}

test_release_bundle_uses_its_adjacent_systemd_template_and_binary() {
    setup_case bundle-layout
    bundle="$CASE_DIR/bundle"
    mkdir -p "$bundle/systemd"
    cp "$INSTALLER" "$bundle/server-quickstart.sh"
    cp "$CASE_DIR/release/rqbit-tunnel" "$bundle/rqbit-tunnel"
    chmod 0755 "$bundle/rqbit-tunnel"
    cp "$(dirname "$INSTALLER")/../../systemd/rqbit-tunnel-server.service" "$bundle/systemd/"
    chmod 0755 "$bundle/server-quickstart.sh"

    env \
        PATH="$CASE_DIR/fake-bin:$ORIGINAL_PATH" \
        FAKE_ROOT="$FAKE_ROOT" \
        RQBIT_KEYGEN_BIN="$CASE_DIR/release/rqbit" \
        SERVER_IP=8.8.8.8 \
        TMPDIR="$CASE_DIR/tmp" \
        "$bundle/server-quickstart.sh" --skip-tui >/dev/null
}

test_failed_fresh_key_install_rolls_back_new_identity() {
    setup_case rollback

    if FAIL_INSTALL_DEST=/etc/rqbit-tunnel/server.key run_installer >/dev/null 2>&1; then
        fail 'quickstart unexpectedly succeeded after a server-key install failure'
    fi

    assert_absent "$FAKE_ROOT/etc/rqbit-tunnel/server.json"
    assert_absent "$FAKE_ROOT/etc/rqbit-tunnel/server.key"
}

test_existing_regular_file_inspects_a_protected_parent_as_root() {
    setup_case protected-parent
    logical_parent="$workspace/blocked/child"
    backing_parent="$workspace/backing/child"
    mkdir -p "$logical_parent" "$backing_parent"
    touch "$backing_parent/server-state.db"
    chmod 000 "$workspace/blocked"

    export PATH="$CASE_DIR/fake-bin:$ORIGINAL_PATH"
    export FAKE_LOGICAL_PREFIX="$logical_parent"
    export FAKE_BACKING_PREFIX="$backing_parent"
    # Load only the installer helpers; main starts at skip_tui.
    # shellcheck disable=SC1090
    source <(awk '/^skip_tui=0$/{ exit } { print }' "$INSTALLER")

    if ! existing_regular_file_as_root "$logical_parent/server-state.db"; then
        fail 'a regular file behind a protected parent must be detected through root inspection'
    fi
}

test_concurrent_install_is_rejected_before_identity_preflight() {
    setup_case lock

    BLOCK_FIRST_KEYGEN=1 run_installer >"$CASE_DIR/first.out" 2>&1 &
    first_pid=$!
    wait_for_path "$FAKE_ROOT/first-keygen.started"

    set +e
    second_output=$(BLOCK_FIRST_KEYGEN=1 run_installer 2>&1)
    second_status=$?
    set -e

    touch "$FAKE_ROOT/release-first-keygen"
    wait "$first_pid"

    (( second_status != 0 )) || fail 'a concurrent installer invocation must be rejected'
    [[ "$second_output" == *'another installation is already in progress'* ]] ||
        fail 'a concurrent installer must explain that the installation lock is held'
}

test_inherited_lock_sentinel_does_not_bypass_serialization() {
    setup_case lock-sentinel

    BLOCK_FIRST_KEYGEN=1 run_installer >"$CASE_DIR/first.out" 2>&1 &
    first_pid=$!
    wait_for_path "$FAKE_ROOT/first-keygen.started"

    set +e
    second_output=$(BLOCK_FIRST_KEYGEN=1 RQBIT_TUNNEL_INSTALL_LOCK_HELD=1 run_installer 2>&1)
    second_status=$?
    set -e

    touch "$FAKE_ROOT/release-first-keygen"
    wait "$first_pid"

    (( second_status != 0 )) ||
        fail 'an inherited lock sentinel must not bypass a held installer lock'
    [[ "$second_output" == *'another installation is already in progress'* ]] ||
        fail 'a sentinel-bypass attempt must report the held installation lock'
}

test_installation_lock_uses_a_root_only_path() {
    setup_case lock-path
    REJECT_WORLD_WRITABLE_LOCK=1 run_installer >/dev/null
}

test_key_generation_stays_outside_the_elevated_lock_holder() {
    setup_case keygen-privilege
    REJECT_ROOT_KEYGEN=1 run_installer >/dev/null
}

test_failed_health_includes_service_journal() {
    local output status

    setup_case health-journal
    sleep() {
        SECONDS=$((SECONDS + ${1:-0}))
    }
    export -f sleep
    set +e
    output=$(FAKE_HEALTH_FAIL=1 run_installer 2>&1)
    status=$?
    set -e
    unset -f sleep

    (( status != 0 )) || fail 'a failed server health check must fail the installer'
    [[ "$output" == *'synthetic server journal: bind: Address already in use'* ]] ||
        fail 'a failed server health check must include the managed service journal'
}

case "$SELECTED_TEST" in
    initial)
        test_initial_config_uses_wildcard_bind_and_managed_export_directory
        ;;
    rollback)
        test_failed_fresh_key_install_rolls_back_new_identity
        ;;
    bundle-layout)
        test_release_bundle_uses_its_adjacent_systemd_template_and_binary
        ;;
    protected-parent)
        test_existing_regular_file_inspects_a_protected_parent_as_root
        ;;
    lock)
        test_concurrent_install_is_rejected_before_identity_preflight
        ;;
    lock-sentinel)
        test_inherited_lock_sentinel_does_not_bypass_serialization
        ;;
    lock-path)
        test_installation_lock_uses_a_root_only_path
        ;;
    keygen-privilege)
        test_key_generation_stays_outside_the_elevated_lock_holder
        ;;
    health-journal)
        test_failed_health_includes_service_journal
        ;;
    all)
        test_initial_config_uses_wildcard_bind_and_managed_export_directory
        test_failed_fresh_key_install_rolls_back_new_identity
        test_existing_regular_file_inspects_a_protected_parent_as_root
        test_concurrent_install_is_rejected_before_identity_preflight
        test_inherited_lock_sentinel_does_not_bypass_serialization
        test_release_bundle_uses_its_adjacent_systemd_template_and_binary
        test_installation_lock_uses_a_root_only_path
        test_key_generation_stays_outside_the_elevated_lock_holder
        test_failed_health_includes_service_journal
        ;;
    *)
        fail "unknown test selection: $SELECTED_TEST"
        ;;
esac

printf 'validated %s (%s)\n' "$INSTALLER" "$SELECTED_TEST"
