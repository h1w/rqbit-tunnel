#!/usr/bin/env bash
# Bootstrap one trusted rqbit-tunnel client release into the managed layout.
set -euo pipefail
umask 077

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly DEFAULT_INSTALL_ROOT='/opt/rqbit-tunnel'
readonly DEFAULT_UNIT_DIR='/etc/systemd/system'
readonly SERVICE_NAME='rqbit-tunnel-client.service'
readonly LAUNCHER_ABI=1

install_root=$DEFAULT_INSTALL_ROOT
unit_dir=$DEFAULT_UNIT_DIR
skip_service=0

usage() {
    cat <<'EOF'
usage: install-client.sh [--root PATH] [--unit-dir PATH] [--skip-service]

Installs this release bundle into the managed client layout. The default paths
require root. --root, --unit-dir, and --skip-service exist for disposable
integration tests; production installs use the defaults.
EOF
}

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

require_absolute_path() {
    [[ "$1" == /* ]] || die "path must be absolute: $1"
}

require_regular_file() {
    local path=$1
    [[ -f "$path" && ! -L "$path" ]] || die "required regular file is missing: $path"
}

require_executable_file() {
    require_regular_file "$1"
    [[ -x "$1" ]] || die "required executable file is missing execute permission: $1"
}

ensure_directory() {
    local path=$1 mode=$2

    if [[ -e "$path" || -L "$path" ]]; then
        [[ ! -L "$path" && -d "$path" ]] || die "expected a non-symlink directory: $path"
    else
        mkdir -p -- "$path"
    fi
    chmod "$mode" -- "$path"
}

atomic_install_file() {
    local source=$1 destination=$2 mode=$3 parent temporary

    parent=${destination%/*}
    [[ "$parent" != "$destination" ]] || die "destination has no parent: $destination"
    if [[ -e "$destination" || -L "$destination" ]]; then
        [[ ! -L "$destination" && -f "$destination" ]] ||
            die "destination is not a replaceable regular file: $destination"
    fi

    temporary=$(mktemp "$parent/.${destination##*/}.XXXXXX")
    if ! install -m "$mode" -- "$source" "$temporary"; then
        rm -f -- "$temporary"
        die "could not stage $destination"
    fi
    mv -f -- "$temporary" "$destination"
}

while (($#)); do
    case "$1" in
        --root)
            (($# >= 2)) || die '--root needs a path'
            install_root=$2
            shift
            ;;
        --unit-dir)
            (($# >= 2)) || die '--unit-dir needs a path'
            unit_dir=$2
            shift
            ;;
        --skip-service)
            skip_service=1
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            usage >&2
            die "unknown argument: $1"
            ;;
    esac
    shift
done

require_absolute_path "$install_root"
require_absolute_path "$unit_dir"
if [[ "$install_root" == "$DEFAULT_INSTALL_ROOT" || "$unit_dir" == "$DEFAULT_UNIT_DIR" ]]; then
    (( EUID == 0 )) || die 'root privileges are required for the managed system paths'
fi

release_version_file="$SCRIPT_DIR/release-version.txt"
require_regular_file "$release_version_file"
release_version=$(<"$release_version_file")
if [[ ! "$release_version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]; then
    die "release-version.txt must contain one canonical semantic version"
fi

payload_source="$SCRIPT_DIR/rqbit-tunnel"
updater_source="$SCRIPT_DIR/rqbit-tunnel-updater"
tray_source="$SCRIPT_DIR/rqbit-tunnel-tray"
launcher_source="$SCRIPT_DIR/launcher"
unit_source="$SCRIPT_DIR/systemd/$SERVICE_NAME"
require_executable_file "$payload_source"
require_executable_file "$updater_source"
require_executable_file "$tray_source"
require_executable_file "$launcher_source"
require_regular_file "$unit_source"

ensure_directory "$install_root" 0755
ensure_directory "$install_root/releases" 0755
ensure_directory "$unit_dir" 0755

lock_path="$install_root/.bootstrap.lock"
if [[ -L "$lock_path" ]]; then
    die "bootstrap lock is a symbolic link: $lock_path"
fi
exec 9>"$lock_path"
if ! flock -n 9; then
    die 'another client bootstrap is already in progress'
fi

release_dir="$install_root/releases/$release_version"
if [[ -e "$release_dir" || -L "$release_dir" ]]; then
    die "immutable release already exists: $release_dir"
fi

release_stage=$(mktemp -d "$install_root/.release.${release_version}.XXXXXX")
cleanup_stage() {
    if [[ -n "$release_stage" ]]; then
        rm -rf -- "$release_stage"
    fi
}
trap cleanup_stage EXIT HUP INT TERM
install -d -m 0755 -- "$release_stage/payload"
install -m 0755 -- "$payload_source" "$release_stage/payload/rqbit-tunnel"
install -m 0755 -- "$updater_source" "$release_stage/payload/rqbit-tunnel-updater"
install -m 0755 -- "$tray_source" "$release_stage/payload/rqbit-tunnel-tray"
mv -- "$release_stage" "$release_dir"
chmod 0755 -- "$release_dir"
release_stage=''

atomic_install_file "$launcher_source" "$install_root/launcher" 0755
atomic_install_file "$unit_source" "$unit_dir/$SERVICE_NAME" 0644

active_path="$install_root/active.json"
if [[ -L "$active_path" ]]; then
    die "active release pointer is a symbolic link: $active_path"
fi
active_temporary=$(mktemp "$install_root/.active.json.XXXXXX")
printf '{"version":"%s","payload_dir":"releases/%s/payload","launcher_abi":%s}' \
    "$release_version" "$release_version" "$LAUNCHER_ABI" >"$active_temporary"
chmod 0644 -- "$active_temporary"
mv -f -- "$active_temporary" "$active_path"

if (( ! skip_service )); then
    command -v systemctl >/dev/null 2>&1 || die 'systemctl is required to install the managed client service'
    systemctl daemon-reload
    if [[ -f /etc/rqbit-tunnel/client.json && ! -L /etc/rqbit-tunnel/client.json ]]; then
        if systemctl is-active --quiet "$SERVICE_NAME"; then
            systemctl enable "$SERVICE_NAME"
            systemctl restart "$SERVICE_NAME"
        else
            systemctl enable --now "$SERVICE_NAME"
        fi
    else
        printf 'client runtime installed; import an enrollment bundle before starting %s\n' "$SERVICE_NAME"
    fi
fi

printf 'installed managed client release %s at %s\n' "$release_version" "$install_root"
