#!/usr/bin/env bash
# Installs the pinned agent-credentials build as the boot service's runtime.
#
#   scripts/agent-credentials/install.sh [--label 0.0.46-nightly.20261008.2833+ac.1]
#       [--archive PATH] [--build] [--without-relay] [--restart] [--dry-run]
#
# What it changes, in order (printed before anything happens):
#   1. unpacks the archive into ~/.t3/runtime/versions/<label>/ with its
#      .install-complete marker, the layout the service launcher runs;
#   2. saves the current ~/.t3/runtime/service-state.json verbatim under
#      ~/.t3/runtime/agent-credentials/history/ for rollback.sh;
#   3. replaces service-state.json with {"protocol":3,"activeVersion":"<label>"}.
#      The launcher reads it when the service next starts.
#   4. with --restart only, restarts t3code.service.
#
# It never touches ~/.t3/userdata. It does not enable the protected-auth socket:
# that stays off until an operator writes ~/.t3/protected-auth.json (see
# docs/agent-credentials/protected-authentication.md).
#
# Pinning: a +ac.<n> build refuses update requests from clients, so the version
# only moves through this script, rollback.sh, or an explicit `t3 update` run
# on the host. --build runs build.sh first; otherwise the archive build.sh
# produced for the label is used.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

label="$BASE_VERSION+ac.$DEFAULT_BUILD_NUMBER"
archive=""
build=false
restart=false
dry_run=false
build_args=()
while [ $# -gt 0 ]; do
  case "$1" in
    --label) label="$2"; shift 2 ;;
    --archive) archive="$2"; shift 2 ;;
    --build) build=true; shift ;;
    --without-relay) build_args+=(--without-relay); shift ;;
    --restart) restart=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$label" =~ $LABEL_PATTERN ]] || die "label must be $BASE_VERSION+ac.<n>, got $label"
[ -n "$archive" ] || archive="$HOME/.cache/t3-agent-credentials/archives/t3-$label-linux-x64.tar.gz"
target_dir="$VERSIONS_DIR/$label"
history_dir="$RECORD_DIR/history"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

[ -f "$STATE_FILE" ] || die "$STATE_FILE not found; install the boot service first (t3 service install)"
current="$(json_field "$STATE_FILE" activeVersion)"
protocol="$(node -e 'process.stdout.write(String(JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).protocol))' "$STATE_FILE")"
update_status="$(state_update_status "$STATE_FILE")"
[ -n "$current" ] || die "$STATE_FILE has no activeVersion"
[ "$protocol" = 3 ] || die "launcher protocol $protocol is not the protocol 3 this build was checked against"
[ "$update_status" != pending ] || die "an update is pending in $STATE_FILE; let it finish first"
[ "$current" != "$label" ] || die "$label is already the active version"

say "Install plan"
say "  service unit:        $SERVICE_UNIT ($(service_active && echo running || echo 'not running'))"
say "  service state:       $STATE_FILE"
say "  current version:     $current${update_status:+ (last update: $update_status)}"
say "  new version:         $label"
if $build; then
  say "  archive:             $archive (built first by build.sh)"
elif [ -f "$archive" ]; then
  say "  archive:             $archive"
else
  say "  archive:             $archive (MISSING: run build.sh or pass --build)"
fi
if [ -f "$target_dir/.install-complete" ] && [ "$(cat "$target_dir/.install-complete")" = "$label" ]; then
  say "  runtime dir:         $target_dir (already installed, reused)"
else
  say "  will create:         $target_dir/ (t3, client/, resource-monitor/, node_modules/, .install-complete)"
fi
say "  will save:           $STATE_FILE -> $history_dir/$stamp-service-state.json"
say "  will write:          $STATE_FILE = {\"protocol\":3,\"activeVersion\":\"$label\"}"
say "                       (drops the update record; rollback.sh restores the saved file as is)"
if $restart; then
  say "  will restart:        systemctl --user restart $SERVICE_UNIT"
else
  say "  restart:             not requested; takes effect at the next start of $SERVICE_UNIT"
fi
say "  unchanged:           ~/.t3/userdata, the database, the launcher binary, the systemd unit"
say "  protected-auth:      stays off until $T3_HOME/protected-auth.json exists"
if $build; then
  say ""
  "$(dirname "${BASH_SOURCE[0]}")/build.sh" --label "$label" --dry-run "${build_args[@]}"
fi
if $dry_run; then
  say ""
  say "Dry run: nothing changed."
  exit 0
fi

if $build; then
  "$(dirname "${BASH_SOURCE[0]}")/build.sh" --label "$label" "${build_args[@]}"
fi
[ -f "$archive" ] || die "archive not found: $archive"
if [ -f "$archive.sha256" ]; then
  (cd "$(dirname "$archive")" && sha256sum -c --quiet "$(basename "$archive").sha256") || die "archive checksum mismatch"
fi

if ! { [ -f "$target_dir/.install-complete" ] && [ "$(cat "$target_dir/.install-complete")" = "$label" ]; }; then
  mkdir -p "$VERSIONS_DIR"
  staging="$(mktemp -d "$VERSIONS_DIR/.staging-XXXXXX")"
  trap 'rm -rf "$staging"' EXIT
  tar -xzf "$archive" -C "$staging" --strip-components=1
  reported="$(env -u T3_SERVICE_LAUNCHER_CONTEXT "$staging/t3" --version 2>/dev/null | tail -n 1 | tr -d '[:space:]')"
  case "$reported" in
    *"$label"*) ;;
    *) die "the built t3 reports version '$reported', expected $label" ;;
  esac
  printf '%s\n' "$label" > "$staging/.install-complete"
  rm -rf "$target_dir"
  mv "$staging" "$target_dir"
  trap - EXIT
  say "Installed $target_dir"
fi

mkdir -p "$history_dir"
chmod 700 "$RECORD_DIR"
cp -p "$STATE_FILE" "$history_dir/$stamp-service-state.json"
next="$(mktemp "$RUNTIME_DIR/.service-state-XXXXXX")"
printf '{\n  "protocol": 3,\n  "activeVersion": "%s"\n}\n' "$label" > "$next"
chmod --reference="$STATE_FILE" "$next" 2>/dev/null || true
mv "$next" "$STATE_FILE"
say "Saved the previous state to $history_dir/$stamp-service-state.json"
say "Set activeVersion to $label (was $current)"

if $restart; then
  systemctl --user restart "$SERVICE_UNIT"
  say "Restarted $SERVICE_UNIT"
else
  say "Restart $SERVICE_UNIT to run it: systemctl --user restart $SERVICE_UNIT"
fi
say "Undo with scripts/agent-credentials/rollback.sh"
