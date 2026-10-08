#!/usr/bin/env bash
# Restores the service state saved by the most recent install.sh run, which
# puts back the previous activeVersion.
#
#   scripts/agent-credentials/rollback.sh [--restart] [--dry-run]
#
# What it changes (printed before anything happens):
#   1. replaces ~/.t3/runtime/service-state.json with the newest file in
#      ~/.t3/runtime/agent-credentials/history/, exactly as it was saved;
#   2. renames that history file to *.restored-<time> so a second rollback
#      steps back one more install;
#   3. with --restart only, restarts t3code.service.
#
# It keeps ~/.t3/runtime/versions/<label>/ for a quick re-install; remove it by
# hand once it is no longer needed. The pinned build shares the base version's
# database schema (build.sh refuses otherwise), so the database needs no restore.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

restart=false
dry_run=false
while [ $# -gt 0 ]; do
  case "$1" in
    --restart) restart=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

history_dir="$RECORD_DIR/history"
saved="$(find "$history_dir" -maxdepth 1 -name '*-service-state.json' -print 2>/dev/null | sort | tail -n 1)"
[ -n "$saved" ] || die "no saved service state in $history_dir; nothing to roll back"
[ -f "$STATE_FILE" ] || die "$STATE_FILE not found"
current="$(json_field "$STATE_FILE" activeVersion)"
previous="$(json_field "$saved" activeVersion)"
[ -n "$previous" ] || die "$saved has no activeVersion"
[ "$(state_update_status "$STATE_FILE")" != pending ] || die "an update is pending in $STATE_FILE; let it finish first"
previous_dir="$VERSIONS_DIR/$previous"
[ -x "$previous_dir/t3" ] && [ "$(cat "$previous_dir/.install-complete" 2>/dev/null)" = "$previous" ] ||
  die "$previous_dir is not a complete runtime; cannot roll back to it"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"

say "Rollback plan"
say "  service unit:     $SERVICE_UNIT ($(service_active && echo running || echo 'not running'))"
say "  current version:  $current"
say "  restore version:  $previous (runtime $previous_dir present)"
say "  will write:       $STATE_FILE <- $saved"
say "  will rename:      $saved -> $saved.restored-$stamp"
if $restart; then
  say "  will restart:     systemctl --user restart $SERVICE_UNIT"
else
  say "  restart:          not requested; takes effect at the next start of $SERVICE_UNIT"
fi
say "  unchanged:        ~/.t3/userdata, the database, every runtime under $VERSIONS_DIR"
if $dry_run; then
  say ""
  say "Dry run: nothing changed."
  exit 0
fi

next="$(mktemp "$RUNTIME_DIR/.service-state-XXXXXX")"
cp "$saved" "$next"
chmod --reference="$STATE_FILE" "$next" 2>/dev/null || true
mv "$next" "$STATE_FILE"
mv "$saved" "$saved.restored-$stamp"
say "Set activeVersion to $previous (was $current)"
if $restart; then
  systemctl --user restart "$SERVICE_UNIT"
  say "Restarted $SERVICE_UNIT"
else
  say "Restart $SERVICE_UNIT to run it: systemctl --user restart $SERVICE_UNIT"
fi
