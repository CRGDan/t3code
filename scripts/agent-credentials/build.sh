#!/usr/bin/env bash
# Builds the pinned agent-credentials runtime archive from this checkout's HEAD,
# the same archive layout a T3 release ships (t3, client/, resource-monitor/,
# node_modules/). Writes nothing under ~/.t3; install.sh installs the result.
#
#   scripts/agent-credentials/build.sh [--label 0.0.46-nightly.20261008.2833+ac.1]
#       [--output-dir DIR] [--resource-monitor-dir DIR] [--dry-run]
#
# The build runs in a temporary detached worktree, so stamping the label into
# package.json never touches this checkout. The single executable needs Node
# 25.7+ for --build-sea; the pinned SEA Node (SEA_NODE_VERSION in
# apps/server/vite.config.ts) is downloaded, checksum-verified, into
# $TOOLCHAIN_DIR. The host's Node and global packages are left alone.
#
# T3 Connect: release builds bake in public relay config. Export
# T3CODE_RELAY_URL, T3CODE_CLERK_PUBLISHABLE_KEY, T3CODE_CLERK_JWT_TEMPLATE and
# T3CODE_CLERK_CLI_OAUTH_CLIENT_ID to keep it; without them the build refuses
# unless --without-relay is passed.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/common.sh"

label="$BASE_VERSION+ac.$DEFAULT_BUILD_NUMBER"
output_dir="$HOME/.cache/t3-agent-credentials/archives"
resource_monitor_dir=""
dry_run=false
without_relay=false
while [ $# -gt 0 ]; do
  case "$1" in
    --label) label="$2"; shift 2 ;;
    --output-dir) output_dir="$2"; shift 2 ;;
    --resource-monitor-dir) resource_monitor_dir="$2"; shift 2 ;;
    --without-relay) without_relay=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

[[ "$label" =~ $LABEL_PATTERN ]] || die "label must be $BASE_VERSION+ac.<n>, got $label"
case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) target=linux-x64; platform=linux; arch=x64 ;;
  *) die "only linux x64 is supported" ;;
esac
archive="$output_dir/t3-$label-$platform-$arch.tar.gz"

cd "$REPO_ROOT"
git merge-base --is-ancestor "$BASE_COMMIT" HEAD || die "HEAD does not contain $BASE_TAG ($BASE_COMMIT)"
[ -z "$(git status --porcelain)" ] || die "the checkout has uncommitted changes; commit them first"
# The pinned build must share the base's database schema, so rollback to the
# base never meets a newer schema.
if [ -n "$(git diff --name-only "$BASE_COMMIT" HEAD -- apps/server/src/persistence/Migrations apps/server/src/persistence/Migrations.ts)" ]; then
  die "this branch changes database migrations; rollback to $BASE_VERSION would not be safe"
fi

# Reuse the resource monitor from the active runtime (same base version) when
# none is given: building it needs a Rust toolchain.
if [ -z "$resource_monitor_dir" ] && [ -f "$STATE_FILE" ]; then
  active="$(json_field "$STATE_FILE" activeVersion)"
  [ -n "$active" ] && resource_monitor_dir="$VERSIONS_DIR/$active/resource-monitor"
fi
[ -n "$resource_monitor_dir" ] && [ -x "$resource_monitor_dir/$target/t3-resource-monitor" ] ||
  die "no resource monitor at ${resource_monitor_dir:-<unset>}/$target; pass --resource-monitor-dir"

sea_node_version="$(sed -n 's/^const SEA_NODE_VERSION = "\([0-9.]*\)";$/\1/p' apps/server/vite.config.ts)"
[ -n "$sea_node_version" ] || die "could not read SEA_NODE_VERSION from apps/server/vite.config.ts"
sea_node_dir="$TOOLCHAIN_DIR/node-v$sea_node_version-$target"

relay_missing=()
for name in T3CODE_RELAY_URL T3CODE_CLERK_PUBLISHABLE_KEY T3CODE_CLERK_JWT_TEMPLATE T3CODE_CLERK_CLI_OAUTH_CLIENT_ID; do
  [ -n "${!name:-}" ] || relay_missing+=("$name")
done

say "Build plan"
say "  commit:            $(git rev-parse HEAD) ($(git rev-parse --abbrev-ref HEAD))"
say "  base:              $BASE_TAG ($BASE_COMMIT)"
say "  version label:     $label"
say "  SEA Node:          $sea_node_version at $sea_node_dir$([ -x "$sea_node_dir/bin/node" ] || printf ' (will download from nodejs.org, SHA-256 checked)')"
say "  resource monitor:  $resource_monitor_dir (copied)"
say "  archive:           $archive"
if [ ${#relay_missing[@]} -gt 0 ]; then
  say "  T3 Connect relay:  NOT configured (${relay_missing[*]} unset)"
else
  say "  T3 Connect relay:  $T3CODE_RELAY_URL"
fi
if [ ${#relay_missing[@]} -gt 0 ] && ! $without_relay; then
  $dry_run && warn "a real build refuses without relay config; set the variables or pass --without-relay"
  $dry_run || die "relay config missing (${relay_missing[*]}); set it or pass --without-relay"
fi
if $dry_run; then
  say "Dry run: nothing built."
  exit 0
fi

if [ ! -x "$sea_node_dir/bin/node" ]; then
  mkdir -p "$TOOLCHAIN_DIR"
  tarball="node-v$sea_node_version-$target.tar.xz"
  download="$(mktemp -d "$TOOLCHAIN_DIR/.download-XXXXXX")"
  curl -fsSL "https://nodejs.org/dist/v$sea_node_version/$tarball" -o "$download/$tarball"
  curl -fsSL "https://nodejs.org/dist/v$sea_node_version/SHASUMS256.txt" -o "$download/SHASUMS256.txt"
  (cd "$download" && grep " $tarball\$" SHASUMS256.txt | sha256sum -c --quiet -)
  tar -xJf "$download/$tarball" -C "$TOOLCHAIN_DIR"
  rm -rf "$download"
fi

work="$(mktemp -d "${TMPDIR:-/tmp}/t3-agent-credentials-build-XXXXXX")"
cleanup() {
  git -C "$REPO_ROOT" worktree remove --force "$work/src" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT
git worktree add --detach "$work/src" HEAD >/dev/null
cd "$work/src"
vp="$REPO_ROOT/node_modules/.bin/vp"
[ -x "$vp" ] || die "run \`vp install\` in $REPO_ROOT first so vp is available"

say "Installing dependencies..."
"$vp" install --frozen-lockfile
# build-cli-archive and the build tasks spawn the worktree's own vp.
export PATH="$work/src/node_modules/.bin:$PATH"
say "Stamping version $label..."
node scripts/update-release-package-versions.ts "$label"
say "Building web client and server bundle..."
vp run --filter t3 build
say "Building the single executable with Node $sea_node_version..."
PATH="$sea_node_dir/bin:$PATH" node apps/server/scripts/cli.ts build-exe --target "$target"
mkdir -p "$work/resource-monitor"
cp -a "$resource_monitor_dir/." "$work/resource-monitor/"
say "Packing the runtime archive..."
node scripts/build-cli-archive.ts --platform "$platform" --arch "$arch" --version "$label" \
  --resource-monitor-dir "$work/resource-monitor" --output-dir "$work/out"
built="$(find "$work/out" -maxdepth 1 -name '*.tar.gz' -print -quit)"
[ -n "$built" ] || die "build-cli-archive produced no archive"
mkdir -p "$output_dir"
mv "$built" "$archive"
(cd "$output_dir" && sha256sum "$(basename "$archive")" > "$(basename "$archive").sha256")
say "Built $archive"
