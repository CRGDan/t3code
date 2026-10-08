# Shared by build.sh, install.sh and rollback.sh. Sourced, not run.
#
# The pinned agent-credentials build is upstream BASE_TAG plus this branch's
# protected-authentication patch. Its version label is BASE_VERSION+ac.<n>;
# the `+ac.` build metadata is what makes the server refuse remote self-update
# (apps/server/src/cloud/selfUpdate.ts), so only these scripts move it.

BASE_TAG="v0.0.46-nightly.20261008.2833"
BASE_COMMIT="a6ec88f7a716fc421bd22c2484881c44110f9375"
BASE_VERSION="0.0.46-nightly.20261008.2833"
DEFAULT_BUILD_NUMBER=1

# Matches EXACT_SERVICE_VERSION in apps/server/src/cloud/serviceProtocol.ts for this base.
LABEL_PATTERN='^0\.0\.46-nightly\.20261008\.2833\+ac\.[1-9][0-9]*$'

T3_HOME="${T3CODE_HOME:-$HOME/.t3}"
RUNTIME_DIR="$T3_HOME/runtime"
STATE_FILE="$RUNTIME_DIR/service-state.json"
VERSIONS_DIR="$RUNTIME_DIR/versions"
# Install records and saved launcher state live beside the runtime, never in userdata.
RECORD_DIR="$RUNTIME_DIR/agent-credentials"
SERVICE_UNIT="t3code.service"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TOOLCHAIN_DIR="${AGENT_CREDENTIALS_TOOLCHAIN_DIR:-$HOME/.cache/t3-agent-credentials/toolchain}"

say() { printf '%s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

# Reads one top-level string field of a JSON file with the host's node.
json_field() {
  node -e 'const v = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]];
if (typeof v === "string") process.stdout.write(v);' "$1" "$2"
}

# Prints "status" of the state file's update record, or nothing.
state_update_status() {
  node -e 'const s = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8"));
process.stdout.write(s.update && typeof s.update.status === "string" ? s.update.status : "");' "$1"
}

service_active() {
  command -v systemctl >/dev/null 2>&1 && systemctl --user is-active --quiet "$SERVICE_UNIT"
}
