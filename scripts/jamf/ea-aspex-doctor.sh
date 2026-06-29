#!/bin/bash
# Jamf Extension Attribute: aspex-doctor
#
# Returns a summary string for Jamf inventory:
#   PASS CLIENTS=3 ENV_SECRETS=0 CONFIG_SECRETS=0 FS_ISSUES=0 NETWORK=0
#   WARN CLIENTS=3 ENV_SECRETS=2 CONFIG_SECRETS=0 FS_ISSUES=1 NETWORK=0
#   FAIL CLIENTS=2 ENV_SECRETS=0 CONFIG_SECRETS=1 FS_ISSUES=0 NETWORK=1
#   NOT_INSTALLED
#   NO_USER
#   ERROR
#
# Smart Group criteria examples:
#   "aspex-doctor EA" like "FAIL*"                -> machines with critical health issues
#   "aspex-doctor EA" like "* CONFIG_SECRETS=[^0]" -> machines with hardcoded credentials
#   "aspex-doctor EA" like "* NETWORK=[^0]"        -> machines with HTTP remote servers
#
# Setup in Jamf Pro:
#   Computers > Management Framework > Extension Attributes > New
#   Data Type: String
#   Input Type: Script
#   Paste this script.

set -euo pipefail

BINARY_NAMES=("aspex-doctor")
SEARCH_PATHS=("/usr/local/bin" "/opt/homebrew/bin" "/opt/local/bin")
TIMEOUT_SECS=60

# --------------------------------------------------------------------------
# Find binary
# --------------------------------------------------------------------------
find_binary() {
    for name in "${BINARY_NAMES[@]}"; do
        for dir in "${SEARCH_PATHS[@]}"; do
            if [[ -x "$dir/$name" ]]; then
                echo "$dir/$name"
                return 0
            fi
        done
    done
    return 1
}

BINARY=$(find_binary) || { echo "<result>NOT_INSTALLED</result>"; exit 0; }

# --------------------------------------------------------------------------
# Identify the logged-in user
# --------------------------------------------------------------------------
LOGGED_IN_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)

if [[ -z "$LOGGED_IN_USER" || "$LOGGED_IN_USER" == "root" || "$LOGGED_IN_USER" == "loginwindow" ]]; then
    echo "<result>NO_USER</result>"
    exit 0
fi

LOGGED_IN_UID=$(id -u "$LOGGED_IN_USER" 2>/dev/null) || { echo "<result>ERROR uid_lookup</result>"; exit 0; }

# --------------------------------------------------------------------------
# Run aspex-doctor --json as the logged-in user
# --------------------------------------------------------------------------
JSON=$(launchctl asuser "$LOGGED_IN_UID" \
    sudo -u "$LOGGED_IN_USER" \
    /usr/bin/timeout "$TIMEOUT_SECS" \
    "$BINARY" --json 2>/dev/null) || { echo "<result>ERROR doctor_failed</result>"; exit 0; }

if [[ -z "$JSON" ]]; then
    echo "<result>ERROR empty_output</result>"
    exit 0
fi

# --------------------------------------------------------------------------
# Parse JSON
# --------------------------------------------------------------------------
SUMMARY=$(python3 - "$JSON" <<'PYEOF'
import sys, json

try:
    data = json.loads(sys.argv[1])
except Exception:
    print("ERROR json_parse")
    sys.exit(0)

findings  = data.get("findings", [])
clients   = data.get("clients_found", 0)

cats = {
    "env_secrets":     0,
    "config_secrets":  0,
    "filesystem":      0,
    "network":         0,
}

for f in findings:
    cat = str(f.get("category", "")).lower()
    sev = str(f.get("severity", "")).upper()
    if "env" in cat:
        cats["env_secrets"] += 1
    elif "config" in cat or "secret" in cat:
        cats["config_secrets"] += 1
    elif "file" in cat or "path" in cat or "fs" in cat:
        cats["filesystem"] += 1
    elif "network" in cat or "http" in cat:
        cats["network"] += 1

# Overall status: FAIL if any critical/high, WARN if any medium/low, else PASS
status = "PASS"
for f in findings:
    sev = str(f.get("severity", "")).upper()
    if sev in ("CRITICAL", "HIGH"):
        status = "FAIL"
        break
    elif sev in ("MEDIUM", "LOW", "WARNING", "WARN"):
        if status == "PASS":
            status = "WARN"

print(
    f"{status} "
    f"CLIENTS={clients} "
    f"ENV_SECRETS={cats['env_secrets']} "
    f"CONFIG_SECRETS={cats['config_secrets']} "
    f"FS_ISSUES={cats['filesystem']} "
    f"NETWORK={cats['network']}"
)
PYEOF
)

echo "<result>${SUMMARY}</result>"
