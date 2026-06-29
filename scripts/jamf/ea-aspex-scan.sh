#!/bin/bash
# Jamf Extension Attribute: aspex-scan
#
# Returns a summary string for Jamf inventory:
#   SCORE=72 CRITICAL=2 HIGH=5 SERVERS=8
#   NOT_INSTALLED
#   NO_USER
#   ERROR
#
# Smart Group criteria examples:
#   "aspex-scan EA" like "CRITICAL=[^0]"   -> machines with any critical finding
#   "aspex-scan EA" like "SCORE=*"         -> machines where scan ran successfully
#   "aspex-scan EA" = "NOT_INSTALLED"      -> machines missing the binary
#
# Setup in Jamf Pro:
#   Computers > Management Framework > Extension Attributes > New
#   Data Type: String
#   Input Type: Script
#   Paste this script.

set -euo pipefail

BINARY_NAMES=("aspex-scan")
SEARCH_PATHS=("/usr/local/bin" "/opt/homebrew/bin" "/opt/local/bin")
TIMEOUT_SECS=120

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
# Identify the logged-in user (GUI session owner)
# --------------------------------------------------------------------------
LOGGED_IN_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)

if [[ -z "$LOGGED_IN_USER" || "$LOGGED_IN_USER" == "root" || "$LOGGED_IN_USER" == "loginwindow" ]]; then
    echo "<result>NO_USER</result>"
    exit 0
fi

LOGGED_IN_UID=$(id -u "$LOGGED_IN_USER" 2>/dev/null) || { echo "<result>ERROR uid_lookup</result>"; exit 0; }

# --------------------------------------------------------------------------
# Run aspex-scan --json as the logged-in user
# launchctl asuser gives the user's environment (keychain, HOME, etc.)
# --------------------------------------------------------------------------
JSON=$(launchctl asuser "$LOGGED_IN_UID" \
    sudo -u "$LOGGED_IN_USER" \
    /usr/bin/timeout "$TIMEOUT_SECS" \
    "$BINARY" --json 2>/dev/null) || { echo "<result>ERROR scan_failed</result>"; exit 0; }

if [[ -z "$JSON" ]]; then
    echo "<result>ERROR empty_output</result>"
    exit 0
fi

# --------------------------------------------------------------------------
# Parse JSON with python3 (ships with macOS, no jq dependency)
# --------------------------------------------------------------------------
SUMMARY=$(python3 - "$JSON" <<'PYEOF'
import sys, json

try:
    data = json.loads(sys.argv[1])
except Exception as e:
    print(f"ERROR json_parse")
    sys.exit(0)

score    = data.get("score", 0)
findings = data.get("findings", [])
servers  = len(data.get("servers", []))

counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
for f in findings:
    sev = str(f.get("severity", "")).upper()
    if sev in counts:
        counts[sev] += 1

print(f"SCORE={score} CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} MEDIUM={counts['MEDIUM']} LOW={counts['LOW']} SERVERS={servers}")
PYEOF
)

echo "<result>${SUMMARY}</result>"
