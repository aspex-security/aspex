#!/bin/bash
# Jamf Policy Script: aspex-scan scheduled scan
#
# Runs aspex-scan as the logged-in user, writes results to a per-user log
# that Jamf can collect via a File Collection policy, and optionally posts
# findings to a Slack/webhook URL.
#
# Jamf policy configuration:
#   Frequency:   Weekly (or Daily for high-risk environments)
#   Trigger:     Recurring check-in
#   Scope:       Machines with aspex-scan installed (Smart Group: "aspex-scan EA" != "NOT_INSTALLED")
#   Parameters:
#     $4 = Webhook URL (optional, Slack or generic JSON endpoint)
#     $5 = Minimum severity to notify on (critical|high|medium|low, default: high)
#
# Log output location (collected by Jamf File Collection or read by other EAs):
#   /Library/Logs/Onyx/aspex-scan-<username>.json
#
# Exit codes:
#   0  Success (scan ran, even if findings were found)
#   1  Binary not installed
#   2  No logged-in user
#   3  Scan execution failed

set -euo pipefail

BINARY_NAMES=("aspex-scan")
SEARCH_PATHS=("/usr/local/bin" "/opt/homebrew/bin" "/opt/local/bin")
TIMEOUT_SECS=120
LOG_DIR="/Library/Logs/Onyx"
WEBHOOK_URL="${4:-}"          # Jamf parameter $4
MIN_SEVERITY="${5:-high}"     # Jamf parameter $5

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

BINARY=$(find_binary) || {
    echo "aspex-scan not found in PATH. Install via: brew install aspex-security/tap/aspex"
    exit 1
}

# --------------------------------------------------------------------------
# Identify the logged-in user
# --------------------------------------------------------------------------
LOGGED_IN_USER=$(stat -f "%Su" /dev/console 2>/dev/null || true)

if [[ -z "$LOGGED_IN_USER" || "$LOGGED_IN_USER" == "root" || "$LOGGED_IN_USER" == "loginwindow" ]]; then
    echo "No user logged in - skipping scan"
    exit 2
fi

LOGGED_IN_UID=$(id -u "$LOGGED_IN_USER")
echo "Running aspex-scan for user: $LOGGED_IN_USER (uid=$LOGGED_IN_UID)"

# --------------------------------------------------------------------------
# Prepare output directory
# --------------------------------------------------------------------------
mkdir -p "$LOG_DIR"
LOG_FILE="$LOG_DIR/aspex-scan-${LOGGED_IN_USER}.json"

# --------------------------------------------------------------------------
# Build scan args
# --------------------------------------------------------------------------
SCAN_ARGS=("--json")
if [[ -n "$WEBHOOK_URL" ]]; then
    SCAN_ARGS+=("--notify" "$WEBHOOK_URL" "--fail-on" "$MIN_SEVERITY")
fi

# --------------------------------------------------------------------------
# Run the scan as the logged-in user
# --------------------------------------------------------------------------
echo "Starting scan (timeout: ${TIMEOUT_SECS}s)..."
START_TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

JSON=$(launchctl asuser "$LOGGED_IN_UID" \
    sudo -u "$LOGGED_IN_USER" \
    /usr/bin/timeout "$TIMEOUT_SECS" \
    "$BINARY" "${SCAN_ARGS[@]}" 2>&1) || SCAN_EXIT=$?

if [[ -z "$JSON" ]]; then
    echo "Scan produced no output"
    exit 3
fi

# Wrap raw output with metadata so Jamf log collection has context.
python3 - "$JSON" "$START_TS" "$LOGGED_IN_USER" "$LOG_FILE" <<'PYEOF'
import sys, json

raw        = sys.argv[1]
started_at = sys.argv[2]
username   = sys.argv[3]
out_path   = sys.argv[4]

try:
    data = json.loads(raw)
except Exception:
    # aspex-scan returned non-JSON (error message) - store as-is for debugging
    wrapper = {
        "meta": {"tool": "aspex-scan", "started_at": started_at, "user": username, "parse_error": True},
        "raw": raw,
    }
    with open(out_path, "w") as f:
        json.dump(wrapper, f, indent=2)
    print(f"Warning: scan output was not valid JSON - stored raw in {out_path}")
    sys.exit(0)

findings = data.get("findings", [])
score    = data.get("score", 0)

crit  = sum(1 for f in findings if str(f.get("severity","")).upper() == "CRITICAL")
high  = sum(1 for f in findings if str(f.get("severity","")).upper() == "HIGH")

wrapper = {
    "meta": {
        "tool":       "aspex-scan",
        "started_at": started_at,
        "user":       username,
    },
    "score":          score,
    "total_findings": len(findings),
    "critical":       crit,
    "high":           high,
    "findings":       findings,
    "servers":        data.get("servers", []),
}

with open(out_path, "w") as f:
    json.dump(wrapper, f, indent=2)

print(f"Scan complete: score={score} critical={crit} high={high} total={len(findings)}")
print(f"Results written to: {out_path}")
PYEOF

exit 0
