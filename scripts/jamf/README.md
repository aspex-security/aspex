# Aspex - Jamf Integration

Three scripts for deploying aspex-scan and aspex-doctor across a managed macOS fleet via Jamf Pro.

## Scripts

| Script | Type | Purpose |
|--------|------|---------|
| `ea-aspex-scan.sh` | Extension Attribute | Inventory: score + finding counts |
| `ea-aspex-doctor.sh` | Extension Attribute | Inventory: health status per category |
| `policy-aspex-scan.sh` | Policy Script | Scheduled full scan with optional webhook |

---

## Extension Attributes

Extension Attributes run on-demand or at inventory update. The result is stored against the device record in Jamf and can be used in Smart Group criteria.

### ea-aspex-scan

**Example output stored in Jamf:**
```
SCORE=72 CRITICAL=2 HIGH=5 MEDIUM=3 LOW=1 SERVERS=8
```

**Smart Group examples:**
| Group Name | Criteria |
|---|---|
| Aspex - Critical Findings | `aspex-scan` like `CRITICAL=[^0]*` |
| Aspex - Score Below 70 | `aspex-scan` like `SCORE=[0-6]*` |
| Aspex - Not Installed | `aspex-scan` is `NOT_INSTALLED` |

### ea-aspex-doctor

**Example output stored in Jamf:**
```
FAIL CLIENTS=3 ENV_SECRETS=0 CONFIG_SECRETS=1 FS_ISSUES=0 NETWORK=1
```

**Smart Group examples:**
| Group Name | Criteria |
|---|---|
| Aspex Doctor - Failing | `aspex-doctor` like `FAIL*` |
| Aspex Doctor - Hardcoded Secrets | `aspex-doctor` like `* CONFIG_SECRETS=[^0]*` |
| Aspex Doctor - HTTP Servers | `aspex-doctor` like `* NETWORK=[^0]*` |

### Setup (both EAs)

1. Jamf Pro - Computers - Management Framework - Extension Attributes - **New**
2. **Display Name:** `aspex-scan` (or `aspex-doctor`)
3. **Data Type:** String
4. **Inventory Display:** General (or create an "AI Security" category)
5. **Input Type:** Script
6. Paste the script contents
7. Save

---

## Policy Script: Scheduled Full Scan

`policy-aspex-scan.sh` runs a full scan on a schedule, writes a JSON log to `/Library/Logs/Onyx/aspex-scan-<username>.json`, and optionally posts findings to a Slack/webhook URL.

### Setup

1. **Jamf Pro - Computers - Policies - New**
2. **General tab:**
   - Display Name: `Aspex - Weekly MCP Scan`
   - Enabled: checked
   - Trigger: Recurring Check-In
   - Execution Frequency: Once every week
3. **Scripts tab:**
   - Add `policy-aspex-scan.sh`
   - Parameter 4: Webhook URL (optional - Slack `hooks.slack.com/...` or generic endpoint)
   - Parameter 5: Minimum severity to notify on (`critical` / `high` / `medium`, default: `high`)
4. **Scope tab:**
   - Target Computers: Smart Group `Aspex - Not Installed` excluded (or scoped to group where it IS installed)
5. Save

### Log collection (optional)

To pull the JSON results back into Jamf for deeper reporting:

1. Computers - Management Framework - **File Collection**
2. Add path: `/Library/Logs/Onyx/aspex-scan-*.json`
3. Collect at inventory update

---

## Installation prerequisite

Aspex must be installed on managed machines before these scripts run. Use a Jamf policy to install via Homebrew or deploy the pkg:

```bash
# Option A: Homebrew (if Homebrew is managed)
brew install aspex-security/tap/aspex

# Option B: Direct install script
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/aspex-security/aspex/main/install.sh)"
```

The scripts check all common install locations (`/usr/local/bin`, `/opt/homebrew/bin`) and return `NOT_INSTALLED` gracefully if the binary is missing.

---

## How the user context works

Jamf policy scripts run as **root**. MCP client configs live in the logged-in user's home directory (`~/Library/Application Support/...`). The scripts use:

```bash
LOGGED_IN_USER=$(stat -f "%Su" /dev/console)
LOGGED_IN_UID=$(id -u "$LOGGED_IN_USER")
launchctl asuser "$LOGGED_IN_UID" sudo -u "$LOGGED_IN_USER" aspex-scan --json
```

`launchctl asuser` gives the subprocess the user's full session environment — same as if the user ran it from Terminal. This is the correct approach for accessing per-user configs from a root context on macOS.

The scripts skip gracefully (`NO_USER`) when no user is logged in (e.g. during provisioning or at the login window).
