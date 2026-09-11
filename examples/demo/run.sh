#!/bin/sh
# Aspex demo: a fake environment, real analysis, nothing executed or sent.
# The demo home is copied to a temporary directory and its placeholder paths
# are rewritten to that directory, so the "home-scoped filesystem server"
# really is scoped to $HOME and classifies as sensitive, exactly as it would
# on a real machine.
set -e
DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/aspex-demo.XXXXXX")"
cp -R "$DIR/home/." "$TMP/"
# Rewrite placeholders (portable sed: write to temp file, move back).
find "$TMP" -type f \( -name '*.json' -o -name '*.jsonl' -o -name '*.md' \) | while IFS= read -r f; do
  sed "s|__DEMO_HOME__|$TMP|g" "$f" > "$f.tmp" && mv "$f.tmp" "$f"
done
# Claude Code keys project logs by the project path; rename the demo project dir accordingly.
PROJ_KEY="$(printf '%s' "$TMP/projects/acme" | sed 's|/|-|g')"
mv "$TMP/.claude/projects/-Users-demo-projects-acme" "$TMP/.claude/projects/$PROJ_KEY"
mkdir -p "$TMP/projects/acme"
export HOME="$TMP"
BIN="${ASPEX_SCAN:-aspex-scan}"
TRACE="${ASPEX_TRACE:-aspex-trace}"
step() { printf '\n\033[1m$ %s\033[0m\n' "$*"; }

step "aspex scan --no-exec        # what CAN happen"
"$BIN" --no-exec --clients claude-code || true

step 'aspex explain "Can this agent leak AWS credentials?"'
"$BIN" explain --no-exec --clients claude-code "Can this agent leak AWS credentials?" || true

step "aspex explain AP003         # the persistence path, defined and applied here"
"$BIN" explain --no-exec --clients claude-code AP003 || true

step "aspex simulate --restrict-filesystem filesystem=$TMP/projects/acme   # WHAT IF"
"$BIN" simulate --no-exec --clients claude-code --restrict-filesystem "filesystem=$TMP/projects/acme" || true

step "aspex trace provenance --since 3650d   # what DID happen"
"$TRACE" provenance --since 3650d --client claude-code || true

printf '\nNext: HOME=%s aspex-scan explore --since 3650d   (opens the local explorer on 127.0.0.1)\n' "$TMP"
printf 'Demo home: %s (delete it when done)\n' "$TMP"
