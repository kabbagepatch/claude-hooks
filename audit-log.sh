#!/usr/bin/env bash
# Audit hook: logs one slim JSON line per hook event for visibility ("what's
# being called, by whom, and what was denied or failed").
#
# Register it with "async": true and matcher "*" on PreToolUse, PostToolUse,
# PostToolUseFailure, PermissionRequest and PermissionDenied. The payload's
# own hook_event_name tells the events apart.
#
# Writes to ~/.claude/security-logs/audit-YYYY-MM.jsonl (UTC month).
# Bodies are trimmed by audit-slim.jq, which must sit next to this script
# (a symlink to this script is fine).
#
# Never fails the hook: every path ends in exit 0.

set -uo pipefail

INPUT=$(cat)

LOGDIR="${CLAUDE_AUDIT_LOG_DIR:-${HOME}/.claude/security-logs}"
mkdir -p "$LOGDIR" 2>/dev/null || exit 0

# Milliseconds need GNU date; fall back to whole seconds elsewhere.
TS=$(date -u +"%Y-%m-%dT%H:%M:%S.%3NZ" 2>/dev/null)
case "$TS" in
  *N*|"") TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ") ;;
esac
LOGFILE="${LOGDIR}/audit-${TS:0:7}.jsonl"

SELF=$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")
FILTER="$(dirname "$SELF")/audit-slim.jq"

ENTRY=""
if command -v jq >/dev/null 2>&1; then
  ENTRY=$(jq -c --arg ts "$TS" -f "$FILTER" <<< "$INPUT" 2>/dev/null) || ENTRY=""
  if [ -z "$ENTRY" ]; then
    # Filter missing or payload not JSON: keep a bounded, valid record.
    ENTRY=$(jq -Rsc --arg ts "$TS" \
      '{logged_at: $ts, audit_error: "unparsed payload", raw_bytes: utf8bytelength, raw: .[0:2000]}' \
      <<< "$INPUT" 2>/dev/null) || ENTRY=""
  fi
fi
if [ -z "$ENTRY" ]; then
  ENTRY=$(printf '{"logged_at":"%s","audit_error":"jq unavailable","raw_bytes":%d}' "$TS" "${#INPUT}")
fi

# One short line per append keeps concurrent async hooks from interleaving.
printf '%s\n' "$ENTRY" >> "$LOGFILE" 2>/dev/null

exit 0
