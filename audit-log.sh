#!/usr/bin/env bash
# PostToolUse hook: logs every tool call for visibility ("what's being
# called, by whom"). Matched broadly (*) in settings.json since it's
# async and doesn't block execution -- breadth doesn't cost latency here.
#
# Writes one JSON line per tool call to ~/.claude/security-logs/audit.jsonl

set -euo pipefail

INPUT=$(cat)
LOGDIR="${HOME}/.claude/security-logs"
mkdir -p "$LOGDIR"
TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Extract tool_name if jq is available; fall back to raw blob otherwise
# so the hook never fails just because jq is missing.
if command -v jq >/dev/null 2>&1; then
  TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // "unknown"' 2>/dev/null || echo "unknown")
  ENTRY=$(jq -c --arg ts "$TS" '. + {logged_at: $ts}' <<< "$INPUT" 2>/dev/null || echo "{\"timestamp\":\"$TS\",\"raw\":$INPUT}")
  echo "$ENTRY" >> "${LOGDIR}/audit.jsonl"
else
  printf '{"timestamp":"%s","raw":%s}\n' "$TS" "$INPUT" >> "${LOGDIR}/audit.jsonl"
fi

exit 0

