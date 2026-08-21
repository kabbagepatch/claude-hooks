#!/usr/bin/env bash
# PreToolUse hook: scans tool input for likely secrets/tokens before the
# tool call (Write | Edit | Bash) is allowed to run.
#
#   exit 0  = allow
#   exit 2  = block (Claude Code treats this as a deny)
#
# SECURITY POSTURE: this hook fails CLOSED. Any unexpected condition --
# missing dependency, unparseable input, an internal error -- blocks the
# call rather than silently allowing it. A broken scanner should never
# be indistinguishable from a clean scan. If you find this too strict
# for your workflow, loosen it deliberately (see FAIL_CLOSED below),
# don't let it degrade by accident.
#
# HARD LIMIT THIS SCRIPT CANNOT FIX: per Claude Code's own hooks
# reference, ONLY exit code 2 blocks a tool call. Any other exit code
# -- including 1, or a launch failure like "Permission denied" (exit
# 126) if this file loses its execute bit -- is treated as a
# NON-BLOCKING error, and the tool call proceeds anyway. That failure
# happens before this script's own code ever runs, so no in-script
# logic can catch it. Mitigate operationally: re-run `chmod +x` after
# any edit to this file, and periodically confirm via Claude Code's
# `/hooks` command that this hook is actually registered and firing.
# There have also been reports of exit-2 itself being ignored in some
# Claude Code versions (proceeding despite a blocking exit code) --
# verify blocking actually works end-to-end on your installed version,
# don't trust this comment or the exit code alone.
#
# INVARIANT: this script never writes a matched secret's actual value to
# any log. Only a stable detector NAME is recorded. If you add a new
# detector, give it a name and log the name, never the pattern or the
# matched text.

# NOTE: no `set -e`. Combined with explicit error handling below, this
# lets us guarantee *every* exit path is a deliberate exit 0 or exit 2,
# rather than trusting a crash to propagate the "right" code. `set -u`
# and `pipefail` are kept since those catch real bugs (unset vars,
# broken pipes) without affecting our exit-code control.
set -u -o pipefail

FAIL_CLOSED=1  # 1 = block on internal errors (recommended). 0 = allow through with a logged warning.
LOGDIR="${HOME}/.claude/security-logs"
BLOCKED_LOG="${LOGDIR}/blocked.jsonl"
ERROR_LOG="${LOGDIR}/scanner-errors.jsonl"

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

# json_escape STR -- escapes a string for safe embedding in a JSON
# string value (backslash, quote, control chars). Never pass secret
# material through this -- it's for detector names / error text only.
json_escape() {
  local s="$1"
  s="${s//\\/\\\\}"
  s="${s//\"/\\\"}"
  s="${s//$'\n'/\\n}"
  s="${s//$'\t'/\\t}"
  printf '%s' "$s"
}

log_event() {
  # log_event LOGFILE EVENT DETECTOR_NAME
  local logfile="$1" event="$2" detector="$3"
  mkdir -p "$LOGDIR" 2>/dev/null || return 0  # logging failure must never block a decision path
  local ts
  ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null) || ts="unknown"
  printf '{"timestamp":"%s","event":"%s","detector":"%s"}\n' \
    "$(json_escape "$ts")" "$(json_escape "$event")" "$(json_escape "$detector")" \
    >> "$logfile" 2>/dev/null || true
}

# die_blocked DETECTOR_NAME -- log and exit 2.
die_blocked() {
  local detector="$1"
  log_event "$BLOCKED_LOG" "secret_scan_block" "$detector"
  printf 'Blocked: tool input matched detector "%s" (likely secret). Review %s. If this is a false positive, adjust secret-scan.sh.\n' \
    "$detector" "$BLOCKED_LOG" >&2
  exit 2
}

# die_error CONTEXT -- an internal/unexpected failure. Fails closed by
# default (see FAIL_CLOSED). This is the "scanner itself is broken"
# path -- distinct from "scanner ran fine and found nothing."
die_error() {
  local context="$1"
  log_event "$ERROR_LOG" "scanner_internal_error" "$context"
  if [[ "$FAIL_CLOSED" -eq 1 ]]; then
    printf 'Blocked: secret scanner hit an internal error (%s) and is configured to fail closed. See %s.\n' \
      "$context" "$ERROR_LOG" >&2
    exit 2
  else
    printf 'Warning: secret scanner hit an internal error (%s) and is configured to fail open -- this call was NOT scanned. See %s.\n' \
      "$context" "$ERROR_LOG" >&2
    exit 0
  fi
}

# ---------------------------------------------------------------------
# Read input
# ---------------------------------------------------------------------

INPUT=$(cat) || die_error "failed to read stdin"
[[ -z "$INPUT" ]] && die_error "empty stdin"

# We scan the raw JSON blob rather than extracting a specific field.
# Tradeoff: simpler and robust to shape differences across tool types,
# at the cost of also scanning JSON structure/keys (harmless -- they
# don't match secret patterns) and any surrounding metadata. If you
# want tighter scoping, extract .tool_input with jq before scanning;
# that adds a hard jq dependency, which is why we don't require it here.
CONTENT="$INPUT"

# ---------------------------------------------------------------------
# High-confidence detectors: vendor-specific prefix + body shape.
# These are safe to hard-block on with very low false-positive risk --
# the prefixes are distinctive enough that legitimate non-secret text
# essentially never collides with them.
# ---------------------------------------------------------------------

declare -A HIGH_CONFIDENCE=(
  [anthropic_api_key]='sk-ant-api03-[A-Za-z0-9_-]{20,}'
  [anthropic_oauth_token]='sk-ant-oat01-[A-Za-z0-9_-]{20,}'
  [openai_project_key]='sk-proj-[A-Za-z0-9_-]{20,}'
  [openai_svcacct_key]='sk-svcacct-[A-Za-z0-9_-]{20,}'
  [openai_admin_key]='sk-admin-[A-Za-z0-9_-]{20,}'
  [openrouter_key]='sk-or-v1-[A-Za-z0-9]{20,}'
  [openai_legacy_key]='sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{0,20}'
  [perplexity_key]='pplx-[A-Za-z0-9]{32,}'
  [replicate_token]='r8_[A-Za-z0-9]{20,}'
  [fireworks_key]='fw_[A-Za-z0-9]{20,}'
  [huggingface_token]='hf_[A-Za-z0-9]{20,}'
  [tavily_key]='tvly-[A-Za-z0-9]{20,}'
  [pinecone_key]='pcsk_[A-Za-z0-9]{30,}'
  [aws_access_key_id]='AKIA[0-9A-Z]{16}'
  [databricks_token]='dapi[0-9a-f]{32,}'
  [google_api_key]='AIza[0-9A-Za-z_-]{35}'
  [github_token]='gh[pousr]_[0-9A-Za-z]{36,}'
  [stripe_live_key]='sk_live_[0-9A-Za-z]{20,}'
  [stripe_test_key]='sk_test_[0-9A-Za-z]{20,}'
  [slack_token]='xox[baprs]-[0-9A-Za-z-]{10,}'
  [pem_private_key]='-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----'
  [jwt_generic]='eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'
)

# ---------------------------------------------------------------------
# Heuristic detectors: pattern-of-usage rather than a distinctive
# prefix (e.g. "api_key: <long string>"). Higher recall, higher
# false-positive risk -- a variable merely NAMED api_key/secret/token
# can trip this even when its value isn't sensitive (test fixtures,
# schema examples, docs). Kept separate from HIGH_CONFIDENCE so you can
# selectively disable this tier without losing vendor-prefix coverage.
# ---------------------------------------------------------------------

HEURISTIC_ENABLED=1

declare -A HEURISTIC=(
  [aws_secret_assignment]='aws_secret_access_key["'\''"]?[[:space:]]*[:=]'
  [generic_credential_assignment]='(api[_-]?key|secret|token|password)[\"'\''"]*[[:space:]]*[:=][[:space:]]*[\"'\''"]*[A-Za-z0-9_/+=-]{16,}'
)

# ---------------------------------------------------------------------
# Scan function: runs an associative array of NAME->PATTERN against a
# given text, returns the matched detector name via stdout (empty if
# no match). Isolated so it can be reused for the plaintext pass and
# the decoded-candidate pass without duplicating logic.
# ---------------------------------------------------------------------

scan_text() {
  local text="$1"
  local -n patterns_ref="$2"
  local name
  for name in "${!patterns_ref[@]}"; do
    if printf '%s' "$text" | grep -E -q -e "${patterns_ref[$name]}" 2>/dev/null; then
      printf '%s' "$name"
      return 0
    fi
  done
  return 1
}

# ---------------------------------------------------------------------
# Pass 1: plaintext, high-confidence detectors
# ---------------------------------------------------------------------

DETECTOR=$(scan_text "$CONTENT" HIGH_CONFIDENCE) && die_blocked "$DETECTOR"

# ---------------------------------------------------------------------
# Pass 2: plaintext, heuristic detectors (skippable)
# ---------------------------------------------------------------------

if [[ "$HEURISTIC_ENABLED" -eq 1 ]]; then
  DETECTOR=$(scan_text "$CONTENT" HEURISTIC) && die_blocked "$DETECTOR"
fi

# ---------------------------------------------------------------------
# Pass 3: bounded base64/hex decode-and-rescan (high-confidence only).
#
# Tradeoff: catches a key that's been base64/hex-wrapped (e.g. stored
# as a Kubernetes-style secret, or piped through `base64 -d`) without
# introducing a new detection strategy -- decoded text still has to
# match a real HIGH_CONFIDENCE pattern to block. Deliberately excludes
# HEURISTIC patterns here: decoding + a loose "looks like an
# assignment" heuristic compounds false-positive risk in a way that
# isn't worth it.
#
# Bounded to MAX_CANDIDATES to keep worst-case latency predictable --
# unbounded candidate extraction on a large diff or binary-heavy file
# scales linearly and can turn a ~100ms check into seconds.
# ---------------------------------------------------------------------

MAX_CANDIDATES=20

decode_and_scan() {
  local content="$1"
  local -a candidates=()
  local candidate decoded count=0

  # Collect base64-looking and hex-looking runs, capped total.
  while IFS= read -r candidate; do
    [[ -z "$candidate" ]] && continue
    candidates+=("$candidate")
    ((count++))
    ((count >= MAX_CANDIDATES)) && break
  done < <(printf '%s' "$content" | grep -oE '[A-Za-z0-9+/]{20,}={0,2}' 2>/dev/null)

  if ((count < MAX_CANDIDATES)); then
    while IFS= read -r candidate; do
      [[ -z "$candidate" ]] && continue
      candidates+=("$candidate")
      ((count++))
      ((count >= MAX_CANDIDATES)) && break
    done < <(printf '%s' "$content" | grep -oE '[0-9a-fA-F]{20,}' 2>/dev/null)
  fi

  for candidate in "${candidates[@]}"; do
    decoded=$(printf '%s' "$candidate" | base64 -d 2>/dev/null) || decoded=""
    if [[ -z "$decoded" ]]; then
      decoded=$(printf '%s' "$candidate" | xxd -r -p 2>/dev/null) || decoded=""
    fi
    [[ -z "$decoded" ]] && continue

    # Only rescan if the decode is printable text -- binary output
    # (images, compressed data) cannot contain a plaintext key pattern,
    # so rescanning it is pure wasted latency.
    if printf '%s' "$decoded" | grep -q -aE '^[[:print:][:space:]]+$' 2>/dev/null; then
      local name
      name=$(scan_text "$decoded" HIGH_CONFIDENCE) && { printf '%s' "$name"; return 0; }
    fi
  done
  return 1
}

# Decode step is best-effort: if base64/xxd aren't available, skip this
# pass rather than treating it as a fatal error (it's a supplementary
# check, not core coverage -- plaintext detection above still applies).
if command -v base64 >/dev/null 2>&1; then
  DETECTOR=$(decode_and_scan "$CONTENT") && die_blocked "${DETECTOR} (found after base64/hex decode)"
fi

# ---------------------------------------------------------------------
# No match -- allow.
# ---------------------------------------------------------------------

exit 0
