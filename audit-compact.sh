#!/usr/bin/env bash
# One-off: rewrite an old, full-body audit log into slim monthly files, using
# the same filter as the live hook (audit-slim.jq, next to this script).
#
#   audit-compact.sh <old-audit.jsonl> <output-dir>
#
# Writes <output-dir>/audit-YYYY-MM.jsonl, one file per UTC month of
# logged_at. Records with no usable logged_at go to audit-unknown.jsonl.
# Lines that are not valid JSON are kept as {"raw": "..."} records, cut to
# 2000 characters.
#
# The input file is never modified. The output directory must not already
# hold audit-*.jsonl files, so a second run cannot double-append.

set -euo pipefail

if [ "$#" -ne 2 ]; then
  echo "usage: $(basename "$0") <old-audit.jsonl> <output-dir>" >&2
  exit 2
fi

SRC=$1
OUT=$2
FILTER="$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/audit-slim.jq"

[ -f "$SRC" ] || { echo "no such file: $SRC" >&2; exit 1; }
[ -f "$FILTER" ] || { echo "filter not found: $FILTER" >&2; exit 1; }

mkdir -p "$OUT"
if compgen -G "$OUT/audit-*.jsonl" >/dev/null; then
  echo "refusing: $OUT already contains audit-*.jsonl files" >&2
  exit 1
fi

jq -Rc '. as $line | try fromjson catch {raw: $line}' "$SRC" \
  | jq -c -f "$FILTER" \
  | jq -r '"\((.logged_at // "") | if test("^[0-9]{4}-[0-9]{2}") then .[0:7] else "unknown" end)\t\(tojson)"' \
  | awk -v dir="$OUT" '{
      i = index($0, "\t")
      file = dir "/audit-" substr($0, 1, i - 1) ".jsonl"
      print substr($0, i + 1) >> file
    }'

in_lines=$(wc -l < "$SRC")
out_lines=$(cat "$OUT"/audit-*.jsonl | wc -l)
in_bytes=$(wc -c < "$SRC")
out_bytes=$(cat "$OUT"/audit-*.jsonl | wc -c)

echo "records: $in_lines in, $out_lines out"
echo "bytes:   $in_bytes in, $out_bytes out"
wc -lc "$OUT"/audit-*.jsonl

if [ "$in_lines" -ne "$out_lines" ]; then
  echo "record count mismatch; keep the original" >&2
  exit 1
fi
