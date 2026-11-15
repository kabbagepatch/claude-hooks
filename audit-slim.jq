# audit-slim.jq -- shrink one Claude Code hook payload to an audit record.
#
# Used by audit-log.sh (live hook) and audit-compact.sh (one-off rewrite of
# old logs), so old and new records have the same shape.
#
# What it does:
#   - records the original size of tool_input / tool_response as
#     input_bytes / response_bytes, before anything is removed
#   - drops body-carrying keys (file contents, edit strings, patches) and
#     leaves their sizes behind in a sibling "_dropped" object
#   - cuts long strings and long arrays, marking every cut inline
#   - stamps logged_at from --arg ts when the record has none
#
# Running it on an already-slim record changes nothing.

# Keys whose values are bodies we never want to keep, at any depth.
def heavy_keys:
  ["originalFile", "structuredPatch", "content", "file_content",
   "old_string", "new_string", "oldString", "newString"];

# A value that already carries a cut marker is left alone, so a second pass
# never cuts the marker itself.
def cut($n):
  if type == "string" and length > $n and (test("…\\[\\+[0-9]+ chars\\]$") | not)
  then .[0:$n] + "…[+\(length - $n) chars]"
  else . end;

def cut_items($n):
  if type == "array" and length > $n
     and ((.[-1] | type) != "string" or (.[-1] | test("^…\\[\\+[0-9]+ items\\]$") | not))
  then .[0:$n] + ["…[+\(length - $n) items]"]
  else . end;

# "_dropped" maps each removed key to the byte size of its value. It is not
# descended into, since its own keys are the heavy key names.
def drop_heavy:
  if type == "object" then
    with_entries(if .key == "_dropped" then . else .value |= drop_heavy end)
    | . as $o
    | [heavy_keys[] | select(. as $k | $o | has($k))] as $hit
    | if ($hit | length) == 0 then .
      else
        reduce $hit[] as $k (.; del(.[$k]))
        | ._dropped = (($o._dropped // {})
            + ($hit | map({key: ., value: ($o[.] | tojson | utf8bytelength)}) | from_entries))
      end
  elif type == "array" then map(drop_heavy)
  else . end;

# General limits for anything inside tool_input / tool_response.
def slim_body:
  drop_heavy
  | walk(if type == "string" then cut(200)
         elif type == "array" then cut_items(50)
         else . end);

# Fields that get a larger limit than the general one. They are lifted out
# before slim_body runs and put back afterwards.
def keep_long($path; $n):
  (getpath($path)? // null) as $v
  | if ($v | type) == "string" then {path: $path, value: ($v | cut($n))} else empty end;

($ARGS.named.ts // "") as $ts
| [ keep_long(["tool_input", "command"]; 4000),
    keep_long(["tool_response", "stderr"]; 2000) ] as $long
| if has("tool_input") and (has("input_bytes") | not)
  then .input_bytes = (.tool_input | tojson | utf8bytelength) else . end
| if has("tool_response") and (has("response_bytes") | not)
  then .response_bytes = (.tool_response | tojson | utf8bytelength) else . end
| if has("tool_input") then .tool_input |= slim_body else . end
| if has("tool_response") then .tool_response |= slim_body else . end
| reduce $long[] as $l (.; setpath($l.path; $l.value))
# Everything else (error text, permission suggestions, raw fallbacks, ...).
| with_entries(
    if .key == "tool_input" or .key == "tool_response" then .
    else .value |= walk(if type == "string" then cut(2000)
                        elif type == "array" then cut_items(50)
                        else . end)
    end)
| if $ts != "" and ((.logged_at // "") == "") then .logged_at = $ts else . end
