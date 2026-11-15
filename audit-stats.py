#!/usr/bin/env python3
"""Load Claude Code audit logs into SQLite and print usage statistics.

The logs are the audit-YYYY-MM.jsonl files written by audit-log.sh (slim
records, see audit-slim.jq). Loading is incremental: each run reads only the
bytes appended since the last one.

    audit-stats.py report                 # sync, then print the report
    audit-stats.py report --since 2026-11-01 --top 15
    audit-stats.py report --save report.md   # write the report as Markdown
    audit-stats.py sessions               # the 15 most recent sessions
    audit-stats.py sessions --last 30 --flagged
    audit-stats.py sessions --show 987f7d1f   # every call of one session
    audit-stats.py sync                   # only load new records
    sqlite3 ~/.claude/security-logs/audit.db   # ad hoc queries

Tables:
    events    one row per log record; `raw` holds the full slim JSON
    programs  one row per program invoked by a Bash command
    net       one row per network host seen, with `kind`:
                denied   sandbox blocked an outbound connection (from stderr)
                allowed  host requested through allowed_domains
                url      host of a URL in a Bash command
                fetch    host of a WebFetch url
    files     load progress per log file

Standard library only.
"""

import argparse
import contextlib
import json
import os
import re
import shlex
import sqlite3
import sys
from collections import Counter
from datetime import datetime
from functools import partial
from pathlib import Path

DEFAULT_DIR = Path.home() / ".claude" / "security-logs"

HOME = str(Path.home())

# ------------------------------------------------------------ what to watch
#
# Edit these lists to change what the "Watched zones" and "Risky commands"
# report sections flag. They are applied when the report runs, so a change
# takes effect on the next report without reloading any logs.

# Places Claude should rarely touch. "~" is the home directory. A prefix
# matches that path and everything under it. The first matching zone wins,
# so specific places come before general ones.
WATCHED_ZONES = [
    ("Windows drives (/mnt)", ["/mnt"]),
    ("Keys and credentials", [
        "~/.ssh", "~/.gnupg", "~/.aws", "~/.azure", "~/.kube", "~/.docker",
        "~/.config/gcloud", "~/.config/gh", "~/.netrc", "~/.npmrc", "~/.pypirc",
        "~/.git-credentials",
    ]),
    ("Claude settings and hooks", [
        "~/.claude/settings.json", "~/.claude/settings.local.json", "~/.claude/hooks",
        "~/.claude/CLAUDE.md", "~/.claude.json", "/etc/claude-code",
    ]),
    ("Claude audit logs", ["~/.claude/security-logs"]),
    ("Shell and git startup files", [
        "~/.bashrc", "~/.bash_profile", "~/.profile", "~/.zshrc", "~/.zprofile",
        "~/.gitconfig", "~/.config/git",
    ]),
    ("System directories", ["/etc", "/root", "/boot", "/var/lib", "/var/spool"]),
]

# A project's own .claude/settings*.json and .claude/hooks count as
# "Claude settings and hooks" wherever the project lives.
PROJECT_CLAUDE_CONFIG = re.compile(r"/\.claude/(settings(\.local)?\.json$|hooks(/|$))")

# Anything else under the home directory is flagged as HOME_ZONE unless it is
# inside a project (any directory a logged session ran in) or listed here.
HOME_ZONE = "Home, outside projects"
HOME_ALLOWED = [
    "~/.claude",  # plans, memory, skills; the sensitive parts are zones above
    "~/.agents",  # installed agent skills and their scripts
]

# Bash commands worth a second look: (label, programs, pattern). The pattern
# is matched against the program's arguments, after quotes are removed.
GIT = r"^(?:-[Cc]\s+\S+\s+|--no-pager\s+)*"  # options git allows before the subcommand
RISKY_COMMANDS = [
    ("Recursive delete (rm -r)", {"rm"}, r"(^|\s)(-[A-Za-z]*[rR][A-Za-z]*|--recursive)(\s|$)"),
    ("git push --force", {"git"}, GIT + r"push\b.*(--force|\s-f(\s|$))"),
    ("git push", {"git"}, GIT + r"push\b"),
    ("git reset --hard", {"git"}, GIT + r"reset\b.*--hard"),
    ("git clean", {"git"}, GIT + r"clean\b"),
    ("git discard changes (restore, checkout --)", {"git"}, GIT + r"(restore\b|checkout\s+(--(\s|$)|\.(\s|$)))"),
    ("git skip hooks (--no-verify)", {"git"}, r"--no-verify\b"),
    ("GitHub writes (gh)", {"gh"}, r"^(pr|issue|release|repo|gist)\s+(create|merge|close|delete|comment|edit|review)\b"),
    ("Publish a package or image", {"npm", "pnpm", "yarn", "cargo", "twine", "docker"}, r"^(publish|upload|push)\b"),
    ("curl / wget sending data", {"curl", "wget"},
     r"(^|\s)(-d|--data\S*|-F|--form|-T|--upload-file|--post-data\S*|-X\s*(POST|PUT|PATCH|DELETE))(\s|=|$)"),
    ("Remote shell or copy (ssh, scp, rsync, sftp)", {"ssh", "scp", "rsync", "sftp"}, r""),
    ("Infrastructure changes (terraform, kubectl)", {"terraform", "kubectl"}, r"^(apply|destroy|delete)\b"),
    ("Database drop or truncate", {"psql", "mysql", "sqlite3"}, r"(?i)\b(drop\s+(table|database|schema)|truncate\s)"),
    ("Recursive or wide-open permissions (chmod, chown)", {"chmod", "chown"}, r"(^|\s)(-R|--recursive|[0-7]?777)(\s|$)"),
    ("Kill processes", {"kill", "pkill", "killall"}, r""),
    ("System control (systemctl, crontab, shutdown, dd, mkfs)",
     {"systemctl", "crontab", "shutdown", "reboot", "dd", "mkfs"}, r""),
]
SUDO_LABEL = "sudo"
PIPE_TO_SHELL_LABEL = "Download piped into a shell"

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    path   TEXT PRIMARY KEY,
    offset INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY,
    source          TEXT NOT NULL,
    logged_at       TEXT,
    day             TEXT,
    event           TEXT,
    tool            TEXT,
    session_id      TEXT,
    prompt_id       TEXT,
    tool_use_id     TEXT,
    cwd             TEXT,
    permission_mode TEXT,
    effort          TEXT,
    agent_type      TEXT,
    duration_ms     INTEGER,
    input_bytes     INTEGER,
    response_bytes  INTEGER,
    file_path       TEXT,
    outside_cwd     INTEGER,
    command         TEXT,
    stderr          TEXT,
    raw             TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS events_day ON events(day);
CREATE INDEX IF NOT EXISTS events_tool ON events(tool);
CREATE INDEX IF NOT EXISTS events_tool_use ON events(tool_use_id);
CREATE TABLE IF NOT EXISTS programs (
    event_id INTEGER NOT NULL REFERENCES events(id),
    program  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS programs_event ON programs(event_id);
CREATE TABLE IF NOT EXISTS net (
    event_id INTEGER NOT NULL REFERENCES events(id),
    kind     TEXT NOT NULL,
    host     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS net_event ON net(event_id);
"""

# ---------------------------------------------------------------- parsing

HEREDOC = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
CUT_MARKER = re.compile(r"…\[\+\d+ chars\]$")
ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
OPERATORS = {"&&", "||", ";", "|", "&", "(", ")", "|&", ";;"}
# Shell words that start a clause but are not programs.
KEYWORDS = {
    "if", "then", "else", "elif", "fi", "for", "while", "until", "do", "done",
    "case", "esac", "in", "{", "}", "!", "time", "function",
}
# Wrappers whose first argument is the program that actually runs.
WRAPPERS = {"sudo", "env", "nohup", "exec", "command", "xargs", "timeout"}
DENIED = re.compile(r"deny network-outbound (\S+)")
URL = re.compile(r"https?://([A-Za-z0-9._-]+)")


def strip_heredocs(command):
    """Remove heredoc bodies, which are data rather than commands."""
    out, delimiter = [], None
    for line in command.split("\n"):
        if delimiter is not None:
            if line.strip() == delimiter:
                delimiter = None
            continue
        out.append(line)
        match = HEREDOC.search(line)
        if match:
            delimiter = match.group(2)
    return "\n".join(out)


def bash_commands(command):
    """Split a Bash command line into its simple commands.

    Returns dicts with `program` (basename), `args` (the remaining words,
    quotes removed), `op` (the operator before it, e.g. "|") and `sudo`.
    Heredoc bodies are ignored. Wrappers such as sudo, env and timeout are
    skipped so the program is the thing that actually runs.
    """
    command = strip_heredocs(CUT_MARKER.sub("", command))
    found = []
    for line in command.split("\n"):
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:  # unbalanced quotes, usually a cut-off command
            tokens = re.split(r"\s+|(&&|\|\||;|\|)", line)
            tokens = [t for t in tokens if t]
        current, op, sudo, wrapped = None, "", False, False
        for token in tokens:
            if token in OPERATORS:
                current, op, sudo, wrapped = None, token, False, False
                continue
            if current is not None:
                current["args"].append(token)
                continue
            if ASSIGNMENT.match(token) or token in KEYWORDS:
                continue
            name = os.path.basename(token)
            if name.startswith("#"):
                break  # rest of the line is a comment
            if name in WRAPPERS:
                sudo = sudo or name == "sudo"
                wrapped = True
                continue
            if wrapped and (name.startswith("-") or name.isdigit()):
                continue  # an option of the wrapper, e.g. `timeout 30`
            if not name or name.startswith(("-", "$", "<", ">")):
                current = {"program": "", "args": [], "op": op, "sudo": sudo}
                continue
            current = {"program": name, "args": [], "op": op, "sudo": sudo}
            found.append(current)
    return found


def bash_programs(command):
    """Programs a Bash command invokes, in order, e.g. ['cd', 'rg', 'head']."""
    return [c["program"] for c in bash_commands(command)]


SHELLS = {"sh", "bash", "zsh", "dash"}
RISKY_COMPILED = [(label, programs, re.compile(pattern)) for label, programs, pattern in RISKY_COMMANDS]


def risky_matches(command):
    """RISKY_COMMANDS labels a Bash command matches, each with the part that matched.

    Returns {label: "program args"} for the first simple command that matched.
    """
    matches, previous = {}, None
    for current in bash_commands(command):
        args = " ".join(current["args"])
        text = f"{current['program']} {args}".strip()
        for label, programs, pattern in RISKY_COMPILED:
            if current["program"] in programs and pattern.search(args):
                matches.setdefault(label, text)
        if current["sudo"]:
            matches.setdefault(SUDO_LABEL, "sudo " + text)
        if (current["program"] in SHELLS and current["op"] in ("|", "|&") and previous
                and previous["program"] in ("curl", "wget")):
            matches.setdefault(PIPE_TO_SHELL_LABEL, f"{previous['program']} … | {text}")
        previous = current
    return matches


# Absolute, ~/ and $HOME/ paths in a command. Relative paths are not seen.
PATH_TOKEN = re.compile(r"(?<![\w.:/@~$}-])(?:~|\$HOME|\$\{HOME\})?(?:/[\w.@%+=,~-]+)+")


def expand(path):
    for prefix in ("~", "$HOME", "${HOME}"):
        if path == prefix or path.startswith(prefix + "/"):
            path = HOME + path[len(prefix):]
            break
    return os.path.normpath(path)


def under(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


ZONES = [(label, [expand(p) for p in prefixes]) for label, prefixes in WATCHED_ZONES]
HOME_OK = [expand(p) for p in HOME_ALLOWED]


def zone_of(path, projects):
    """The watched zone an absolute path falls in, or None."""
    path = expand(path)
    for label, prefixes in ZONES:
        if any(under(path, prefix) for prefix in prefixes):
            return label
    if PROJECT_CLAUDE_CONFIG.search(path):
        return "Claude settings and hooks"
    if under(path, HOME) and path != HOME:
        if any(under(path, ok) for ok in HOME_OK) or any(under(path, root) for root in projects):
            return None
        return HOME_ZONE
    return None


def bash_paths(command):
    return {expand(m.group(0)) for m in PATH_TOKEN.finditer(strip_heredocs(command))}


def hosts(record):
    """(kind, host) pairs for every network destination a record mentions."""
    found = []
    tool_input = record.get("tool_input") or {}
    tool_response = record.get("tool_response") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    if not isinstance(tool_response, dict):
        tool_response = {}
    stderr = tool_response.get("stderr")
    if isinstance(stderr, str):
        found += [("denied", h.rsplit(":", 1)[0]) for h in DENIED.findall(stderr)]
    allowed = tool_input.get("allowed_domains")
    if isinstance(allowed, list):
        found += [("allowed", h) for h in allowed if isinstance(h, str) and not h.startswith("…")]
    command = tool_input.get("command")
    if isinstance(command, str):
        found += [("url", h) for h in set(URL.findall(command))]
    url = tool_input.get("url")
    if record.get("tool_name") == "WebFetch" and isinstance(url, str):
        found += [("fetch", h) for h in URL.findall(url)]
    return found


def as_text(value):
    return value if isinstance(value, str) else None


def as_int(value):
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def row_for(record, source):
    tool_input = record.get("tool_input")
    tool_response = record.get("tool_response")
    tool_input = tool_input if isinstance(tool_input, dict) else {}
    tool_response = tool_response if isinstance(tool_response, dict) else {}
    effort = record.get("effort")
    if isinstance(effort, dict):
        effort = effort.get("level")
    logged_at = as_text(record.get("logged_at"))
    cwd = as_text(record.get("cwd"))
    file_path = as_text(tool_input.get("file_path"))
    outside = None
    if file_path and cwd:
        outside = 0 if (file_path == cwd or file_path.startswith(cwd.rstrip("/") + "/")) else 1
    return (
        source,
        logged_at,
        logged_at[:10] if logged_at else None,
        as_text(record.get("hook_event_name")),
        as_text(record.get("tool_name")),
        as_text(record.get("session_id")),
        as_text(record.get("prompt_id")),
        as_text(record.get("tool_use_id")),
        cwd,
        as_text(record.get("permission_mode")),
        as_text(effort),
        as_text(record.get("agent_type")),
        as_int(record.get("duration_ms")),
        as_int(record.get("input_bytes")),
        as_int(record.get("response_bytes")),
        file_path,
        outside,
        as_text(tool_input.get("command")),
        as_text(tool_response.get("stderr")),
    )


# ---------------------------------------------------------------- loading

INSERT_EVENT = (
    "INSERT INTO events (source, logged_at, day, event, tool, session_id, prompt_id,"
    " tool_use_id, cwd, permission_mode, effort, agent_type, duration_ms, input_bytes,"
    " response_bytes, file_path, outside_cwd, command, stderr, raw)"
    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
)


def log_files(paths):
    files = []
    for path in paths:
        path = Path(path).expanduser()
        if path.is_dir():
            files += sorted(path.glob("audit-*.jsonl"))
        elif path.is_file():
            files.append(path)
        else:
            print(f"skipping {path}: not found", file=sys.stderr)
    return [f.resolve() for f in files]


def sync(db, paths):
    """Load records appended since the last run. Returns (loaded, bad lines)."""
    loaded = bad = 0
    for path in log_files(paths):
        key = str(path)
        row = db.execute("SELECT offset FROM files WHERE path = ?", (key,)).fetchone()
        offset = row[0] if row else 0
        if path.stat().st_size < offset:
            # The file shrank, so it was replaced: reload it from the start.
            ids = "SELECT id FROM events WHERE source = ?"
            db.execute(f"DELETE FROM programs WHERE event_id IN ({ids})", (key,))
            db.execute(f"DELETE FROM net WHERE event_id IN ({ids})", (key,))
            db.execute("DELETE FROM events WHERE source = ?", (key,))
            offset = 0
        with open(path, "rb") as handle:
            handle.seek(offset)
            for line in handle:
                if not line.endswith(b"\n"):
                    break  # a record still being written; pick it up next run
                offset += len(line)
                text = line.decode("utf-8", "replace").strip()
                if not text:
                    continue
                try:
                    record = json.loads(text)
                except ValueError:
                    record = None
                if not isinstance(record, dict):
                    bad += 1
                    continue
                cursor = db.execute(INSERT_EVENT, row_for(record, key) + (text,))
                event_id = cursor.lastrowid
                command = (record.get("tool_input") or {}).get("command") \
                    if isinstance(record.get("tool_input"), dict) else None
                if record.get("tool_name") == "Bash" and isinstance(command, str):
                    db.executemany(
                        "INSERT INTO programs VALUES (?, ?)",
                        [(event_id, p) for p in bash_programs(command)],
                    )
                db.executemany(
                    "INSERT INTO net VALUES (?, ?, ?)",
                    [(event_id, kind, host) for kind, host in hosts(record)],
                )
                loaded += 1
        db.execute(
            "INSERT INTO files (path, offset) VALUES (?, ?)"
            " ON CONFLICT(path) DO UPDATE SET offset = excluded.offset",
            (key, offset),
        )
        db.commit()
    return loaded, bad


# ---------------------------------------------------------------- report

SENSITIVE = (
    "file_path LIKE '%/.env' OR file_path LIKE '%/.env.%' OR file_path LIKE '%/.ssh/%'"
    " OR file_path LIKE '%/.aws/%' OR file_path LIKE '%/.gnupg/%' OR file_path LIKE '%id_rsa%'"
    " OR file_path LIKE '%.pem' OR file_path LIKE '%.key' OR file_path LIKE '%/credentials'"
    " OR file_path LIKE '%/credentials.json'"
    " OR file_path LIKE '%/.netrc' OR file_path LIKE '%/.npmrc'"
)


def human(n):
    n = n or 0
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def seconds(ms):
    return "-" if ms is None else f"{ms / 1000:.1f}s"


# Set by --save: render the report as Markdown instead of aligned plain text.
MARKDOWN = False


def paragraph(*lines):
    """Print lines that belong together; Markdown needs explicit line breaks."""
    if MARKDOWN:
        print()
        print("  \n".join(lines))
    else:
        print("\n".join(lines))


def md_cell(text):
    return re.sub(r"([|*_`<\\])", r"\\\1", text)


def table(title, headers, rows, note=None):
    print(f"\n## {title}")
    if note:
        paragraph(*note.split("\n"))
    if not rows:
        paragraph("(none)")
        return
    rows = [[("" if cell is None else str(cell)) for cell in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    numeric = [all(re.fullmatch(r"\$?[\d.,%]+( ?[KMG]?B|s|[KM])?|-|", r[i]) for r in rows) for i in range(len(headers))]

    if MARKDOWN:
        print()
        print("| " + " | ".join(h or " " for h in headers) + " |")
        print("| " + " | ".join("---:" if num else "---" for num in numeric) + " |")
        for row in rows:
            print("| " + " | ".join(md_cell(c) for c in row) + " |")
        return

    def fmt(cells):
        parts = [c.rjust(w) if num else c.ljust(w) for c, w, num in zip(cells, widths, numeric)]
        return "  ".join(parts).rstrip()

    print(fmt(headers))
    for row in rows:
        print(fmt(row))


def shorten(path, limit=60):
    home = str(Path.home())
    if path and path.startswith(home):
        path = "~" + path[len(home):]
    if path and len(path) > limit:
        path = "…" + path[-(limit - 1):]
    return path


WRITE_TOOLS = {"Edit", "Write", "NotebookEdit", "MultiEdit"}


def call_status(events):
    """How a tool call ended, from the set of hook events logged for it."""
    if "PermissionDenied" in events:
        return "denied"
    if "PostToolUse" in events:
        return "done"
    if "PostToolUseFailure" in events:
        return "failed"
    return "unfinished"


def safety_sections(db, since, top):
    """Watched zones and risky commands, computed from the lists at the top."""
    projects = {
        expand(cwd) for (cwd,) in db.execute("SELECT DISTINCT cwd FROM events WHERE cwd IS NOT NULL")
        if expand(cwd) not in (HOME, "/")
    }
    where, args = ("AND day >= ?", (since,)) if since else ("", ())
    calls = {}
    for key, event, tool, day, cwd, session, file_path, command in db.execute(
        "SELECT coalesce(tool_use_id, id), event, tool, day, cwd, session_id, file_path, command"
        # Permission prompts carry no call id, so they are not calls of their own.
        f" FROM events WHERE tool IS NOT NULL AND NOT (event IS 'PermissionRequest' AND tool_use_id IS NULL)"
        f" {where} ORDER BY id",
        args,
    ):
        call = calls.setdefault(key, {"events": set(), "tool": tool, "day": day, "cwd": cwd,
                                      "session": session, "file_path": file_path, "command": command})
        call["events"].add(event)

    zone_names = [label for label, _ in ZONES] + [HOME_ZONE]
    columns = ["read", "write", "bash", "denied", "failed", "unfinished"]
    zone_counts = {zone: dict.fromkeys(columns, 0) for zone in zone_names}
    path_counts, project_counts = {}, {}
    risky_counts, risky_latest = {}, {}

    for call in calls.values():
        status = call_status(call["events"])
        touched = set()  # (zone, access, path)
        if call["file_path"]:
            access = "write" if call["tool"] in WRITE_TOOLS else "read"
            zone = zone_of(call["file_path"], projects)
            if zone:
                touched.add((zone, access, expand(call["file_path"])))
        if call["tool"] == "Bash" and call["command"]:
            for path in bash_paths(call["command"]):
                zone = zone_of(path, projects)
                if zone:
                    touched.add((zone, "bash", path))
            for label, matched in risky_matches(call["command"]).items():
                counts = risky_counts.setdefault(label, {"done": 0, "denied": 0, "failed": 0, "unfinished": 0, "last": ""})
                counts[status] += 1
                counts["last"] = max(counts["last"], call["day"] or "")
                if (call["day"] or "") >= risky_latest.get(label, {"day": ""})["day"]:
                    risky_latest[label] = {"day": call["day"] or "", "cwd": call["cwd"], "command": matched}
        for zone, access in {(zone, access) for zone, access, _ in touched}:
            zone_counts[zone][access if status == "done" else status] += 1
        for zone, access, path in touched:
            key = (zone, access, path)
            path_counts[key] = path_counts.get(key, 0) + 1
        for zone in {zone for zone, _, _ in touched}:
            entry = project_counts.setdefault((zone, call["cwd"]), [0, set()])
            entry[0] += 1
            entry[1].add(call["session"])

    table(
        "Watched zones",
        ["zone", "read", "write", "bash", "denied", "failed", "unfinished"],
        [[zone] + [zone_counts[zone][c] for c in columns] for zone in zone_names],
        note="Tool calls touching places listed in WATCHED_ZONES at the top of the script.\n"
             "read / write = completed file-tool calls; bash = completed Bash commands naming a path there.\n"
             "denied, failed and unfinished calls are counted in their own columns instead.",
    )
    per_zone = min(top, 5)
    rows = []
    for zone in zone_names:
        ranked = sorted(((n, access, path) for (z, access, path), n in path_counts.items() if z == zone), reverse=True)
        rows += [(zone, access, shorten(path), n) for n, access, path in ranked[:per_zone]]
    table("Watched zones: most touched paths", ["zone", "access", "path", "calls"], rows,
          note=f"up to {per_zone} per zone")
    rows = []
    for zone in zone_names:
        ranked = sorted(((n, len(sessions), cwd or "") for (z, cwd), (n, sessions) in project_counts.items() if z == zone),
                        reverse=True)
        rows += [(zone, shorten(cwd), n, sessions) for n, sessions, cwd in ranked[:3]]
    table("Watched zones: which projects", ["zone", "session directory", "calls", "sessions"], rows,
          note="up to 3 per zone")

    order = [label for label, _, _ in RISKY_COMMANDS] + [SUDO_LABEL, PIPE_TO_SHELL_LABEL]
    table(
        "Risky commands",
        ["command type", "completed", "denied", "failed", "unfinished", "last seen"],
        [(label, c["done"], c["denied"], c["failed"], c["unfinished"], c["last"])
         for label in order for c in [risky_counts.get(label)] if c],
        note="Bash commands matching RISKY_COMMANDS at the top of the script. Types with no matches are omitted.",
    )
    table(
        "Risky commands: latest example of each",
        ["command type", "day", "session directory", "matching part of the command"],
        [(label, e["day"], shorten(e["cwd"] or "", 40), e["command"].replace("\n", " ")[:90])
         for label in order for e in [risky_latest.get(label)] if e],
    )


def report(db, since, top):
    where, args = ("WHERE day >= ?", (since,)) if since else ("", ())
    also = "AND" if where else "WHERE"

    def q(sql, extra=()):
        return db.execute(sql.format(where=where, also=also), args + tuple(extra)).fetchall()

    total, first, last, sessions, prompts = q(
        "SELECT count(*), min(logged_at), max(logged_at),"
        " count(DISTINCT session_id), count(DISTINCT prompt_id) FROM events {where}"
    )[0]
    if not total:
        print("no records" + (f" since {since}" if since else ""))
        return
    print(f"# Claude Code audit report{f' (since {since})' if since else ''}")
    paragraph(f"{total} records, {sessions} sessions, {prompts} prompts", f"{first} to {last}")

    events = q("SELECT coalesce(event, '(none)'), count(*) FROM events {where} GROUP BY 1 ORDER BY 2 DESC")
    table("Records by hook event", ["event", "records"], events)
    names = {name for name, _ in events}

    # A tool call counts once, from the event that ended it.
    table(
        "Tools (completed calls)",
        ["tool", "calls", "share", "avg", "max", "response size"],
        [
            (tool, calls, f"{100 * calls / max(1, done):.1f}%", seconds(avg), seconds(peak), human(size))
            for done in [q("SELECT count(*) FROM events {where} {also} event = 'PostToolUse'")[0][0]]
            for tool, calls, avg, peak, size in q(
                "SELECT tool, count(*), avg(duration_ms), max(duration_ms), sum(response_bytes)"
                " FROM events {where} {also} event = 'PostToolUse' GROUP BY tool ORDER BY 2 DESC LIMIT ?",
                (top,),
            )
        ],
    )

    outcome_events = ["PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest", "PermissionDenied"]
    if names & (set(outcome_events) - {"PostToolUse"}):
        columns = ", ".join(f"sum(event = '{e}')" for e in outcome_events)
        rows = q(f"SELECT tool, {columns} FROM events {{where}} GROUP BY tool ORDER BY 2 DESC, 3 DESC LIMIT ?", (top,))
        table(
            "Outcomes by tool",
            ["tool", "started", "succeeded", "failed", "asked", "denied", "fail %", "deny %"],
            [
                (tool, pre, ok, failed, asked, denied,
                 f"{100 * failed / ((ok or 0) + (failed or 0)):.1f}%" if (ok or 0) + (failed or 0) else "-",
                 f"{100 * denied / pre:.1f}%" if pre else "-")
                for tool, pre, ok, failed, asked, denied in rows
            ],
            note="started = PreToolUse, succeeded = PostToolUse, failed = PostToolUseFailure,\n"
                 "asked = PermissionRequest, denied = PermissionDenied",
        )
        if "PreToolUse" in names:
            table(
                "Started but never finished (blocked, denied or interrupted)",
                ["tool", "calls"],
                q(
                    "SELECT tool, count(*) FROM events p {where} {also} event = 'PreToolUse'"
                    " AND NOT EXISTS (SELECT 1 FROM events d WHERE d.tool_use_id = p.tool_use_id"
                    " AND d.event IN ('PostToolUse', 'PostToolUseFailure'))"
                    " GROUP BY tool ORDER BY 2 DESC LIMIT ?",
                    (top,),
                ),
            )
    else:
        print("\n## Outcomes by tool")
        paragraph(
            "Only PostToolUse records so far: failures, permission prompts and denials",
            "are not in the log. They appear once the hook is registered on PreToolUse,",
            "PostToolUseFailure, PermissionRequest and PermissionDenied.",
        )

    safety_sections(db, since, top)

    # A call can be logged by several events (PreToolUse, PostToolUse, ...).
    # Network and file sections count it once, keyed by tool_use_id.
    call = "coalesce(e.tool_use_id, e.id)"
    day_filter = "AND e.day >= ?" if since else ""

    def net(kind):
        return db.execute(
            f"SELECT n.host, count(DISTINCT {call}) FROM net n JOIN events e ON e.id = n.event_id"
            f" WHERE n.kind = ? {day_filter} GROUP BY n.host ORDER BY 2 DESC LIMIT ?",
            (kind,) + args + (top,),
        ).fetchall()

    table("Network: outbound connections the sandbox blocked", ["host", "calls"], net("denied"))
    table("Network: hosts requested through allowed_domains", ["host", "calls"], net("allowed"))
    table("Network: hosts in Bash command URLs", ["host", "calls"], net("url"))
    table("Network: WebFetch hosts", ["host", "calls"], net("fetch"))

    table(
        "Bash programs",
        ["program", "calls"],
        db.execute(
            f"SELECT p.program, count(DISTINCT {call}) FROM programs p JOIN events e ON e.id = p.event_id"
            f" WHERE 1 {day_filter} GROUP BY p.program ORDER BY 2 DESC LIMIT ?",
            args + (top,),
        ).fetchall(),
        note="calls = Bash commands that invoke the program at least once",
    )

    table(
        "File tools reaching outside the session directory",
        ["tool", "calls", "outside cwd", "share"],
        [
            (tool, calls, outside, f"{100 * outside / calls:.1f}%")
            for tool, calls, outside in db.execute(
                f"SELECT tool, count(*), sum(outside) FROM ("
                f"SELECT e.tool AS tool, max(e.outside_cwd) AS outside FROM events e"
                f" WHERE e.outside_cwd IS NOT NULL {day_filter} GROUP BY {call}"
                f") GROUP BY tool ORDER BY 2 DESC",
                args,
            )
        ],
    )
    table(
        "Sensitive-looking file paths",
        ["tool", "path", "calls"],
        [
            (tool, shorten(path), calls)
            for tool, path, calls in db.execute(
                f"SELECT e.tool, e.file_path, count(DISTINCT {call}) FROM events e"
                f" WHERE ({SENSITIVE}) {day_filter} GROUP BY 1, 2 ORDER BY 3 DESC LIMIT ?",
                args + (top,),
            )
        ],
        note="matched on file_path only (.env, .ssh, .aws, key files, credentials files); Bash commands are not scanned",
    )

    done = "event = 'PostToolUse'"
    table("Permission mode", ["mode", "calls"],
          q(f"SELECT coalesce(permission_mode, '(none)'), count(*) FROM events {{where}} {{also}} {done} GROUP BY 1 ORDER BY 2 DESC"))
    table("Subagent calls by type", ["agent type", "calls"],
          q(f"SELECT agent_type, count(*) FROM events {{where}} {{also}} {done} AND agent_type IS NOT NULL GROUP BY 1 ORDER BY 2 DESC LIMIT ?", (top,)))
    table("Projects", ["cwd", "calls", "sessions"],
          [(shorten(cwd), calls, n) for cwd, calls, n in
           q(f"SELECT cwd, count(*), count(DISTINCT session_id) FROM events {{where}} {{also}} {done} GROUP BY 1 ORDER BY 2 DESC LIMIT ?", (top,))])
    table("Busiest days", ["day", "calls", "sessions"],
          q(f"SELECT day, count(*), count(DISTINCT session_id) FROM events {{where}} {{also}} {done} GROUP BY 1 ORDER BY 2 DESC LIMIT ?", (top,)))
    table("By month", ["month", "calls", "sessions", "response size"],
          [(month, calls, n, human(size)) for month, calls, n, size in
           q(f"SELECT substr(day, 1, 7), count(*), count(DISTINCT session_id), sum(response_bytes) FROM events {{where}} {{also}} {done} GROUP BY 1 ORDER BY 1")])

    per_prompt = sorted(n for (n,) in q(f"SELECT count(*) FROM events {{where}} {{also}} {done} AND prompt_id IS NOT NULL GROUP BY prompt_id"))
    per_session = sorted(n for (n,) in q(f"SELECT count(*) FROM events {{where}} {{also}} {done} GROUP BY session_id"))
    rows = []
    for label, values in (("per prompt", per_prompt), ("per session", per_session)):
        if values:
            rows.append((label, values[len(values) // 2], values[int(len(values) * 0.9)], values[-1]))
    table("Tool calls per prompt and session", ["", "median", "p90", "max"], rows)

    table(
        "Slowest calls",
        ["time", "tool", "day", "what"],
        [
            (seconds(ms), tool, day, (what or "").replace("\n", " ")[:70])
            for ms, tool, day, what in q(
                f"SELECT duration_ms, tool, day, coalesce(json_extract(raw, '$.tool_input.description'), command, file_path)"
                f" FROM events {{where}} {{also}} {done} AND tool NOT IN ('Agent', 'AskUserQuestion', 'ExitPlanMode')"
                f" ORDER BY duration_ms DESC LIMIT ?",
                (min(top, 10),),
            )
        ],
        note="excludes tools that wait on a person or a subagent",
    )


# ---------------------------------------------------------------- sessions

TRANSCRIPT_MARKERS = (b'"ai-title"', b'"custom-title"', b'"cost-state"')
FLAG_KINDS = ["zone", "risky", "net blocked", "denied", "unfinished"]
# Everything the models read or wrote, cached or not, summed over all models.
TOKEN_FIELDS = ("inputTokens", "outputTokens", "cacheReadInputTokens", "cacheCreationInputTokens")
# The most telling short description of a call, whatever the tool.
WHAT = (
    "coalesce(json_extract(raw, '$.tool_input.description'), command, file_path,"
    " json_extract(raw, '$.tool_input.url'), json_extract(raw, '$.tool_input.query'),"
    " json_extract(raw, '$.tool_input.skill'), json_extract(raw, '$.tool_input.pattern'))"
)


def parse_time(text):
    """A logged_at value as an aware datetime, or None."""
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        return None


def local_time(text, fmt="%Y-%m-%d %H:%M"):
    moment = parse_time(text)
    return moment.astimezone().strftime(fmt) if moment else "-"


def time_span(first, last):
    start, end = parse_time(first), parse_time(last)
    if not start or not end:
        return "-"
    minutes = max(0, int((end - start).total_seconds() // 60))
    hours, minutes = divmod(minutes, 60)
    if hours == 0:
        return f"{minutes}m"
    if hours < 48:
        return f"{hours}h{minutes:02d}m"
    return f"{hours // 24}d{hours % 24}h"


def clip(text, limit):
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def transcript_info(path):
    """Title, cost, model and lines changed from a session transcript.

    Claude Code keeps these in the transcript, not in hook events. Returns an
    empty dict when the transcript has been deleted. A name the user gave the
    session wins over the generated title.
    """
    if not path:
        return {}
    try:
        handle = open(os.path.expanduser(path), "rb")
    except OSError:
        return {}
    generated = custom = cost = None
    with handle:
        for line in handle:
            if not any(marker in line for marker in TRANSCRIPT_MARKERS):
                continue
            try:
                entry = json.loads(line)
            except ValueError:
                continue
            if not isinstance(entry, dict):
                continue
            kind = entry.get("type")
            if kind == "ai-title" and isinstance(entry.get("aiTitle"), str):
                generated = entry["aiTitle"].strip() or generated
            elif kind == "custom-title" and isinstance(entry.get("customTitle"), str):
                custom = entry["customTitle"].strip() or custom
            elif kind == "cost-state":
                cost = entry
    info = {}
    if custom or generated:
        info["title"] = custom or generated
    if cost:
        if isinstance(cost.get("totalCostUSD"), (int, float)):
            info["cost"] = cost["totalCostUSD"]
        info["added"] = as_int(cost.get("totalLinesAdded")) or 0
        info["removed"] = as_int(cost.get("totalLinesRemoved")) or 0
        usage = cost.get("modelUsage")
        if isinstance(usage, dict) and usage:
            spend = {m: (u.get("costUSD") or 0) if isinstance(u, dict) else 0 for m, u in usage.items()}
            info["model"] = max(spend, key=spend.get).removeprefix("claude-")
            info["tokens"] = sum(
                as_int(u.get(field)) or 0 for u in usage.values() if isinstance(u, dict) for field in TOKEN_FIELDS)
    return info


def project_roots(db):
    """Every directory a logged session ran in; paths under these are not flagged."""
    return {
        expand(cwd) for (cwd,) in db.execute("SELECT DISTINCT cwd FROM events WHERE cwd IS NOT NULL")
        if expand(cwd) not in (HOME, "/")
    }


def call_flags(call, projects, net_blocked):
    """Why a call is worth a look, as {kind: detail}. Empty for an ordinary call."""
    flags = {}
    zones = set()
    if call["file_path"]:
        zones.add(zone_of(call["file_path"], projects))
    if call["tool"] == "Bash" and call["command"]:
        zones |= {zone_of(path, projects) for path in bash_paths(call["command"])}
        risky = risky_matches(call["command"])
        if risky:
            flags["risky"] = ", ".join(risky)
    zones.discard(None)
    if zones:
        flags["zone"] = ", ".join(sorted(zones))
    if net_blocked:
        flags["net blocked"] = ""
    if call["status"] in ("denied", "unfinished"):
        flags[call["status"]] = ""
    return flags


def load_sessions(db, session_ids):
    """Group the logged events of the given sessions into tool calls, with flags."""
    projects = project_roots(db)
    marks = ",".join("?" * len(session_ids))
    blocked = {
        key for (key,) in db.execute(
            "SELECT DISTINCT coalesce(e.tool_use_id, e.id) FROM net n JOIN events e ON e.id = n.event_id"
            f" WHERE n.kind = 'denied' AND e.session_id IN ({marks})",
            session_ids,
        )
    }
    sessions = {}
    for (key, call_id, event, tool, logged_at, cwd, session_id, prompt_id, file_path, command,
         agent_type, duration_ms, transcript, what) in db.execute(
        "SELECT coalesce(tool_use_id, id), tool_use_id, event, tool, logged_at, cwd, session_id, prompt_id,"
        f" file_path, command, agent_type, duration_ms, json_extract(raw, '$.transcript_path'), {WHAT}"
        f" FROM events WHERE tool IS NOT NULL AND session_id IN ({marks}) ORDER BY id",
        session_ids,
    ):
        session = sessions.setdefault(
            session_id, {"id": session_id, "calls": {}, "first": logged_at, "last": logged_at,
                         "transcript": None, "asked": 0})
        session["last"] = logged_at
        if event == "PermissionRequest" and not call_id:
            # Permission prompts carry no call id, so they cannot be tied to a
            # call. Count them for the session instead of inventing calls.
            session["asked"] += 1
            continue
        if transcript and (not agent_type or not session["transcript"]):
            session["transcript"] = transcript
        call = session["calls"].setdefault(key, {
            "events": set(), "tool": tool, "at": logged_at, "cwd": cwd, "prompt": prompt_id,
            "file_path": file_path, "command": command, "agent": agent_type, "took": None, "what": what,
        })
        call["events"].add(event)
        if duration_ms is not None:
            call["took"] = duration_ms
        call["what"] = call["what"] or what
    for session in sessions.values():
        for key, call in session["calls"].items():
            call["status"] = call_status(call["events"])
            call["flags"] = call_flags(call, projects, key in blocked)
    return sessions


def summarize(session):
    calls = list(session["calls"].values())
    flag_counts = Counter(kind for call in calls for kind in call["flags"])
    summary = {
        "id": session["id"],
        "first": session["first"],
        "last": session["last"],
        "calls": len(calls),
        "prompts": len({call["prompt"] for call in calls if call["prompt"]}),
        "failed": sum(call["status"] == "failed" for call in calls),
        "asked": session["asked"],
        "subagent": sum(bool(call["agent"]) for call in calls),
        "tools": Counter(call["tool"] for call in calls).most_common(4),
        "project": Counter(call["cwd"] or "" for call in calls).most_common(1)[0][0] if calls else "",
        "flagged": sum(bool(call["flags"]) for call in calls),
        "flag_text": ", ".join(f"{kind} {flag_counts[kind]}" for kind in FLAG_KINDS if flag_counts[kind]) or "-",
    }
    summary.update(transcript_info(session["transcript"]))
    return summary


def money(value):
    return "-" if value is None else f"${value:.2f}"


def count(value):
    """A large number in short form: 950, 12.3K, 4.5M."""
    if value is None:
        return "-"
    if value < 1000:
        return str(value)
    return f"{value / 1000:.1f}K" if value < 1_000_000 else f"{value / 1_000_000:.1f}M"


def sessions_table(db, since, last, flagged):
    """Recent sessions, newest first: where they ran, what they called, what was flagged."""
    rows = db.execute(
        "SELECT session_id FROM events WHERE session_id IS NOT NULL AND tool IS NOT NULL GROUP BY session_id"
        + (" HAVING max(day) >= ?" if since else "") + " ORDER BY max(logged_at) DESC",
        (since,) if since else (),
    ).fetchall()
    ids = [session_id for (session_id,) in rows]
    if not flagged:
        ids = ids[:last]
    picked = []
    if ids:
        sessions = load_sessions(db, ids)
        for session_id in ids:
            summary = summarize(sessions[session_id])
            if flagged and not summary["flagged"]:
                continue
            picked.append(summary)
            if len(picked) == last:
                break
    if not picked:
        print("no sessions" + (" with flags" if flagged else "") + (f" since {since}" if since else ""))
        return

    print("# Claude Code sessions")
    paragraph(
        f"{len(picked)} most recent sessions" + (" with flags" if flagged else "")
        + (f" since {since}" if since else "") + ", most recently active first. Times are local.",
    )
    table(
        "Sessions",
        ["started", "length", "session", "title", "project", "prompts", "calls", "failed", "asked", "flagged",
         "model", "tokens", "cost"],
        [
            (local_time(s["first"]), time_span(s["first"], s["last"]), s["id"][:8], clip(s.get("title"), 44) or "-",
             shorten(s["project"], 40), s["prompts"], s["calls"], s["failed"], s["asked"], s["flagged"],
             s.get("model", "-"), count(s.get("tokens")), money(s.get("cost")))
            for s in picked
        ],
        note="length = first to last tool call. failed = calls that ran and failed.\n"
             "asked = permission prompts Claude Code showed.\n"
             "flagged = calls that touched a watched zone, ran a risky command, had a network\n"
             "connection blocked, were denied, or never finished.\n"
             "model = the model most of the cost went to. tokens = all tokens read and written, cached included.\n"
             "title, model, tokens and cost come from the session transcript; '-' means it is gone or has no totals yet.",
    )
    table(
        "Sessions: tools and flags",
        ["session", "tools", "subagent calls", "lines", "flags"],
        [
            (s["id"][:8], ", ".join(f"{tool} {n}" for tool, n in s["tools"]), s["subagent"],
             f"+{s['added']} -{s['removed']}" if "added" in s else "-", s["flag_text"])
            for s in picked
        ],
        note="lines = lines added and removed.\n"
             "flags counts calls per kind; see WATCHED_ZONES and RISKY_COMMANDS at the top of the script.",
    )
    paragraph("", "Every call of one session: audit-stats.py sessions --show <session>")


def show_session(db, wanted):
    """Every tool call of one session, in order."""
    matches = [row[0] for row in db.execute(
        "SELECT DISTINCT session_id FROM events WHERE session_id LIKE ? ORDER BY session_id", (wanted + "%",))]
    if len(matches) != 1:
        print(f"no session starts with {wanted!r}" if not matches
              else f"{len(matches)} sessions start with {wanted!r}: " + ", ".join(m[:13] for m in matches[:8]))
        return
    session = load_sessions(db, matches)[matches[0]]
    summary = summarize(session)
    print(f"# Session {session['id']}")
    paragraph(
        f"Title: {summary.get('title', '-')}",
        f"Project: {shorten(summary['project'])}",
        f"{local_time(summary['first'])} to {local_time(summary['last'])} local ({time_span(summary['first'], summary['last'])})",
        f"{summary['calls']} calls in {summary['prompts']} prompts, {summary['failed']} failed,"
        f" {summary['asked']} permission prompts, {summary['flagged']} flagged",
        f"Cost {money(summary.get('cost'))}, {count(summary.get('tokens'))} tokens, model {summary.get('model', '-')}",
    )
    prompts = {}
    rows = []
    for call in session["calls"].values():
        number = prompts.setdefault(call["prompt"], len(prompts) + 1) if call["prompt"] else "-"
        flags = "; ".join(f"{kind}: {detail}" if detail else kind for kind, detail in call["flags"].items())
        rows.append((
            local_time(call["at"], "%m-%d %H:%M:%S"),
            number,
            f"{call['tool']} ({call['agent']})" if call["agent"] else call["tool"],
            "ok" if call["status"] == "done" else call["status"],
            seconds(call["took"]),
            clip(call["what"], 70),
            flags,
        ))
    table("Calls", ["time", "prompt", "tool", "status", "took", "what", "flags"], rows,
          note="prompt numbers the prompts of this session in order; a tool name in brackets is the subagent that made the call.")


# ---------------------------------------------------------------- command line

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("action", choices=["report", "sync", "sessions"])
    parser.add_argument("logs", nargs="*", help=f"log files or directories (default: {DEFAULT_DIR})")
    parser.add_argument("--db", help="SQLite file (default: audit.db in the first log directory)")
    parser.add_argument("--since", metavar="YYYY-MM-DD", help="report only records from this UTC day on")
    parser.add_argument("--top", type=int, default=10, help="rows per section (default: 10)")
    parser.add_argument("--save", metavar="FILE.md", help="write the output to this file as Markdown instead of printing it")
    parser.add_argument("--last", type=int, default=15, metavar="N", help="sessions: how many sessions to list (default: 15)")
    parser.add_argument("--flagged", action="store_true", help="sessions: list only sessions with something flagged")
    parser.add_argument("--show", metavar="SESSION", help="sessions: list every call of one session (its id or first characters)")
    options = parser.parse_args()

    logs = options.logs or [str(DEFAULT_DIR)]
    first = Path(logs[0]).expanduser()
    db_path = Path(options.db).expanduser() if options.db else (first if first.is_dir() else first.parent) / "audit.db"

    db = sqlite3.connect(db_path)
    db.executescript(SCHEMA)
    loaded, bad = sync(db, logs)
    status = f"loaded {loaded} new records into {db_path}"
    if bad:
        status += f" ({bad} unreadable lines skipped)"
    print(status, file=sys.stderr)
    if options.action == "sync":
        return
    if options.action == "report":
        render = partial(report, db, options.since, options.top)
    elif options.show:
        render = partial(show_session, db, options.show)
    else:
        render = partial(sessions_table, db, options.since, options.last, options.flagged)
    if options.save:
        global MARKDOWN
        MARKDOWN = True
        save_path = Path(options.save).expanduser()
        with open(save_path, "w", encoding="utf-8") as handle, contextlib.redirect_stdout(handle):
            render()
        print(f"saved to {save_path}", file=sys.stderr)
    else:
        render()


if __name__ == "__main__":
    main()
