#!/usr/bin/env python3
"""Load Claude Code audit logs into SQLite and print usage statistics.

The logs are the audit-YYYY-MM.jsonl files written by audit-log.sh (slim
records, see audit-slim.jq). Loading is incremental: each run reads only the
bytes appended since the last one.

    audit-stats.py report                 # sync, then print the report
    audit-stats.py report --since 2026-11-01 --top 15
    audit-stats.py report --save report.md   # write the report as Markdown
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
from pathlib import Path

DEFAULT_DIR = Path.home() / ".claude" / "security-logs"

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


def bash_programs(command):
    """Programs a Bash command invokes, in order, e.g. ['cd', 'rg', 'head']."""
    command = strip_heredocs(CUT_MARKER.sub("", command))
    programs = []
    for line in command.split("\n"):
        try:
            lexer = shlex.shlex(line, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            tokens = list(lexer)
        except ValueError:  # unbalanced quotes, usually a cut-off command
            tokens = re.split(r"\s+|(&&|\|\||;|\|)", line)
            tokens = [t for t in tokens if t]
        at_start = True
        for token in tokens:
            if token in OPERATORS:
                at_start = True
                continue
            if not at_start:
                continue
            if ASSIGNMENT.match(token) or token in KEYWORDS:
                continue
            name = os.path.basename(token)
            if name in WRAPPERS:
                continue
            if name and not name.startswith(("-", "$", "<", ">", "#")):
                programs.append(name)
            elif name.startswith("#"):
                break  # rest of the line is a comment
            at_start = False
    return programs


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
    numeric = [all(re.fullmatch(r"[\d.,%]+( ?[KMG]?B|s)?|-|", r[i]) for r in rows) for i in range(len(headers))]

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
                 f"{100 * failed / (ok + failed):.1f}%" if ok + failed else "-",
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


# ---------------------------------------------------------------- command line

def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("action", choices=["report", "sync"])
    parser.add_argument("logs", nargs="*", help=f"log files or directories (default: {DEFAULT_DIR})")
    parser.add_argument("--db", help="SQLite file (default: audit.db in the first log directory)")
    parser.add_argument("--since", metavar="YYYY-MM-DD", help="report only records from this UTC day on")
    parser.add_argument("--top", type=int, default=10, help="rows per section (default: 10)")
    parser.add_argument("--save", metavar="FILE.md", help="write the report to this file as Markdown instead of printing it")
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
    if options.action == "report":
        if options.save:
            global MARKDOWN
            MARKDOWN = True
            save_path = Path(options.save).expanduser()
            with open(save_path, "w", encoding="utf-8") as handle, contextlib.redirect_stdout(handle):
                report(db, options.since, options.top)
            print(f"report saved to {save_path}", file=sys.stderr)
        else:
            report(db, options.since, options.top)


if __name__ == "__main__":
    main()
