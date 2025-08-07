import sqlite3
from pathlib import Path
from modules.ui import info, success, warn, fail, plain

SESSION_DB = Path(__file__).parent.parent / "db" / "sapstract_sessions.db"

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active. Use 'session start <name>' first.")
        return

    if not args:
        fail("Usage: target set <host_or_ip> | target list | target delete <host_or_ip>")
        return

    action = args[0]

    if action == "list":
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("SELECT target FROM targets WHERE session_name = ?", (current_session,))
            rows = c.fetchall()
            if not rows:
                warn("No targets found.")
            else:
                info(f"Targets for session '{current_session}':")
                for (target,) in rows:
                    plain(f"  - {target}")
        return

    elif action == "delete":
        if len(args) < 2:
            fail("Usage: target delete <host_or_ip>")
            return
        target = args[1]
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM targets WHERE session_name = ? AND target = ?", (current_session, target))
            if c.rowcount > 0:
                conn.commit()
                success(f"Removed target '{target}' from session '{current_session}'")
            else:
                warn(f"Target '{target}' not found in session '{current_session}'")
        return

    elif action == "set":
        if len(args) < 2:
            fail("Usage: target set <host_or_ip>")
            return
        target = args[1]
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS targets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_name TEXT NOT NULL,
                    target TEXT NOT NULL,
                    UNIQUE(session_name, target)
                )
            """)
            try:
                c.execute("INSERT INTO targets (session_name, target) VALUES (?, ?)", (current_session, target))
                conn.commit()
                success(f"Added target '{target}' to session '{current_session}'")
            except sqlite3.IntegrityError:
                warn(f"Target '{target}' already exists in this session.")
        return

    else:
        fail("Unknown subcommand. Use: set, list, delete")

def complete(args_so_far):
    subcommands = ["set", "list", "delete"]
    if len(args_so_far) == 0:
        return subcommands
    elif len(args_so_far) == 1:
        return [cmd for cmd in subcommands if cmd.startswith(args_so_far[0])]
    elif args_so_far[0] == "delete":
        from __main__ import CURRENT_SESSION  
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            try:
                c.execute("SELECT target FROM targets WHERE session_name = ?", (CURRENT_SESSION,))
                return [row[0] for row in c.fetchall() if row[0].startswith(args_so_far[1])]
            except Exception:
                return []
    return []

