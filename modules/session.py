import sqlite3
from pathlib import Path
from modules.ui import info, success, warn, fail, plain

SESSION_DB = Path(__file__).parent.parent / "db" / "sapstract_sessions.db"

def run(args, set_session, current_session):
    if not args:
        fail("Usage: session start|set|delete|list <name?>")
        return

    cmd = args[0]

    if cmd == "list":
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("SELECT name, created_at FROM sessions")
            rows = c.fetchall()
            if not rows:
                warn("No sessions found.")
                return
            info("Available sessions:")
            for row in rows:
                plain(f"  - {row[0]} (created {row[1]})")

    elif cmd == "start":
        if len(args) < 2:
            fail("Usage: session start <name>")
            return
        name = args[1]
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sessions WHERE name = ?", (name,))
            if c.fetchone() is None:
                c.execute("INSERT INTO sessions (name) VALUES (?)", (name,))
                conn.commit()
                success(f"Created and started session '{name}'")
            else:
                info(f"Resuming session '{name}'")
        set_session(name)

    elif cmd == "set":
        if len(args) < 2:
            fail("Usage: session set <name>")
            return
        name = args[1]
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sessions WHERE name = ?", (name,))
            if c.fetchone():
                set_session(name)
                success(f"Switched to session '{name}'")
            else:
                warn(f"Session '{name}' does not exist. Use 'session start <name>' to create it.")

    elif cmd == "delete":
        if len(args) < 2:
            fail("Usage: session delete <name>")
            return
        name = args[1]
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("DELETE FROM sessions WHERE name = ?", (name,))
            conn.commit()
        if current_session == name:
            set_session(None)
        success(f"Deleted session '{name}'")

    else:
        fail("Unknown subcommand. Use: start, set, delete, list")

def complete(args_so_far):
    subcommands = ["start", "set", "delete", "list"]
    if len(args_so_far) == 0:
        return subcommands
    elif len(args_so_far) == 1:
        return [cmd for cmd in subcommands if cmd.startswith(args_so_far[0])]
    elif args_so_far[0] in ["set", "delete"]:
        with sqlite3.connect(SESSION_DB) as conn:
            c = conn.cursor()
            c.execute("SELECT name FROM sessions")
            return [row[0] for row in c.fetchall() if row[0].startswith(args_so_far[1])]
    return []

