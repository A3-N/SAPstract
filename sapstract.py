import sqlite3
import os
import sys
import readline
from pathlib import Path
import importlib.util
from termcolor import colored

ROOT_DIR = Path(__file__).parent.resolve()
DB_DIR = ROOT_DIR / "db"
MODULES_DIR = ROOT_DIR / "modules"
SESSION_DB = DB_DIR / "sapstract_sessions.db"

LOADED_COMMANDS = {}
CURRENT_SESSION = None


def init_db():
    DB_DIR.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS targets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name TEXT NOT NULL,
            target TEXT NOT NULL,
            UNIQUE(session_name, target)
        )
        """)
        c.execute("""
        CREATE TABLE IF NOT EXISTS ports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name TEXT NOT NULL,
            target TEXT NOT NULL,
            port INTEGER NOT NULL,
            status TEXT NOT NULL,
            label TEXT,
            UNIQUE(session_name, target, port)
        )
        """)
        conn.commit()


def load_modules():
    sys.path.insert(0, str(MODULES_DIR))
    for file in MODULES_DIR.glob("*.py"):
        mod_name = file.stem
        spec = importlib.util.spec_from_file_location(mod_name, file)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        LOADED_COMMANDS[mod_name] = mod


def set_current_session(name):
    global CURRENT_SESSION
    CURRENT_SESSION = name


def get_prompt():
    if CURRENT_SESSION:
        return colored(f"sabstract ({CURRENT_SESSION}) > ", "cyan")
    return colored("sabstract > ", "cyan")


def fetch_session_names():
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("SELECT name FROM sessions")
        return [row[0] for row in c.fetchall()]


def setup_autocomplete():
    def completer(text, state):
        buffer = readline.get_line_buffer().split()
        if not buffer:
            matches = list(LOADED_COMMANDS.keys()) + ["exit"]
        else:
            cmd = buffer[0]
            args_so_far = buffer[1:]

            if len(buffer) == 1:
                matches = [c for c in list(LOADED_COMMANDS.keys()) + ["exit"] if c.startswith(text)]
            elif cmd in LOADED_COMMANDS:
                mod = LOADED_COMMANDS[cmd]
                if hasattr(mod, "complete"):
                    try:
                        options = mod.complete(args_so_far)
                        if len(buffer) > 1:
                            matches = [o for o in options if o.startswith(text)]
                        else:
                            matches = options
                    except Exception:
                        matches = []
                else:
                    matches = []
            else:
                matches = []

        return matches[state] if state < len(matches) else None

    readline.parse_and_bind("tab: complete")
    readline.set_completer(completer)

def main():
    init_db()
    load_modules()
    setup_autocomplete()

    print(colored("""
    SAPPAS
    """, "green"))

    print(colored("Welcome to SAPstract. Type 'help' for options.\n", "yellow"))

    # Handle one-off command
    if len(sys.argv) > 1:
        base_cmd = sys.argv[1]
        args = sys.argv[2:]
        if base_cmd in LOADED_COMMANDS:
            LOADED_COMMANDS[base_cmd].run(args, set_current_session, CURRENT_SESSION)
        elif base_cmd == "exit":
            print("[*] Bye.")
        else:
            print(f"[!] Unknown command '{base_cmd}'. Type 'help'.")
        return

    while True:
        try:
            cmd = input(get_prompt()).strip()
            if not cmd:
                continue

            args = cmd.split()
            base_cmd = args[0]

            if base_cmd in LOADED_COMMANDS:
                LOADED_COMMANDS[base_cmd].run(args[1:], set_current_session, CURRENT_SESSION)
            elif base_cmd == "exit":
                print("[*] Bye.")
                break
            else:
                print(colored(f"[!] Unknown command '{base_cmd}'. Type 'help'.", "red"))

        except KeyboardInterrupt:
            print("\n[*] Bye.")
            break


if __name__ == "__main__":
    main()

