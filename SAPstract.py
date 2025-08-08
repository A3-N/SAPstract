import os
import sys
import sqlite3
import importlib.util
from termcolor import colored
from pathlib import Path

try:
    import readline
except ImportError:
    if os.name == 'nt':
        try:
            import pyreadline3 as readline
        except ImportError:
            print("[!] Windows requires 'pyreadline3'. Run: pip install pyreadline3")
            sys.exit(1)
    else:
        raise

try:
    import colorama
    colorama.init()
except ImportError:
    if os.name == 'nt':
        print("[!] 'colorama' required for colored output. Run: pip install colorama")
        sys.exit(1)

from termcolor import colored
from modules.ui import info, success, warn, fail, plain

if os.name == 'nt':
    os.system("chcp 65001 >NUL")

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
        c.execute("""
        CREATE TABLE IF NOT EXISTS sap_http_services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            session_name TEXT NOT NULL,
            target TEXT NOT NULL,
            port INTEGER NOT NULL,
            scheme TEXT NOT NULL,
            sap_label TEXT NOT NULL,
            sap_type TEXT,
            service_name TEXT,
            paths TEXT,
            metadata TEXT,
            UNIQUE(session_name, target, port, sap_label)
        )
        """)# this db is not being used, but im keeping it as a reminder to use it one day lol
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
    sap = colored("SAP", "blue")
    stract = colored("stract", "white")
    if CURRENT_SESSION:
        return f"{sap}{stract} ({CURRENT_SESSION}) > "
    return f"{sap}{stract} > "


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

    print("""\033[94m
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\033[97m.dBBBBP dBBBBBBP dBBBBBb dBBBBBb     dBBBP dBBBBBBP\033[94m
     @@@@#+-     .=+*%@@@@@*:::::=@@@@@*:::::::-==+*%@@@@@@@@@@@@@@@@ \033[97m.BP                   dBP      BB\033[94m                       
     @@+              *@@@%       =@@@@+              +@@@@@@@@@@@@   \033[97m`BBBBb   dBP     dBBBBK   dBP BB   dBP      dBP\033[94m    
     @=      .::     %@@@@         +@@@+               :@@@@@@@@@@       \033[97mdBP  dBP     dBP  BB  dBP  BB  dBP      dBP\033[94m
     @      @@@@@@@@@@@@@-          %@@+     +@@@%-     +@@@@@@     \033[97mdBBBBP'  dBP     dBP  dB' dBBBBBBB dBBBBP   dBP\033[94m 
     @.       :*%@@@@@@@+     =     =@@+     +@@@@=     +@@@@      \033[97m-----------------------------------------------------\033[94m     
     @%:           =*@@#     -%=     +@+     :+++:      %@@@        \033[97mTool: SAPstract  — SAP enumeration & fuzzing toolkit\033[94m
     @@@#+           :*:     *@@      #+               #@@          \033[97mBy:   @A3-N      — github.com/A3-N/SAPstract\033[94m     
     @@@@@@@%#+.             +#*:     -+            =#@@            \033[97mCred: Bizsploit  — Mariano Nuñez Di Croce\033[94m
     @@%*@@@@@@@-                      .     +@@@@@@@@                    \033[97mMetasploit — rapid7\033[94m
     @%.                                     +@@@@@@                      \033[97mpysap      — OWASP\033[94m 
     @-                   -@@%%%@@+          +@@@@                          
     @@@#+=-. .-=@@@@@@@@@@@@@@@@@+=@@@#@@@@@@@@                    
     @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@                          \033[97mDeveloped while doing ur mom, loser\033[94m
    """)

    if len(sys.argv) > 1:
        base_cmd = sys.argv[1]
        args = sys.argv[2:]
        if base_cmd in LOADED_COMMANDS:
            LOADED_COMMANDS[base_cmd].run(args, set_current_session, CURRENT_SESSION)
        elif base_cmd == "exit":
            os.system("cls" if os.name == "nt" else "clear")
            info("Bye.")
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
                os.system("cls" if os.name == "nt" else "clear")
                info("Bye.")
                break
            else:
                print(colored(f"[!] Unknown command '{base_cmd}'. Type 'help'.", "red"))

        except KeyboardInterrupt:
            os.system("cls" if os.name == "nt" else "clear")
            print("")
            info("Bye.")
            break


if __name__ == "__main__":
    main()

