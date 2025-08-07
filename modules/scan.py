import socket
import threading
import queue
import sqlite3
from pathlib import Path
import importlib.util
from modules.ui import info, success, warn, fail, plain
from scans.ports_label import build_port_labels

SESSION_DB = Path(__file__).parent.parent / "db" / "sapstract_sessions.db"

# Hardcoded scan subcommands and their corresponding modules
SUBCOMMANDS = {
    "ports": "ports",
    "fuzz": "fuzz"
}

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active.")
        return

    if not args:
        fail("Usage: scan <subcommand>")
        return

    subcmd = args[0]
    if subcmd not in SUBCOMMANDS:
        fail(f"Unknown scan subcommand: {subcmd}")
        return

    # Import the corresponding subcommand module dynamically
    try:
        module_name = SUBCOMMANDS[subcmd]
        mod = __import__(f"scans.{module_name}", fromlist=["run"])
        mod.run(args[1:], set_session, current_session)
    except Exception as e:
        fail(f"Failed to execute scan {subcmd}: {e}")

def complete(args_so_far):
    if len(args_so_far) == 0:
        return list(SUBCOMMANDS.keys())
    elif len(args_so_far) == 1:
        return [cmd for cmd in SUBCOMMANDS if cmd.startswith(args_so_far[0])]
    elif args_so_far[0] in SUBCOMMANDS:
        try:
            mod = __import__(f"scans.{SUBCOMMANDS[args_so_far[0]]}", fromlist=["complete"])
            return mod.complete(args_so_far[1:])
        except Exception:
            return []
    return []

