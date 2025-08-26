#!/usr/bin/env python3
import os, sys, shlex, shutil
from pathlib import Path

from src.ui import info, warn, fail, plain, set_no_color, _colorize
from src.ascii_art import ASCII_BANNER, render_banner
from src.sessions import (
    get_current_session_name,
    set_session,
    remove_session,
    list_sessions,
    session_names,
)

APP_NAME = "SAPstract"
APP_VER  = "0.0.0-dev (skeleton)"
ROOT_DIR = Path(__file__).parent.resolve()

if os.environ.get("NO_COLOR") or os.environ.get("SAPSTRACT_NO_COLOR"):
    set_no_color(True)

COMMANDS = ["help", "ls", "set", "remove", "list", "exit", "quit", "q"]


def get_prompt():
    sap = _colorize("SAP", "blue", bold=True)
    stract = _colorize("stract", "white", bold=True)
    cur = get_current_session_name()
    return f"{sap}{stract} ({cur}) > " if cur else f"{sap}{stract} > "


def print_ascii_banner():
    render_banner(ASCII_BANNER)
    info(f"{APP_NAME} — {APP_VER}")
    info("Type 'help' for available commands.")


def show_help():
    plain("""
Commands:
  help                        Show this help
  ls [dir ...]                List directory contents
  set session <name>          Set current session (creates if needed)
  remove session <name>       Remove a session (and its stash)
  list session                List sessions (mark current), show IDs
  exit | quit | q             Exit
""")


def do_ls(paths, show_hidden=False):
    if not paths:
        paths = ['.']
    term_width = shutil.get_terminal_size((80, 20)).columns
    for i, p in enumerate(paths):
        try:
            entries = os.listdir(p)
        except Exception as e:
            fail(f"ls: cannot access '{p}': {e}")
            continue
        if not show_hidden:
            entries = [n for n in entries if not n.startswith('.')]
        entries.sort()
        if len(paths) > 1:
            plain(f"{p}:")
        if not entries:
            plain("")
        else:
            disp = [n + "/" if os.path.isdir(os.path.join(p, n)) else n for n in entries]
            maxlen = max(len(n) for n in disp)
            colw = maxlen + 2
            cols = max(1, term_width // colw)
            buf = ""
            ci = 0
            for n in disp:
                buf += n.ljust(colw)
                ci += 1
                if ci == cols:
                    plain(buf.rstrip())
                    buf = ""
                    ci = 0
            if buf:
                plain(buf.rstrip())
        if i != len(paths) - 1:
            plain("")


def _enable_tab_completion():
    try:
        import readline
    except ImportError:
        warn("Tab completion not available on this platform.")
        return

    def _complete_path(text):
        base = os.path.expanduser(text or "")
        d, partial = os.path.split(base)
        d = d or "."
        try:
            names = os.listdir(d)
        except Exception:
            return []
        out = []
        for n in names:
            if not n.startswith(partial):
                continue
            path = os.path.join(d, n)
            out.append(os.path.join(d, n) + (os.sep if os.path.isdir(path) else ""))
        return out

    def completer(text, state):
        buf = readline.get_line_buffer()
        beg = readline.get_begidx()
        end = readline.get_endidx()

        before = buf[:beg]
        try:
            tokens = shlex.split(before)
        except Exception:
            tokens = before.strip().split()

        if not tokens:
            options = [c for c in COMMANDS if c.startswith(text)]
        else:
            cmd = tokens[0]

            if cmd in ("set", "remove"):
                if len(tokens) == 1:
                    options = [w for w in ["session"] if w.startswith(text)]
                elif len(tokens) >= 2 and tokens[1] == "session":
                    options = [n for n in session_names() if n.startswith(text)]
                else:
                    options = []

            elif cmd == "list":
                if len(tokens) == 1:
                    options = [w for w in ["session"] if w.startswith(text)]
                else:
                    options = []

            elif cmd == "ls":
                options = _complete_path(text)

            else:
                options = []

        try:
            return sorted(options)[state]
        except IndexError:
            return None

    readline.set_completer_delims(' \t\n')
    readline.parse_and_bind('tab: complete')
    readline.set_completer(completer)


def run_command(cmdline: str):
    try:
        parts = shlex.split(cmdline)
    except ValueError as e:
        fail(f"parse error: {e}")
        return
    if not parts:
        return

    cmd, *args = parts

    if cmd in ("exit", "quit", "q"):
        info("Bye.")
        sys.exit(0)

    if cmd in ("help", "h", "?"):
        show_help()
        return

    if cmd == "ls":
        show_hidden = any(a.startswith('-') and ('a' in a or 'A' in a) for a in args)
        do_ls([a for a in args if not a.startswith('-')], show_hidden)
        return

    if cmd == "set" and len(args) >= 2 and args[0] == "session":
        name = " ".join(args[1:]).strip()
        res = set_session(name)
        (info if res["ok"] else fail)(res["msg"])
        return

    if cmd == "remove" and len(args) >= 2 and args[0] == "session":
        name = " ".join(args[1:]).strip()
        res = remove_session(name)
        (info if res["ok"] else warn)(res["msg"])
        return

    if cmd == "list" and (len(args) == 1 and args[0] == "session"):
        plain(list_sessions())
        return

    fail(f"Unknown command '{cmd}'. Type 'help'.", src=None)


def main():
    if len(sys.argv) > 1:
        print_ascii_banner()
        run_command(" ".join(sys.argv[1:]))
        return

    print_ascii_banner()
    _enable_tab_completion()

    while True:
        try:
            line = input(get_prompt())
        except EOFError:
            print()
            info("Bye.")
            break
        except KeyboardInterrupt:
            print()
            info("Bye.")
            sys.exit(0)

        try:
            run_command(line)
        except SystemExit:
            raise
        except Exception as e:
            fail(f"Unhandled error: {e!r}", src="core")


if __name__ == "__main__":
    main()

