#!/usr/bin/env python3
import os
import sys
import shlex
import shutil
from pathlib import Path

from src.ui import info, warn, fail, plain, set_no_color, _colorize
from src.ascii_art import ASCII_BANNER, render_banner

APP_NAME = "SAPstract"
APP_VER  = "0.0.0-dev (skeleton)"
ROOT_DIR = Path(__file__).parent.resolve()

if os.environ.get("NO_COLOR") or os.environ.get("SAPSTRACT_NO_COLOR"):
    set_no_color(True)


def get_prompt():
    sap = _colorize("SAP", "blue", bold=True)
    stract = _colorize("stract", "white", bold=True)
    return f"{sap}{stract} > "


def print_ascii_banner():
    render_banner(ASCII_BANNER)
    info(f"{APP_NAME} — {APP_VER}")
    info("Type 'help' for available commands.")


def show_help():
    plain("""
Commands:
  help                  Show this help
  ls [dir ...]          List directory contents
  exit | quit | q       Exit
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
            entries = [name for name in entries if not name.startswith('.')]
        entries.sort()

        if len(paths) > 1:
            plain(f"{p}:")

        if not entries:
            plain("")
        else:
            # add / suffix for dirs
            entries_display = []
            for name in entries:
                fullpath = os.path.join(p, name)
                if os.path.isdir(fullpath):
                    entries_display.append(name + "/")
                else:
                    entries_display.append(name)

            maxlen = max(len(name) for name in entries_display)
            col_width = maxlen + 2
            cols = max(1, term_width // col_width)

            line_buf = ""
            col_idx = 0
            for name in entries_display:
                line_buf += name.ljust(col_width)
                col_idx += 1
                if col_idx == cols:
                    plain(line_buf.rstrip())
                    line_buf = ""
                    col_idx = 0
            if line_buf:
                plain(line_buf.rstrip())

        if i != len(paths) - 1:
            plain("")


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
        paths = [a for a in args if not a.startswith('-')]
        do_ls(paths, show_hidden=show_hidden)
        return

    fail(f"Unknown command '{cmd}'. Type 'help'.", src=None)


def main():
    if len(sys.argv) > 1:
        print_ascii_banner()
        run_command(" ".join(sys.argv[1:]))
        return

    print_ascii_banner()
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

