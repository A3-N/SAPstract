#!/usr/bin/env python3
import os
import sys
from pathlib import Path

from src.ui import info, success, warn, fail, plain, set_no_color, _colorize
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
  version               Show version
  exit | quit | q       Exit
""")


def run_command(cmdline: str):
    parts = cmdline.strip().split()
    if not parts:
        return

    cmd, *args = parts

    if cmd in ("exit", "quit", "q"):
        info("Bye.")
        sys.exit(0)

    if cmd in ("help", "h", "?"):
        show_help()
        return

    if cmd == "version":
        info(f"{APP_NAME} version: {APP_VER}")
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

