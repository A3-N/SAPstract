import os
import sys

try:
    import colorama
    colorama.init()
except ImportError:
    if os.name == 'nt':
        print("[!] 'colorama' is required for colored output on Windows.")
        print("    Run: pip install colorama")
        sys.exit(1)

try:
    from termcolor import colored
except ImportError:
    print("[!] 'termcolor' is required. Run: pip install termcolor")
    sys.exit(1)


def info(msg):
    print(f"{colored('[*]', 'blue')} {msg}")


def success(msg):
    print(f"{colored('[+]', 'green')} {msg}")


def warn(msg):
    print(f"{colored('[!]', 'yellow')} {msg}")


def fail(msg):
    print(f"{colored('[-]', 'red')} {msg}")


def plain(msg):
    print(msg)


def bold(msg):
    print(colored(msg, attrs=["bold"]))

