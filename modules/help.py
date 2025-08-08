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


def run(args, set_session, current_session):
    def section(title, rows):
        print(f"\n{colored(title, 'cyan')}")
        print("+" + "-" * 30 + "+" + "-" * 60 + "+")
        for cmd, desc in rows:
            print(f"| {cmd:<29}| {desc:<59}|")
        print("+" + "-" * 30 + "+" + "-" * 60 + "+")

    section("Session Management", [
        ("session start <name>", "Create or resume a session."),
        ("session set <name>", "Switch to an existing session."),
        ("session list", "List all saved sessions."),
        ("session delete <name>", "Delete a session and its data."),
    ])

    section("Target Management", [
        ("target set <host>", "Add a target host/IP to the session."),
        ("target list", "List all targets in the current session."),
        ("target delete <host>", "Remove a target from the session."),
    ])

    section("Scanning", [
        ("scan ports", "Scan session targets for known SAP ports."),
        ("scan web", "Fingerprint and verify SAP web services."),
    ])

    section("SAP Intelligence", [
        ("sap", "Run SAP-related enumeration commands."),
        ("sap wiki <term>", "Search and view SAP wiki docs (e.g., port details)."),
        ("sap manual", "View SAP manual entries (e.g., TCodes, client/SID info)."),
    ])

    section("General", [
        ("help", "Display this help menu."),
        ("exit", "Exit the CLI interface."),
    ])

