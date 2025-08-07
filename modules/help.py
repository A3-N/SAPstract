from termcolor import colored

def run(args, set_session, current_session):
    def section(title, rows):
        print(f"\n{colored(title, 'cyan')}")
        print("+" + "-" * 28 + "+" + "-" * 45 + "+")
        for cmd, desc in rows:
            print(f"| {cmd:<27}| {desc:<44}|")
        print("+" + "-" * 28 + "+" + "-" * 45 + "+")

    section("Session Commands", [
        ("session start <name>", "Start (or create) a session"),
        ("session set <name>", "Switch to an existing session"),
        ("session list", "List all saved sessions"),
        ("session delete <name>", "Delete a session"),
    ])

    section("Target Commands", [
        ("target add <host>", "Add a target to the session"),
        ("target list", "List all session targets"),
        ("target delete <host>", "Delete a target from session"),
    ])

    section("Scan Commands", [
        ("scan ports", "Scan session targets for SAP ports"),
    ])

    section("General", [
        ("help", "Show this help menu"),
        ("exit", "Exit the CLI"),
    ])

