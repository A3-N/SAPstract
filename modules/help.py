from termcolor import colored

def run(args, set_session, current_session):
    def section(title, rows):
        print(f"\n{colored(title, 'cyan')}")
        print("+" + "-" * 30 + "+" + "-" * 60 + "+")
        for cmd, desc in rows:
            print(f"| {cmd:<29}| {desc:<59}|")
        print("+" + "-" * 30 + "+" + "-" * 60 + "+")

    section("Session Management", [
        ("session start <name>", "Create a new session or resume if it already exists."),
        ("session set <name>", "Switch to an existing session for subsequent operations."),
        ("session list", "Show all saved sessions with creation timestamps."),
        ("session delete <name>", "Delete a session and its associated targets and results."),
    ])

    section("Target Management", [
        ("target set <host>", "Add a target host/IP to the current session."),
        ("target list", "Show all targets added to the current session."),
        ("target delete <host>", "Remove a specific target from the current session."),
    ])

    section("Scanning & Fuzzing", [
        ("scan ports", "Scan all session targets for known SAP-related ports."),
        ("scan fuzz", "Fuzz confirmed SAP web services using a wordlist."),
        ("scan fuzz threads <n> delay <s> status <codes>", "Custom thread count, delay, and status codes for fuzz."),
    ])

    section("Session Context", [
        ("set_session(name)", "This is auto-handled. Most commands require a session to be active."),
    ])

    section("General Usage", [
        ("help", "Show this help menu with available commands."),
        ("exit", "Exit the CLI interface."),
    ])

