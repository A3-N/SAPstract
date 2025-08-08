import sys

try:
    from modules.ui import info, success, warn, fail, plain
except ImportError as e:
    print(f"[!] Failed to import UI module: {e}")
    sys.exit(1)

# Add more subcommands here as needed
SUBCOMMANDS = {
    "wiki": "wiki"
}

def run(args, set_session, current_session):
    if not args:
        fail("Usage: sap <subcommand>")
        return

    subcmd = args[0]
    if subcmd not in SUBCOMMANDS:
        fail(f"Unknown sap subcommand: {subcmd}")
        return

    try:
        module_name = SUBCOMMANDS[subcmd]
        mod = __import__(f"docs.{module_name}", fromlist=["run"])
        mod.run(args[1:], set_session, current_session)
    except Exception as e:
        fail(f"Failed to execute sap {subcmd}: {e}")

def complete(args_so_far):
    if len(args_so_far) == 0:
        return list(SUBCOMMANDS.keys())
    elif len(args_so_far) == 1:
        return [cmd for cmd in SUBCOMMANDS if cmd.startswith(args_so_far[0])]
    elif args_so_far[0] in SUBCOMMANDS:
        try:
            mod = __import__(f"docs.{SUBCOMMANDS[args_so_far[0]]}", fromlist=["complete"])
            return mod.complete(args_so_far[1:])
        except Exception:
            return []
    return []

