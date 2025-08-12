import os
import sys
import sqlite3
import importlib.util
from pathlib import Path
from types import SimpleNamespace

try:
    from modules.ui import info, success, warn, fail, plain
except ImportError as e:
    print(f"[!] Failed to import UI module: {e}")
    sys.exit(1)

# DB + check locations
SESSION_DB = Path(__file__).parent.parent.parent / "db" / "sapstract_sessions.db"
SRC_DIR    = Path(__file__).parent.parent / "src" / "web"

# Only treat these groups as web-facing. Everything else is ignored.
WEB_GROUPS = {
    # ABAP/ICM & MsgServer HTTP/S
    "80NN", "443NN", "81NN", "444NN",
    # Java HTTP/S variants
    "5NN00", "5NN01", "5NN05", "5NN06", "5NN19",
    # IGS admin HTTP
    "4NN80",
    # ITS via fixed ports (store group as "ITS")
    "ITS",
    # Common fixed HTTP/S if you store them as groups
    "80", "443",
    # SAPinst / Upgrade HTTP UIs (store group as literal)
    "21212", "21213", "4239",
}

def infer_scheme(label: str, port: int) -> str:
    # HTTPS by label hints or obvious port
    if label in ("443NN", "444NN", "443", "5NN01", "5NN06"):
        return "https"
    if port == 443:
        return "https"
    return "http"

def execute_check(label: str, context):
    script_path = SRC_DIR / f"{label}.py"
    if not script_path.exists():
        warn(f"No check defined for: {label}")
        return

    spec = importlib.util.spec_from_file_location(label, script_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        if hasattr(module, "run"):
            module.run(context)
        else:
            success(f"Executed {label}.py (no run() function found)")
    except Exception as e:
        fail(f"Failed to run {label}.py: {e}")

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active.")
        return

    info(f"Checking open SAP web ports for session '{current_session}'")

    # Pull open ports with their group pattern from DB
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT target, port, group_pattern
            FROM ports
            WHERE session_name = ? AND status = 'OPEN'
        """, (current_session,))
        rows = c.fetchall()

    if not rows:
        fail("No open ports found.")
        return

    # Group by target; keep (port, group) tuples
    target_ports = {}
    for target, port, group in rows:
        g = (group or "").strip()
        target_ports.setdefault(target, []).append((int(port), g))

    executed = set()  # dedupe per (group@target)

    for target, pairs in sorted(target_ports.items()):
        # Keep only entries with a non-empty group that we consider web
        web_pairs = sorted([(p, g) for p, g in pairs if g and g in WEB_GROUPS])
        if not web_pairs:
            continue

        info(f"Web-capable services on {target}:")
        for port, grp in web_pairs:
            plain(f"    {target}:{port}  [{grp}]")

        for port, label in web_pairs:
            key = f"{label}@{target}"
            if key in executed:
                continue
            executed.add(key)

            scheme = infer_scheme(label, port)
            ctx = SimpleNamespace(
                session=current_session,
                target=target,
                port=port,
                scheme=scheme,
                sap_label=label,  # used as the module name under src/web/
                db_path=str(SESSION_DB)
            )

            info(f"Running check module for group: {label} (host: {target})")
            success(f"{label}:")
            execute_check(label, ctx)

