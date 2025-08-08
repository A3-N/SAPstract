import os
import sys
import sqlite3
import importlib.util
from pathlib import Path

try:
    from modules.ui import info, success, warn, fail, plain
except ImportError as e:
    print(f"[!] Failed to import UI module: {e}")
    sys.exit(1)

SESSION_DB = Path(__file__).parent.parent.parent / "db" / "sapstract_sessions.db"
SRC_DIR = Path(__file__).parent.parent / "src"

# Baseline normalization based on SAP label structures
def normalize_port_label(port):
    # NetWeaver ABAP
    if 8000 <= port <= 8099: return "80NN"
    if 44300 <= port <= 44399: return "443NN"
    if 8100 <= port <= 8199: return "81NN"
    if 44400 <= port <= 44499: return "444NN"

    # NetWeaver JAVA (HTTP variants only)
    if 50000 <= port <= 50999:
        suffix = str(port)[-2:]
        if suffix in ['00', '01', '05', '06']:
            return f"5NN{suffix}"
        if suffix == '19':  # SDM HTTP
            return "5NN19"

    # SAP IGS (HTTP-only admin port)
    if 40080 <= port <= 40089:  # covers 4NN80
        return "4NN80"

    # SAPinst (only ones known to expose HTTP UI)
    if port in [21212, 21213]: return str(port)

    # SAP Upgrade Assistant HTTP
    if port == 4239: return str(port)

    # ITS (Internet Transaction Server)
    if port in [3950, 3951, 3954, 3964]: return "ITS"

    # Common HTTP/HTTPS ports
    if port == 80: return "80"
    if port == 443: return "443"

    return None

def fetch_open_ports(session_name):
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT DISTINCT port FROM ports
            WHERE session_name = ? AND status = 'OPEN'
        """, (session_name,))
        return sorted(set(row[0] for row in c.fetchall()))

def execute_check(label):
    script_path = SRC_DIR / f"{label}.py"
    if not script_path.exists():
        warn(f"No check defined for: {label}")
        return

    spec = importlib.util.spec_from_file_location(label, script_path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
        if hasattr(module, "run"):
            module.run()
        else:
            success(f"Executed {label}.py (no run() function found)")
    except Exception as e:
        fail(f"Failed to run {label}.py: {e}")

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active.")
        return

    info(f"Checking open SAP ports for session '{current_session}'")

    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT target, port FROM ports
            WHERE session_name = ? AND status = 'OPEN'
        """, (current_session,))
        rows = c.fetchall()

    if not rows:
        fail("No open ports found.")
        return

    target_ports = {}
    for target, port in rows:
        target_ports.setdefault(target, set()).add(port)

    executed = set()

    for target, ports in sorted(target_ports.items()):
        web_ports = sorted([p for p in ports if normalize_port_label(p)])
        if not web_ports:
            continue  

        info(f"Looking for HTTP/S SAP services on {target}:")
        for port in web_ports:
            plain(f"    {target}:{port}")

        for port in web_ports:
            label = normalize_port_label(port)
            if not label:
                continue
            key = f"{label}@{target}"
            if key in executed:
                continue
            executed.add(key)
            info(f"Running check module for port label: {label} (host: {target})")
            success(f"{label}:")
            execute_check(label)

