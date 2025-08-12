import json
import sqlite3
import importlib.util
from pathlib import Path

VULN_DIR = Path(__file__).parent.parent / "vuln"
WANTED_VULNS = ["checkCTC"]  

def _get(context, key, default=None):
    if context is None: return default
    if isinstance(context, dict): return context.get(key, default)
    return getattr(context, key, default)

def _load_vuln_module(name: str):
    p = VULN_DIR / f"{name}.py"
    if not p.exists():
        print(f"    -> Skipping {name}: not found in {VULN_DIR}")
        return None
    spec = importlib.util.spec_from_file_location(name, p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def _start_scan(conn, session_name, target, port, scheme, sap_label, web_module, note=""):
    cur = conn.cursor()
    cur.execute("""
      INSERT INTO web_scans(session_name,target,port,scheme,sap_label,web_module,notes)
      VALUES(?,?,?,?,?, ?, ?)
    """, (session_name, target, port, scheme, sap_label, web_module, note))
    return cur.lastrowid

def _finish_scan(conn, scan_id, status='COMPLETED', note=None):
    conn.execute("""
      UPDATE web_scans
      SET finished_at=CURRENT_TIMESTAMP,
          status=?,
          notes=COALESCE(?, notes)
      WHERE id=?
    """, (status, note, scan_id))

def _log_vuln(conn, scan_id, vuln_module, result, reason="", details=None):
    conn.execute("""
      INSERT INTO vuln_checks(scan_id, vuln_module, result, reason, details_json)
      VALUES(?, ?, ?, ?, ?)
      ON CONFLICT(scan_id, vuln_module) DO UPDATE SET
        result=excluded.result,
        reason=excluded.reason,
        details_json=excluded.details_json,
        created_at=CURRENT_TIMESTAMP
    """, (scan_id, vuln_module, result, reason,
          json.dumps(details) if details is not None else None))

def run(context=None):
    label      = _get(context, "sap_label", Path(__file__).stem)
    db_path    = _get(context, "db_path") 
    session    = _get(context, "session")
    target     = _get(context, "target")
    port       = _get(context, "port")
    scheme     = _get(context, "scheme", "http")
    web_module = label 

    print(f"    [SAP Service - {label} Module]")

    logging_enabled = all([db_path, session, target, port])

    scan_id = None
    if logging_enabled:
        with sqlite3.connect(db_path) as conn:
            scan_id = _start_scan(conn, session, target, port, scheme, label, web_module, note=f"Kickoff {label}")
            conn.commit()
    else:
        print("    -> Missing session/target/port/db_path; logging disabled.")

    if not WANTED_VULNS:
        print("    -> No vulns listed for this module.")
    else:
        errors = []
        for vuln in WANTED_VULNS:
            mod = _load_vuln_module(vuln)
            if not mod:
                continue
            try:
                try:
                    result = mod.run(context)
                except TypeError:
                    result = mod.run()
                if result not in ("VULNERABLE","NOT_VULNERABLE","INCONCLUSIVE","ERROR"):
                    result = "INCONCLUSIVE"
                reason  = getattr(mod, "LAST_REASON", "")
                details = getattr(mod, "LAST_DETAILS_JSON", None)

                if logging_enabled and scan_id is not None:
                    with sqlite3.connect(db_path) as conn:
                        _log_vuln(conn, scan_id, vuln, result, reason, details)
                        conn.commit()

                print(f"    -> {vuln}: {result}{' — ' + reason if reason else ''}")
            except Exception as e:
                errors.append(f"{vuln}: {e}")
                if logging_enabled and scan_id is not None:
                    with sqlite3.connect(db_path) as conn:
                        _log_vuln(conn, scan_id, vuln, "ERROR", f"{type(e).__name__}: {e}", None)
                        conn.commit()
                print(f"    -> {vuln} error: {e}")

        if logging_enabled and scan_id is not None:
            with sqlite3.connect(db_path) as conn:
                _finish_scan(conn, scan_id,
                             status=("ERROR" if errors else "COMPLETED"),
                             note="; ".join(errors) if errors else None)
                conn.commit()

