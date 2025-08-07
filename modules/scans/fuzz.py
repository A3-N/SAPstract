import sqlite3
import requests
from pathlib import Path
from modules.ui import info, success, warn, fail, plain

WORDLIST_DIR = Path(__file__).parent.parent / "src" / "wordlists"
SESSION_DB = Path(__file__).parent.parent.parent / "db" / "sapstract_sessions.db"
TIMEOUT = 5

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active.")
        return

    wordlist_file = WORDLIST_DIR / "sap_paths.txt"
    if not wordlist_file.exists():
        fail("Wordlist 'sap_paths.txt' not found in modules/src/wordlists/")
        return
    else:
        success(f"Found wordlist: {wordlist_file}")

    info(f"Checking open SAP ports for session '{current_session}'...")
    sap_ports = fetch_sap_ports(current_session)

    if not sap_ports:
        fail("No open SAP web ports found.")
        return

    success("Found SAP web ports:")
    targets_to_use = []
    for target, port, label in sap_ports:
        plain(f"  {target}:{port}  ({label})")
        scheme = detect_scheme(target, port)
        if scheme:
            success(f"Confirmed {scheme.upper()} service on {target}:{port}")
            targets_to_use.append((scheme, target, port))
        else:
            warn(f"{target}:{port} does not appear to be a web server")

    if not targets_to_use:
        fail("No usable SAP web services identified. Aborting.")
        return

    info("Initialization complete. Ready for fuzzing.")

def detect_scheme(host, port):
    schemes = [("https", True), ("https", False), ("http", True)]
    methods = ["GET", "OPTIONS", "HEAD"]

    for scheme, verify in schemes:
        url = f"{scheme}://{host}:{port}/"
        for method in methods:
            try:
                r = requests.request(method, url, timeout=TIMEOUT, verify=verify, allow_redirects=True)
                if 200 <= r.status_code < 500:
                    return scheme + (" (insecure)" if not verify and scheme == "https" else "")
            except requests.exceptions.SSLError:
                continue
            except requests.RequestException:
                continue
    return None

def fetch_sap_ports(session_name):
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT target, port, label FROM ports
            WHERE session_name = ?
              AND status = 'OPEN'
              AND label IS NOT NULL
              AND label != ''
        """, (session_name,))
        return c.fetchall()

def complete(args_so_far):
    return []

