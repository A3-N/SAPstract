from collections import defaultdict
from queue import Queue
from threading import Thread
import time
import sqlite3
import requests
from pathlib import Path
from modules.ui import info, success, warn, fail, plain

WORDLIST_DIR = Path(__file__).parent.parent / "src" / "wordlists"
SESSION_DB = Path(__file__).parent.parent.parent / "db" / "sapstract_sessions.db"
TIMEOUT = 5
HOST_PAD = 15
PORT_PAD = 6

def parse_fuzz_args(args):
    config = {
        "threads": 10,
        "delay": 0.0,
        "status": [200, 301, 403],
    }

    args = [a.lower() for a in args]
    for i in range(len(args)):
        if args[i] == "threads" and i + 1 < len(args):
            try:
                config["threads"] = int(args[i + 1])
            except ValueError:
                pass
        elif args[i] == "delay" and i + 1 < len(args):
            try:
                config["delay"] = float(args[i + 1])
            except ValueError:
                pass
        elif args[i] == "status" and i + 1 < len(args):
            try:
                config["status"] = [int(x.strip()) for x in args[i + 1].split(',')]
            except ValueError:
                pass
    return config

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active.")
        return

    # Based on MetaSploit data/wordlist
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

    confirmed_hosts = defaultdict(list)
    targets_to_use = []

    for target, port, label in sap_ports:
        scheme = detect_scheme(target, port)
        if scheme:
            confirmed_hosts[target].append((scheme, port, label))
        else:
            warn(f"{target}:{port} does not appear to be a web server")

    for target, entries in confirmed_hosts.items():
        scheme_set = {s for s, _, _ in entries}
        scheme = list(scheme_set)[0] if len(scheme_set) == 1 else "Mixed"
        success(f"Confirmed {scheme.upper()} service on {target}")
        for scheme, port, label in sorted(entries, key=lambda x: x[1]):
            plain(f"    {target:<{HOST_PAD}}:{str(port):<{PORT_PAD}}  ({label})")
            targets_to_use.append((scheme, target, port))

    if not targets_to_use:
        fail("No usable SAP web services identified. Aborting.")
        return

    info("Initialization complete. Ready for fuzzing.")
    config = parse_fuzz_args(args)
    info(f"Starting fuzz with threads={config['threads']}, delay={config['delay']}, status={config['status']}")

    q = Queue()
    for scheme, target, port in targets_to_use:
        with open(wordlist_file) as f:
            for line in f:
                path = line.strip().lstrip('/')
                if not path:
                    continue
                q.put((scheme, target, port, f"/{path}"))

    def worker():
        while not q.empty():
            scheme, target, port, path = q.get()
            url = f"{scheme.replace(' (insecure)', '')}://{target}:{port}{path}"
            try:
                verify_ssl = not scheme.endswith("(insecure)")
                r = requests.get(url, timeout=TIMEOUT, verify=verify_ssl)
                code = r.status_code

                if code in config["status"]:
                    if 200 <= code < 300:
                        log = success
                    elif 300 <= code < 400:
                        log = info
                    elif 400 <= code < 500:
                        log = warn
                    else:
                        log = fail

                    log(f"{target}:{port:<5} {code} - {path}")

                with sqlite3.connect(SESSION_DB) as conn:
                    c = conn.cursor()
                    c.execute("""
                        INSERT OR IGNORE INTO paths (
                            session_name, target, port, scheme, path, status_code
                        ) VALUES (?, ?, ?, ?, ?, ?)
                    """, (current_session, target, port, scheme, path, code))
                    conn.commit()

            except requests.RequestException as e:
                fail(f"ERR - {path} ({str(e).split(':')[0]})")

            time.sleep(config["delay"])
            q.task_done()

    threads = []
    for _ in range(config["threads"]):
        t = Thread(target=worker)
        t.daemon = True
        t.start()
        threads.append(t)

    q.join()
    success("Fuzzing complete.")

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

