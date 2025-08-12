import os
import sys
import socket
import threading
import queue
import sqlite3
from pathlib import Path

try:
    import colorama
    colorama.init()
except ImportError:
    if os.name == 'nt':
        print("[!] 'colorama' is required for Windows terminal support. Run: pip install colorama")
        sys.exit(1)

try:
    from modules.ui import info, success, warn, fail, plain
except ImportError as e:
    print(f"[!] Failed to import UI module: {e}")
    sys.exit(1)

try:
    from src.ports_label import build_port_labels, build_port_groups
except ImportError as e:
    print(f"[!] Failed to import port label logic: {e}")
    sys.exit(1)

SESSION_DB = Path(__file__).parent.parent.parent / "db" / "sapstract_sessions.db"
PORT_LABELS = build_port_labels()
PORT_GROUPS = build_port_groups()

def run(args, set_session, current_session):
    if not current_session:
        fail("No session active.")
        return

    if args:
        fail("Usage: scan ports")
        return

    targets = fetch_targets(current_session)
    if not targets:
        fail("No targets found for this session.")
        return

    ports = sorted(PORT_LABELS.keys())

    info(f"Selecting all target(s) from session {current_session} for port scan")
    info(f"SAP Port Scan: {len(ports)} will be scanned")

    for target in targets:
        if not is_host_reachable(target):
            warn(f"{target} does not appear reachable. Skipping.")
            continue

        success(f"Starting TCP scan for {target} on {len(ports)} ports...")
        results = tcp_scan(target, ports, max_threads=50)

        if not results["open"]:
            fail("No open ports found.")

        if results["filtered"]:
            warn(f"Filtered Ports : {len(results['filtered'])}")
        if results["closed"]:
            fail(f"Closed Ports   : {len(results['closed'])}")

        info("Storing results to database...")
        store_results(current_session, target, results)


def fetch_targets(session_name):
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        c.execute("SELECT target FROM targets WHERE session_name = ?", (session_name,))
        return [row[0] for row in c.fetchall()]


def store_results(session_name, target, results):
    with sqlite3.connect(SESSION_DB) as conn:
        c = conn.cursor()
        for state in ["open", "closed", "filtered"]:
            for port in results[state]:
                label = PORT_LABELS.get(port, "")
                group = PORT_GROUPS.get(port, "")
                c.execute("""
                    INSERT OR REPLACE INTO ports (
                        session_name, target, port, status, label, group_pattern
                    ) VALUES (?, ?, ?, ?, ?, ?)
                """, (session_name, target, port, state.upper(), label, group))
        conn.commit()

def is_host_reachable(ip):
    try:
        socket.gethostbyname(ip)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(2)
            s.connect_ex((ip, 1))
        return True
    except socket.gaierror:
        return False
    except OSError:
        return False

def tcp_scan(ip, ports, max_threads=30, timeout=5):
    task_queue = queue.Queue()
    result_queue = queue.Queue()

    for port in ports:
        task_queue.put((ip, port))

    threads = [
        PortScanner(task_queue, result_queue, timeout)
        for _ in range(max_threads)
    ]

    for t in threads:
        t.start()

    results = {}
    for _ in ports:
        host, port, status = result_queue.get()
        results[port] = status

        if status == "OPEN":
            label = PORT_LABELS.get(port, "")
            success(f"    {port:<5} OPEN      {label or '-'}")

    open_ports = sorted([p for p, s in results.items() if s == "OPEN"])
    closed_ports = sorted([p for p, s in results.items() if s == "CLOSED"])
    filtered_ports = sorted([p for p, s in results.items() if s == "FILTERED"])

    return {"open": open_ports, "closed": closed_ports, "filtered": filtered_ports}


class PortScanner(threading.Thread):
    def __init__(self, inq, outq, timeout=5):
        super().__init__()
        self.inq = inq
        self.outq = outq
        self.timeout = timeout
        self.daemon = True

    def run(self):
        while not self.inq.empty():
            try:
                host, port = self.inq.get_nowait()
                status = self.scan(host, port)
                self.outq.put((host, port, status))
                self.inq.task_done()
            except queue.Empty:
                break

    def scan(self, host, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
            return "OPEN"
        except socket.timeout:
            return "FILTERED"
        except ConnectionRefusedError:
            return "CLOSED"
        except OSError as e:
            if hasattr(e, 'errno') and e.errno == 113:
                return "FILTERED"
            elif hasattr(e, 'errno') and e.errno == 111:
                return "CLOSED"
            return "FILTERED"
        except Exception:
            return "FILTERED"


def complete(args_so_far):
    if len(args_so_far) == 0:
        return []
    return []

