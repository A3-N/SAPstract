import json
import time
import requests
from urllib.parse import urlparse, urljoin
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.text import Text
from src.console import console, print_info, print_bad, print_summary

requests.packages.urllib3.disable_warnings()

def load_json(path):
    with open(path, "r") as f:
        return json.load(f)

def parse_target(target):
    if not target.startswith("http"):
        target = "http://" + target
    parsed = urlparse(target)
    return {
        "host": parsed.hostname,
        "port": parsed.port,
        "scheme": parsed.scheme,
        "user_port": parsed.port is not None,
        "user_scheme": True
    }

def is_web_service(host, port, scheme):
    url = f"{scheme}://{host}:{port}/"
    try:
        requests.head(url, timeout=3)
        return True
    except requests.exceptions.SSLError:
        try:
            requests.head(url, timeout=3, verify=False)
            return True
        except:
            return False
    except:
        return False

def scan_path(url, path, verbose, pause):
    time.sleep(pause)
    full_url = urljoin(url, path.lstrip("/"))
    try:
        r = requests.get(full_url, timeout=5, verify=False)
        if r.status_code == 200:
            return path, "OK"
        elif r.status_code in [401, 403]:
            return path, "AUTH REQUIRED"
        else:
            return path, f"Status {r.status_code}"
    except Exception as e:
        if verbose:
            msg = str(e).split(":")[-1].strip()
            return path, f"ERROR: {msg}"
        return path, None

def enum_sap(target, pause, verbose, threads):
    parsed = parse_target(target)
    ports_map = load_json("src/resources/sap_ports.json")
    paths_map = load_json("src/resources/sap_paths.json")

    host = parsed["host"]
    user_port = parsed["port"]
    user_scheme = parsed["scheme"]

    all_ports = set()
    for scheme_ports in ports_map.values():
        all_ports.update(int(p) for p in scheme_ports)
    if user_port:
        all_ports.add(user_port)

    print_summary(host, sorted(all_ports))

    for scheme in ["http", "https"]:
        defined_ports = ports_map.get(scheme, {})

        ports_to_scan = set(int(p) for p in defined_ports)
        if user_port:
            ports_to_scan.add(user_port)

        prioritized = []
        if user_port:
            prioritized.append(user_port)
        prioritized += sorted(p for p in ports_to_scan if p != user_port)

        for port in prioritized:
            sap_types = defined_ports.get(str(port), ["ABAP", "JAVA", "BOE", "HANA"])
            url = f"{scheme}://{host}:{port}/"

            if not is_web_service(host, port, scheme):
                if verbose:
                    print_bad(f"Skipping port {port:<5} ({scheme}) - no web service")
                continue

            relevant_paths = {p: t for p, t in paths_map.items() if t in sap_types}
            if not relevant_paths:
                continue

            print_info(f"Scanning        : {scheme}://{host}:{port} ({', '.join(sap_types)})")

            with ThreadPoolExecutor(max_workers=threads) as executor:
                futures = {
                    executor.submit(scan_path, url, path, verbose, pause): path
                    for path in relevant_paths
                }
                for future in as_completed(futures):
                    path, status = future.result()
                    if not status:
                        continue
                    if status == "OK":
                        console.print(f"    {path:<22} -> OK")
                    elif status == "AUTH REQUIRED":
                        console.print(f"    {path:<22} -> AUTH REQUIRED")
                    elif verbose:
                        print_bad(f"{path:<22} -> {status}")

