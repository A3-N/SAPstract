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
        print("[!] colorama is required for Windows terminal support. Run: pip install colorama")
        sys.exit(1)

try:
    from modules.ui import info, success, warn, fail, plain
except ImportError as e:
    print(f"[!] Failed to import UI module: {e}")
    sys.exit(1)

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

LAST_REASON = ""
LAST_DETAILS_JSON = None

def run(context=None):
    global LAST_REASON, LAST_DETAILS_JSON
    LAST_REASON = ""
    LAST_DETAILS_JSON = None

    target = getattr(context, "target", None) if context else None
    port   = getattr(context, "port", None) if context else None
    scheme = getattr(context, "scheme", "https") if context else "https"

    if not (target and port):
        fail("No target or port context provided")
        LAST_REASON = "No target or port context provided"
        return "INCONCLUSIVE"

    variants = [
        "/ctc/ConfigServlet",
        "/ctc/ConfigServlet/",
        "/CTC/ConfigServlet"
    ]

    for path in variants:
        url = f"{scheme}://{target}:{port}{path}"
        info(f"Checking {url}")

        try:
            r = requests.get(url, timeout=10, verify=False, allow_redirects=False, headers={
                "Range": "bytes=0-2048",
                "Accept": "text/html,*/*;q=0.1"
            })
            code = r.status_code
            body = (r.text or "")[:2048]

            if code == 200:
                if "ConfigServlet" in body or "com.sap.ctc" in body or "<title>Config Tool" in body:
                    if "<form" in body and "j_security_check" in body:
                        LAST_REASON = "Login page detected"
                        LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url}
                        success("Present protected")
                        return "PRESENT_PROTECTED"
                    else:
                        LAST_REASON = "CTC markers found"
                        LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url}
                        warn("Vulnerable")
                        return "VULNERABLE"
                else:
                    LAST_REASON = "No CTC markers"
                    LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url}
                    warn("Inconclusive")
                    return "INCONCLUSIVE"

            elif code in (401, 403):
                LAST_REASON = f"Access denied {code}"
                LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url}
                success("Present protected")
                return "PRESENT_PROTECTED"

            elif code in (301, 302, 303, 307, 308):
                loc = r.headers.get("Location", "")
                if any(s in loc for s in ["/irj", "/nwa", "/ctc/"]):
                    LAST_REASON = f"Redirect to {loc}"
                    LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url, "location": loc}
                    success("Present inferred")
                    return "PRESENT_INFERRED"
                else:
                    LAST_REASON = f"Redirect to {loc}"
                    LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url, "location": loc}
                    warn("Inconclusive")
                    return "INCONCLUSIVE"

            elif code == 404:
                LAST_REASON = "Not found"
                LAST_DETAILS_JSON = {"method": "GET", "status": code, "url": url}
                fail("Not found")
                return "NOT_FOUND"

        except Exception as e:
            LAST_REASON = f"{type(e).__name__}: {e}"
            LAST_DETAILS_JSON = {"error": str(e), "url": url, "method": "GET"}
            fail(f"Error {e}")
            return "ERROR"

    warn("No variants matched")
    return "NOT_FOUND"

