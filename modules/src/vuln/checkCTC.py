import requests

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
        LAST_REASON = "No target/port context provided"
        return "INCONCLUSIVE"

    url = f"{scheme}://{target}:{port}/ctc/ConfigServlet"
    try:
        r = requests.head(url, timeout=10, verify=False, allow_redirects=False)
        code = r.status_code
        if code == 200:
            LAST_REASON = "HEAD /ctc/ConfigServlet returned 200"
            LAST_DETAILS_JSON = {"method": "HEAD", "status": code, "url": url}
            return "VULNERABLE"
        elif code in (401, 403, 404):
            LAST_REASON = f"HEAD blocked/hidden ({code})"
            LAST_DETAILS_JSON = {"method": "HEAD", "status": code, "url": url}
            return "NOT_VULNERABLE"
        else:
            LAST_REASON = f"Unexpected status {code}"
            LAST_DETAILS_JSON = {"method": "HEAD", "status": code, "url": url}
            return "INCONCLUSIVE"
    except Exception as e:
        LAST_REASON = f"{type(e).__name__}: {e}"
        LAST_DETAILS_JSON = {"error": str(e), "url": url}
        return "ERROR"

