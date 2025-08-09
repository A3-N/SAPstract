LAST_REASON = ""
LAST_DETAILS_JSON = None

def run(context=None):
    global LAST_REASON, LAST_DETAILS_JSON
    LAST_REASON = ""
    LAST_DETAILS_JSON = None

    target = getattr(context, "target", None) if context else None
    port   = getattr(context, "port", None)   if context else None
    scheme = getattr(context, "scheme", "http") if context else "http"

    # implement your logic here
    if not (target and port):
        LAST_REASON = "No target/port context provided"
        return "INCONCLUSIVE"

    # example placeholder:
    # url = f"{scheme}://{target}:{port}/..."
    # ... do request / check ...
    # LAST_REASON = "explanation"
    # LAST_DETAILS_JSON = {"any": "structured data"}

    return "NOT_VULNERABLE"

