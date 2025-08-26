import json, os, uuid, shutil
from pathlib import Path
from typing import Dict, Any, Optional, List

_APP_DIR = Path(os.environ.get("SAPSTRACT_HOME", Path.home() / ".sapstract")).resolve()
_STORE   = _APP_DIR / "sessions.json"
_SESSDIR = _APP_DIR / "sessions"

def _ensure_base_dirs() -> None:
    _APP_DIR.mkdir(parents=True, exist_ok=True)
    _SESSDIR.mkdir(parents=True, exist_ok=True)

def _sanitize(data: Dict[str, Any]) -> Dict[str, Any]:
    """Ensure expected shapes; coerce/skip bad entries."""
    if not isinstance(data, dict):
        return {"current": None, "sessions": {}}
    data.setdefault("current", None)
    sessions = data.get("sessions", {})
    if not isinstance(sessions, dict):
        sessions = {}
    cleaned: Dict[str, Dict[str, str]] = {}
    for sid, meta in sessions.items():
        name = ""
        if isinstance(meta, dict):
            nm = meta.get("name", "")
            name = nm if isinstance(nm, str) else str(nm)
        if name:
            cleaned[str(sid)] = {"name": name}
    return {"current": data.get("current"), "sessions": cleaned}

def _load() -> Dict[str, Any]:
    _ensure_base_dirs()
    if not _STORE.exists():
        return {"current": None, "sessions": {}}
    try:
        with _STORE.open("r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        return {"current": None, "sessions": {}}
    return _sanitize(raw)

def _save(data: Dict[str, Any]) -> None:
    _ensure_base_dirs()
    clean = _sanitize(data)
    tmp = _STORE.with_suffix(".json.tmp")
    with tmp.open("w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2, sort_keys=True)
    os.replace(tmp, _STORE)

def _new_id() -> str:
    return uuid.uuid4().hex[:12]

def _find_id_by_name(data: Dict[str, Any], name: str) -> Optional[str]:
    target = name.strip().lower()
    for sid, meta in data.get("sessions", {}).items():
        nm = meta.get("name", "")
        if isinstance(nm, str) and nm.strip().lower() == target:
            return sid
    return None

def get_current_session_name() -> Optional[str]:
    data = _load()
    sid = data.get("current")
    if not sid:
        return None
    meta = data.get("sessions", {}).get(sid) or {}
    nm = meta.get("name")
    return nm if isinstance(nm, str) and nm else None

def get_stash_dir(session_id: Optional[str], create=True) -> Optional[Path]:
    if not session_id:
        return None
    path = (_SESSDIR / session_id).resolve()
    if create:
        path.mkdir(parents=True, exist_ok=True)
    return path

def set_session(name: str) -> Dict[str, str]:
    name = name.strip()
    if not name:
        return {"ok": False, "msg": "Usage: set <session>"}
    data = _load()
    sid = _find_id_by_name(data, name) or _new_id()
    if "sessions" not in data or not isinstance(data["sessions"], dict):
        data["sessions"] = {}
    data["sessions"][sid] = {"name": name}
    data["current"] = sid
    _save(data)
    stash = get_stash_dir(sid, True)
    return {"ok": True, "msg": f"Session set to '{name}' (id={sid}). Stash: {stash}"}

def remove_session(name: str) -> Dict[str, str]:
    name = name.strip()
    if not name:
        return {"ok": False, "msg": "Usage: remove <session>"}
    data = _load()
    sid = _find_id_by_name(data, name)
    if not sid:
        return {"ok": False, "msg": f"Session '{name}' not found."}
    try:
        del data["sessions"][sid]
    except Exception:
        data = _sanitize(data)
        if sid in data["sessions"]:
            del data["sessions"][sid]
    if data.get("current") == sid:
        data["current"] = None
    _save(data)
    try:
        shutil.rmtree(_SESSDIR / sid)
    except Exception:
        pass
    return {"ok": True, "msg": f"Removed session '{name}' and its stash."}

def list_sessions() -> str:
    data = _load()
    cur = data.get("current")
    items = data.get("sessions", {})
    if not items:
        return "No sessions."
    def _key(item):
        sid, meta = item
        nm = meta.get("name", "")
        nm = nm if isinstance(nm, str) else str(nm)
        return (nm.lower(), sid)
    lines: List[str] = []
    for sid, meta in sorted(items.items(), key=_key):
        nm = meta.get("name", "")
        nm = nm if isinstance(nm, str) else str(nm)
        marker = " *" if sid == cur else ""
        lines.append(f"{nm} (id={sid}){marker}")
    if cur:
        stash = get_stash_dir(cur, True)
        lines.append("")
        lines.append(f"Current stash: {stash}")
    return "\n".join(lines)

def session_names() -> List[str]:
    data = _load()
    names: List[str] = []
    for meta in data.get("sessions", {}).values():
        nm = meta.get("name", "")
        if isinstance(nm, str) and nm:
            names.append(nm)
    return names

