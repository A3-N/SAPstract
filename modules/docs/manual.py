import os
import sys
import json
from pathlib import Path
from textwrap import wrap

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


def run(args, set_session=None, current_session=None):
    DOCS_DIR = Path(__file__).parent
    manual_files = sorted(DOCS_DIR.glob("m_*.json"))
    entries = []

    for file in manual_files:
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)
            title = data.get("title", "(no title found)")
            entries.append((file.name, title, data))
        except Exception as e:
            warn(f"Failed to parse {file.name}: {e}")

    if not entries:
        fail("No manual entries found.")
        return

    success(f"Found {len(entries)} manual entries:")
    for i, (_, title, _) in enumerate(entries, 1):
        plain(f"[{i}] {title}")
    plain("")

    try:
        selection = int(input("Select a number to view details: ").strip())
        if not (1 <= selection <= len(entries)):
            fail("Invalid selection.")
            return
    except ValueError:
        fail("Invalid input.")
        return

    chosen_file, _, chosen_data = entries[selection - 1]
    info(f"Showing manual from: {chosen_file}")
    plain("-" * 60)

    for key, value in chosen_data.items():
        plain(f"{key}:")

        if isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    for subkey, subval in item.items():
                        wrapped_lines = wrap(str(subval), width=70)
                        if wrapped_lines:
                            plain(f"  - {subkey}: {wrapped_lines[0]}")
                            for line in wrapped_lines[1:]:
                                plain(f"              {line}")
                        else:
                            plain(f"  - {subkey}:")
                else:
                    wrapped = wrap(str(item), width=70)
                    for line in wrapped:
                        plain(f"  {line}")

        elif isinstance(value, dict):
            for subkey, subval in value.items():
                wrapped = wrap(str(subval), width=70)
                if wrapped:
                    plain(f"  - {subkey}: {wrapped[0]}")
                    for line in wrapped[1:]:
                        plain(f"              {line}")
                else:
                    plain(f"  - {subkey}:")
        else:
            for line in wrap(str(value), width=70):
                plain(f"  {line}")
        plain("")

    plain("-" * 60)


def complete(args_so_far):
    return []

