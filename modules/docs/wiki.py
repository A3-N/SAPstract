import os
import sys
import json
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


def run(args, set_session=None, current_session=None):
    if not args:
        fail("Usage: sap wiki <term>")
        return

    STOPWORDS = {"the", "is", "a", "an", "and", "of", "to", "for", "in", "on", "at", "by", "with"}
    query = " ".join(args).lower()
    query_tokens = [word for word in query.split() if word not in STOPWORDS]

    if not query_tokens:
        fail("Query too generic or contained only common words.")
        return

    DOCS_DIR = Path(__file__).parent
    matches = []

    def extract_snippet(text, token, window=30):
        idx = text.find(token)
        if idx == -1:
            return "", ""

        start = max(0, idx - window)
        end = min(len(text), idx + len(token) + window * 2)
        snippet = text[start:end].replace("\n", " ").strip()

        words = snippet.split()
        first_line = "... " + " ".join(words[:20])
        second_line = " ".join(words[20:40]) + " ..."
        return first_line, second_line

    for file in DOCS_DIR.glob("*.json"):
        try:
            with open(file, "r", encoding="utf-8") as f:
                data = json.load(f)

            match_score = 0
            first_snippet = None

            for key, value in data.items():
                content = f"{key} {value}".lower()
                for token in query_tokens:
                    if token in content:
                        match_score += 1
                        if not first_snippet:
                            first_snippet = extract_snippet(content, token)

            if match_score > 0:
                matches.append((file.name, data, match_score, first_snippet))

        except Exception as e:
            warn(f"Failed to read {file.name}: {e}")

    if not matches:
        warn(f"No documentation found matching: {query}")
        return

    matches.sort(key=lambda x: x[2], reverse=True)

    success(f"Found {len(matches)} match(es):")
    for i, (_, _, _, snippet) in enumerate(matches, 1):
        if snippet and isinstance(snippet, tuple):
            first, second = snippet
            plain(f"[{i}] {first}")
            if second.strip() != "...":
                plain(f"     {second}")
        else:
            plain(f"[{i}] (no preview)")
    plain("")

    try:
        selection = int(input("Select a number to view details: ").strip())
        if not (1 <= selection <= len(matches)):
            fail("Invalid selection.")
            return
    except ValueError:
        fail("Invalid input.")
        return

    chosen_file, chosen_data, _, _ = matches[selection - 1]
    info(f"Showing documentation from: {chosen_file}")
    plain("-" * 60)
    for key, value in chosen_data.items():
        plain(f"{key}:")
        if isinstance(value, list):
            for item in value:
                plain(f"  - {item}")
        else:
            for line in str(value).splitlines():
                plain(f"  {line}")
        plain("")
    plain("-" * 60)


def complete(args_so_far):
    return []

