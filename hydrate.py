#!/usr/bin/env python3
"""hydrate.py — Load ALL .md files in the project root for context.

Usage:
    python hydrate.py [--load | --count | --list | --search <term> | --tree]
"""

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def get_all_md_files():
    return sorted(ROOT.glob("*.md"))


def load_all():
    files = get_all_md_files()
    print(f"=== root/ — {len(files)} .md files ===\n")
    for f in files:
        content = f.read_text(encoding="utf-8")
        print(f"--- {f.name} ---")
        print(content)
        print()


def count_all():
    files = get_all_md_files()
    total_lines = 0
    for f in files:
        lines = len(f.read_text(encoding="utf-8").splitlines())
        total_lines += lines
        print(f"{f.name}: {lines} lines")
    print(f"\nTotal: {len(files)} files, {total_lines} lines")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        load_all()
    elif sys.argv[1] == "--load":
        load_all()
    elif sys.argv[1] == "--count":
        count_all()
    elif sys.argv[1] == "--list":
        for f in get_all_md_files():
            print(f.name)
    elif sys.argv[1] == "--search" and len(sys.argv) >= 3:
        term = sys.argv[2]
        for f in get_all_md_files():
            content = f.read_text(encoding="utf-8")
            if term.lower() in content.lower():
                print(f"{f.name}: {content.lower().count(term.lower())} matches")
    else:
        print(__doc__)