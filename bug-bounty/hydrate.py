#!/usr/bin/env python3
"""Load ALL .md files in bug-bounty/ for context.

Usage:
    python bug-bounty/hydrate.py [--load | --count | --list | --search <term> | --tree]
"""

import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MODULE = HERE.name


def get_all_md_files():
    return sorted(HERE.glob("*.md"))


def load_all():
    files = get_all_md_files()
    print(f"=== {MODULE}/ - {len(files)} .md files ===\n")
    for f in files:
        print(f"--- {f.name} ---")
        print(f.read_text(encoding="utf-8"))
        print()


def count_all():
    files = get_all_md_files()
    total_lines = 0
    for f in files:
        lines = len(f.read_text(encoding="utf-8").splitlines())
        total_lines += lines
        print(f"{f.name}: {lines} lines")
    print(f"\nTotal: {len(files)} files, {total_lines} lines")


def list_all():
    files = get_all_md_files()
    for f in files:
        lines = len(f.read_text(encoding="utf-8").splitlines())
        print(f"{f.name} ({lines} lines)")


def search(term: str):
    files = get_all_md_files()
    for f in files:
        content = f.read_text(encoding="utf-8")
        if term.lower() in content.lower():
            matches = content.lower().count(term.lower())
            print(f"{f.name}: {matches} matches")
            for i, line in enumerate(content.splitlines(), 1):
                if term.lower() in line.lower():
                    print(f"  {i}: {line.strip()[:120]}")


def tree():
    files = get_all_md_files()
    print(f"{MODULE}/")
    for f in files:
        lines = len(f.read_text(encoding="utf-8").splitlines())
        print(f"  {f.name} ({lines} lines, {f.stat().st_size} bytes)")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        load_all()
    elif sys.argv[1] == "--load":
        load_all()
    elif sys.argv[1] == "--count":
        count_all()
    elif sys.argv[1] == "--list":
        list_all()
    elif sys.argv[1] == "--search" and len(sys.argv) >= 3:
        search(sys.argv[2])
    elif sys.argv[1] == "--tree":
        tree()
    else:
        print(__doc__)
