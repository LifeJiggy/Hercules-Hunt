#!/usr/bin/env python3
"""
memory/hydrate.py — Hydrate ALL .md files in memory/ with session data.

Auto-discovers every .md file in this directory and hydrates template
variables ([TARGET], [DATE], [SESSION_ID], etc.) with live session data.

Usage:
    python memory/hydrate.py --new-session --target example.com
    python memory/hydrate.py --add-discovery "Found X endpoint"
    python memory/hydrate.py --hydrate-all
    python memory/hydrate.py --list-templates
    python memory/hydrate.py --list-placeholders
    python memory/hydrate.py --dry-run
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
HYDRATION_SCRIPT = BASE_DIR / "tools" / "python" / "hydration.py"
MEMORY_DIR = Path(__file__).resolve().parent


def run_hydration(args: list):
    cmd = f'python "{HYDRATION_SCRIPT}" {" ".join(args)}'
    os.system(cmd)


def list_all_memory_files() -> list:
    return sorted(MEMORY_DIR.glob("*.md"))


def new_session(target: str, program: str = "HackerOne"):
    values = {
        "TARGET": target,
        "DOMAIN": target,
        "PROGRAM": program,
        "PLATFORM": program,
        "DATE": datetime.now().strftime("%Y-%m-%d"),
        "SESSION_ID": datetime.now().strftime("SES-%Y%m%d-%H%M"),
        "STATE": "INIT",
        "N": "0",
    }
    memory_files = list_all_memory_files()
    print(f"[memory/hydrate] Hydrating {len(memory_files)} files in memory/ for {target}...")
    cli_args = [f'--set {k}={v}' for k, v in values.items()]
    cli_args.append(f'--dir "{MEMORY_DIR}"')
    cli_args.append("--hydrate-all")
    cli_args.append("--in-place")
    run_hydration(cli_args)
    print(f"[memory/hydrate] Session initialized for {target}")


def append_discovery(discovery_text: str, session_id: str = None):
    discoveries_path = MEMORY_DIR / "discoveries.md"
    if not discoveries_path.exists():
        print(f"Error: {discoveries_path} not found")
        return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    sid = session_id or f"SES-{datetime.now().strftime('%Y%m%d-%H%M')}"
    with open(discoveries_path, "a", encoding="utf-8") as f:
        f.write(f"\n- **{timestamp}** [{sid}] {discovery_text}\n")
    print(f"[memory/hydrate] Discovery logged: {discovery_text[:60]}...")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1]

    if cmd == "--new-session" and len(sys.argv) >= 3:
        target = sys.argv[2]
        program = sys.argv[3] if len(sys.argv) > 3 else "HackerOne"
        new_session(target, program)
    elif cmd == "--add-discovery" and len(sys.argv) >= 3:
        text = sys.argv[2]
        sid = sys.argv[3] if len(sys.argv) > 3 else None
        append_discovery(text, sid)
    elif cmd == "--hydrate-all":
        memory_files = list_all_memory_files()
        print(f"[memory/hydrate] Hydrating all {len(memory_files)} memory files...")
        run_hydration([f'--dir "{MEMORY_DIR}"', "--hydrate-all", "--in-place"])
    elif cmd == "--list-templates":
        for f in list_all_memory_files():
            print(f.name)
    elif cmd == "--list-placeholders":
        run_hydration([f'--dir "{MEMORY_DIR}"', "--list-placeholders"])
    elif cmd == "--dry-run":
        run_hydration([f'--dir "{MEMORY_DIR}"', "--dry-run", "--hydrate-all"])
    else:
        run_hydration(sys.argv[1:])
