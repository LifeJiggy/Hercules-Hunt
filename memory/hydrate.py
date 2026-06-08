#!/usr/bin/env python3
"""
memory/hydrate.py — Hydrate memory templates from session state.

Reads session data and writes hydrated markdown into memory/*.md
template files in-place. Tracks session progression, discoveries,
and lessons across hunting sessions.

Usage:
    python memory/hydrate.py --new-session --target example.com
    python memory/hydrate.py --add-discovery "Found X endpoint with Y behavior"
    python memory/hydrate.py --from-session session_state.json
    python memory/hydrate.py --list-templates
    python memory/hydrate.py --hydrate-memory
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
HYDRATION_SCRIPT = BASE_DIR / "tools" / "python" / "hydration.py"


def run_hydration(args: list):
    cmd = f'python "{HYDRATION_SCRIPT}" {" ".join(args)}'
    os.system(cmd)


def new_session(target: str, program: str = "HackerOne"):
    """Initialize memory templates for a new hunting session."""
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
    cli_args = [f'--set {k}={v}' for k, v in values.items()]
    cli_args.append("--hydrate-all")
    cli_args.append("--in-place")
    run_hydration(cli_args)
    print(f"[memory/hydrate] Session initialized for {target}")


def append_discovery(discovery_text: str, session_id: str = None):
    """Append a discovery entry to memory/discoveries.md."""
    discoveries_path = BASE_DIR / "memory" / "discoveries.md"
    if not discoveries_path.exists():
        print("Error: memory/discoveries.md not found")
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
    elif cmd == "--from-session" and len(sys.argv) >= 3:
        run_hydration(["--data", sys.argv[2], "--hydrate-all", "--in-place"])
    elif cmd == "--list-templates":
        run_hydration(["--list-templates"])
    elif cmd == "--hydrate-memory":
        run_hydration(["--hydrate-all", "--in-place"])
    else:
        run_hydration(sys.argv[1:])
