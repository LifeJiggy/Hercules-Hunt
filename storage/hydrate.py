#!/usr/bin/env python3
"""
storage/hydrate.py — Hydrate storage templates from tool output JSON.

Reads tool output (findings, evidence, tool results) and writes hydrated
markdown into storage/*.md template files in-place.

Usage:
    python storage/hydrate.py --from-json findings.json
    python storage/hydrate.py --from-hunter rce --target example.com
    python storage/hydrate.py --list-templates
    python storage/hydrate.py --all-storage
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
HYDRATION_SCRIPT = BASE_DIR / "tools" / "python" / "hydration.py"


def run_hydration(args: list):
    """Delegate to hydration.py with storage-specific args."""
    cmd = f'python "{HYDRATION_SCRIPT}" {" ".join(args)}'
    os.system(cmd)


def from_hunter_output(hunter_name: str, target: str, output_dir: str = None):
    """Auto-hydrate storage templates using defaults for a given hunter."""
    values = {
        "TARGET": target,
        "DOMAIN": target,
        "DATE": datetime.now().strftime("%Y-%m-%d"),
        "SESSION_ID": datetime.now().strftime("SES-%Y%m%d-%H%M"),
        "N": "0",
    }

    if output_dir and os.path.exists(output_dir):
        findings_json = os.path.join(output_dir, "findings.json")
        if os.path.exists(findings_json):
            with open(findings_json) as f:
                data = json.load(f)
            if isinstance(data, dict):
                values.update({k.upper(): str(v) for k, v in data.items()})

    cli_args = [f'--set {k}={v}' for k, v in values.items()]
    cli_args.append("--hydrate-all")
    cli_args.append("--in-place")

    cmd = f'python "{HYDRATION_SCRIPT}" {" ".join(cli_args)} --output-dir "{BASE_DIR / "storage"}"'
    print(f"[storage/hydrate] Hydrating storage templates for {target}...")
    os.system(cmd)
    print(f"[storage/hydrate] Done. Storage templates populated.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--from-hunter" and len(sys.argv) >= 4:
        from_hunter_output(sys.argv[2], sys.argv[3],
                           sys.argv[4] if len(sys.argv) > 4 else None)
    elif sys.argv[1] == "--from-json" and len(sys.argv) >= 3:
        run_hydration(["--data", sys.argv[2], "--hydrate-all", "--in-place"])
    elif sys.argv[1] == "--list-templates":
        run_hydration(["--list-templates"])
    elif sys.argv[1] == "--all-storage":
        run_hydration(["--hydrate-all", "--in-place"])
    else:
        run_hydration(sys.argv[1:])
