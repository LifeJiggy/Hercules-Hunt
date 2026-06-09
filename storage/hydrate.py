#!/usr/bin/env python3
"""
storage/hydrate.py — Hydrate ALL .md files in storage/ with tool output data.

Auto-discovers every .md file in this directory and hydrates template
variables with findings, evidence, and session data.

Usage:
    python storage/hydrate.py --from-json findings.json
    python storage/hydrate.py --from-hunter rce --target example.com
    python storage/hydrate.py --hydrate-all
    python storage/hydrate.py --list-templates
    python storage/hydrate.py --list-placeholders
    python storage/hydrate.py --dry-run
"""

import json
import os
import sys
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
HYDRATION_SCRIPT = BASE_DIR / "tools" / "python" / "hydration.py"
STORAGE_DIR = Path(__file__).resolve().parent


def run_hydration(args: list):
    cmd = f'python "{HYDRATION_SCRIPT}" {" ".join(args)}'
    os.system(cmd)


def list_all_storage_files() -> list:
    return sorted(STORAGE_DIR.glob("*.md"))


def from_hunter_output(hunter_name: str, target: str, output_dir: str = None):
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

    storage_files = list_all_storage_files()
    print(f"[storage/hydrate] Hydrating {len(storage_files)} files in storage/ for {target}...")
    cli_args = [f'--set {k}={v}' for k, v in values.items()]
    cli_args.append(f'--dir "{STORAGE_DIR}"')
    cli_args.append("--hydrate-all")
    cli_args.append("--in-place")
    run_hydration(cli_args)
    print(f"[storage/hydrate] Done. {len(storage_files)} storage files hydrated.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    if sys.argv[1] == "--from-hunter" and len(sys.argv) >= 4:
        from_hunter_output(sys.argv[2], sys.argv[3],
                           sys.argv[4] if len(sys.argv) > 4 else None)
    elif sys.argv[1] == "--from-json" and len(sys.argv) >= 3:
        run_hydration([f'--dir "{STORAGE_DIR}"', "--data", sys.argv[2], "--hydrate-all", "--in-place"])
    elif sys.argv[1] == "--hydrate-all":
        storage_files = list_all_storage_files()
        print(f"[storage/hydrate] Hydrating all {len(storage_files)} storage files...")
        run_hydration([f'--dir "{STORAGE_DIR}"', "--hydrate-all", "--in-place"])
    elif sys.argv[1] == "--list-templates":
        for f in list_all_storage_files():
            print(f.name)
    elif sys.argv[1] == "--list-placeholders":
        run_hydration([f'--dir "{STORAGE_DIR}"', "--list-placeholders"])
    elif sys.argv[1] == "--dry-run":
        run_hydration([f'--dir "{STORAGE_DIR}"', "--dry-run", "--hydrate-all"])
    else:
        run_hydration(sys.argv[1:])
