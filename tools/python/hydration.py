#!/usr/bin/env python3
"""
hydration.py — Storage/Memory Template Hydration Engine

Reads storage/*.md and memory/*.md template files, replaces placeholder values
with live session data. Supports JSON input files, CLI key=value pairs, and
environment variable injection.

Usage:
  python hydration.py --hydrate-all --data session.json
  python hydration.py --hydrate storage/evidence-packages.md --set TARGET=example.com
  python hydration.py --list-placeholders
"""

import argparse
import json
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

BASE_DIR = Path(__file__).resolve().parent.parent.parent
STORAGE_DIR = BASE_DIR / "storage"
MEMORY_DIR = BASE_DIR / "memory"
OUT_DIR = BASE_DIR / "hydrated"

PLACEHOLDER_RE = re.compile(r'\[([A-Z_]+)\]')
TABLE_EMPTY_RE = re.compile(r'^\|[\s—|]+\|$', re.MULTILINE)
CHECKBOX_RE = re.compile(r'\[ \]')
DASH_PLACEHOLDER_RE = re.compile(r'(?<!\w)—(?!\w)')


def discover_templates() -> List[Path]:
    files = []
    for d in [STORAGE_DIR, MEMORY_DIR]:
        if d.exists():
            files.extend(sorted(d.glob("*.md")))
    return files


def list_placeholders(filepath: Path) -> Dict[str, List[str]]:
    text = filepath.read_text(encoding="utf-8")
    placeholders = sorted(set(PLACEHOLDER_RE.findall(text)))
    return {"file": str(filepath.relative_to(BASE_DIR)), "placeholders": placeholders}


def list_all_placeholders() -> List[Dict[str, List[str]]]:
    return [list_placeholders(f) for f in discover_templates()]


def hydrate_file(
    filepath: Path,
    values: Dict[str, str],
    output_dir: Optional[Path] = None,
    add_timestamp: bool = True,
    auto_fill_empty_tables: bool = True,
) -> str:
    text = filepath.read_text(encoding="utf-8")

    for key, val in values.items():
        text = text.replace(f"[{key}]", str(val))

    if add_timestamp and "[DATE]" not in values:
        text = text.replace("[DATE]", datetime.now().strftime("%Y-%m-%d"))

    if auto_fill_empty_tables:
        text = TABLE_EMPTY_RE.sub("", text)

    if output_dir:
        rel = filepath.relative_to(BASE_DIR)
        out = output_dir / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        return str(out)

    return text


def hydrate_all(
    values: Dict[str, str],
    output_dir: Optional[Path] = None,
    add_timestamp: bool = True,
) -> List[str]:
    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)

    hydrated = []
    for fp in discover_templates():
        result = hydrate_file(fp, values, output_dir, add_timestamp)
        hydrated.append(result)
    return hydrated


def parse_key_value_pairs(items: List[str]) -> Dict[str, str]:
    result = {}
    for item in items:
        if "=" not in item:
            print(f"Warning: skipping '{item}' (no '=' found)", file=sys.stderr)
            continue
        key, _, val = item.partition("=")
        result[key.strip()] = val.strip()
    return result


def load_json_data(path: str) -> Dict[str, str]:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {str(k).upper(): str(v) for k, v in data.items()}


def parse_args():
    parser = argparse.ArgumentParser(
        description="Hydrate storage/*.md and memory/*.md templates with session data",
    )
    parser.add_argument("--hydrate", type=str, help="Hydrate a single template file")
    parser.add_argument("--hydrate-all", action="store_true", help="Hydrate all templates")
    parser.add_argument(
        "--data", type=str, help="JSON file with key=value hydration data",
    )
    parser.add_argument(
        "--set", action="append", default=[], help="Key=Value pair (can be repeated)",
    )
    parser.add_argument(
        "--output-dir", type=str, default=None, help="Output directory for hydrated files",
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="Print what would happen without writing",
    )
    parser.add_argument(
        "--list-placeholders", action="store_true", help="List all placeholders across templates",
    )
    parser.add_argument(
        "--list-templates", action="store_true", help="List all template files",
    )
    parser.add_argument(
        "--stdout", action="store_true", help="Print hydrated content to stdout",
    )
    parser.add_argument(
        "--in-place", action="store_true",
        help="Write hydrated output directly back to the original template file (overwrites)",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.list_templates:
        for fp in discover_templates():
            rel = fp.relative_to(BASE_DIR)
            print(f"{rel} ({fp.stat().st_size} bytes)")
        return

    if args.list_placeholders:
        results = list_all_placeholders()
        for entry in results:
            print(f"\n{entry['file']}:")
            for p in entry["placeholders"]:
                print(f"  [{p}]")
        return

    values: Dict[str, str] = {}

    if args.data:
        values.update(load_json_data(args.data))

    if args.set:
        values.update(parse_key_value_pairs(args.set))

    if not values:
        values = {
            "TARGET": "example.com",
            "DOMAIN": "example.com",
            "PROGRAM": "HackerOne",
            "PLATFORM": "HackerOne",
            "DATE": datetime.now().strftime("%Y-%m-%d"),
            "SESSION_ID": datetime.now().strftime("SES-%Y%m%d-%H%M"),
            "N": "0",
        }

    output_dir = Path(args.output_dir) if args.output_dir else OUT_DIR

    if args.dry_run:
        print("Dry run — would hydrate with values:")
        for k, v in sorted(values.items()):
            print(f"  [{k}] = {v}")
        target = [args.hydrate] if args.hydrate else [str(f) for f in discover_templates()]
        for t in target:
            print(f"  -> {t}")
        return

    if args.in_place:
        output_dir = None  # disable output dir — write back to original

    if args.hydrate:
        fp = Path(args.hydrate)
        if not fp.exists():
            print(f"Error: file not found: {fp}", file=sys.stderr)
            sys.exit(1)
        if args.in_place:
            result = hydrate_file(fp, values, output_dir=fp.parent, add_timestamp=True)
            print(f"In-place hydrated: {fp}")
        else:
            result = hydrate_file(fp, values, output_dir if not args.stdout else None)
            if args.stdout:
                print(result)
            else:
                print(f"Written: {result}")

    elif args.hydrate_all:
        if args.in_place:
            for fp in discover_templates():
                hydrate_file(fp, values, output_dir=fp.parent, add_timestamp=True)
                print(f"In-place hydrated: {fp}")
        else:
            results = hydrate_all(values, output_dir if not args.stdout else None)
            if args.stdout:
                for r in results:
                    print(f"--- {r} ---")
            else:
                for r in results:
                    print(f"Written: {r}")

    else:
        print("No action specified. Use --hydrate, --hydrate-all, --list-templates, or --list-placeholders")


if __name__ == "__main__":
    main()
