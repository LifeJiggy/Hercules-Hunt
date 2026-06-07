#!/usr/bin/env python3
"""Hercules-Hunt Universal Adapter Installer — install across 18+ agentic CLIs.

Installs the Hercules-Hunt bug bounty system (agents, rules, tools, skills,
config, hooks, MCP configs) into any agentic coding CLI or IDE assistant.

Usage:
  python scripts/jiggy-adapter.py --list-targets
  python scripts/jiggy-adapter.py --target all --dry-run
  python scripts/jiggy-adapter.py --target claude-code --apply
  python scripts/jiggy-adapter.py --target all --component agents --apply
  python scripts/jiggy-adapter.py --target all --target-root ./preview --apply
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import shutil
import sys
import tempfile


TARGETS = [
    "codex", "claude-code", "opencode", "kilocode",
    "kimi-code", "hermes-agent", "aider", "gemini-cli",
    "goose", "cursor", "windsurf", "cline",
    "roo-code", "continue", "zed", "sourcegraph-cody",
    "github-copilot", "jetbrains-ai",
]

COMPONENT_NAMES = ["all", "agents", "rules", "tools", "skills", "config", "hooks", "mcp"]


@dataclass
class PlannedCopy:
    source: Path
    destination: Path
    component: str


class AdapterInstallError(RuntimeError):
    """Raised when adapter installation cannot safely continue."""


def _color(code: int, text: str) -> str:
    if sys.stdout.isatty():
        return f"\033[{code}m{text}\033[0m"
    return text


def green(text: str) -> str: return _color(32, text)
def cyan(text: str) -> str: return _color(36, text)
def yellow(text: str) -> str: return _color(33, text)
def red(text: str) -> str: return _color(31, text)
def dim(text: str) -> str: return _color(90, text)


# ── Path helpers ─────────────────────────────────────────────────────────────

def repo_root() -> Path:
    root = Path(__file__).resolve().parents[1]
    required = [
        root / "Hercules.md",
        root / "plugin.json",
        root / "AGENTS.md",
        root / "SKILL.md",
        root / "agents" / "recon-agent.md",
        root / "rules" / "hunting.md",
        root / "tools" / "curl-hunter.ps1",
    ]
    missing = [str(p) for p in required if not p.is_file()]
    if missing:
        raise AdapterInstallError(
            "Repository root is missing adapter sources:\n  " + "\n  ".join(missing)
        )
    return root


def home_dir() -> Path:
    return Path.home()


def target_base(target: str, home: Path, target_root: Path | None = None) -> Path:
    if target_root is not None:
        return target_root / target

    config = home / ".config"

    if target == "codex":
        return home / ".codex" / "plugins" / "jiggy-2026"
    if target == "claude-code":
        return home / ".claude"
    if target == "opencode":
        return config / "opencode" / "jiggy-2026"
    if target == "kilocode":
        return config / "kilocode" / "jiggy-2026"
    if target == "kimi-code":
        return config / "kimi-code" / "jiggy-2026"
    if target == "hermes-agent":
        return config / "hermes-agent" / "jiggy-2026"
    if target == "aider":
        return home / ".aider" / "jiggy-2026"
    if target == "gemini-cli":
        return config / "gemini-cli" / "jiggy-2026"
    if target == "goose":
        return config / "goose" / "jiggy-2026"
    if target == "cursor":
        return home / ".cursor" / "jiggy-2026"
    if target == "windsurf":
        return config / "windsurf" / "jiggy-2026"
    if target == "cline":
        return config / "cline" / "jiggy-2026"
    if target == "roo-code":
        return config / "roo-code" / "jiggy-2026"
    if target == "continue":
        return home / ".continue" / "jiggy-2026"
    if target == "zed":
        return config / "zed" / "jiggy-2026"
    if target == "sourcegraph-cody":
        return config / "sourcegraph-cody" / "jiggy-2026"
    if target == "github-copilot":
        return config / "github-copilot" / "jiggy-2026"
    if target == "jetbrains-ai":
        return config / "JetBrains" / "jiggy-2026"
    raise ValueError(f"Unsupported target: {target}")


# ── File discovery ───────────────────────────────────────────────────────────

def _list_dir(root: Path, rel: str, extensions: set[str] | None = None) -> list[Path]:
    d = root / rel
    if not d.is_dir():
        return []
    result = []
    for p in sorted(d.iterdir()):
        if p.is_file() and (extensions is None or p.suffix in extensions):
            result.append(p)
    return result


def _subtree_files(root: Path, rel: str) -> list[Path]:
    d = root / rel
    if not d.is_dir():
        return []
    result = []
    for p in sorted(d.rglob("*")):
        if p.is_file():
            result.append(p)
    return result


def _agent_files(root: Path) -> list[Path]:
    return _list_dir(root, "agents", {".md"})


def _rule_files(root: Path) -> list[Path]:
    return _list_dir(root, "rules", {".md"})


def _tool_files(root: Path) -> list[Path]:
    return _list_dir(root, "tools", {".ps1", ".py"})


def _skill_files(root: Path) -> list[Path]:
    candidates = [
        root / "SKILL.md",
        root / "bug-bounty" / "SKILL.md",
        root / "security-arsenal" / "SKILL.md",
        root / "report-writing" / "SKILL.md",
    ]
    candidates.extend(_list_dir(root / "triage-validation", ".", {".md"}))
    return [p for p in candidates if p.is_file()]


def _config_files(root: Path) -> list[Path]:
    return [p for p in [
        root / "Hercules.md",
        root / "plugin.json",
        root / "AGENTS.md",
        root / "opencode.json",
    ] if p.is_file()]


def _hook_files(root: Path) -> list[Path]:
    return [p for p in [
        root / "hooks" / "hooks.json",
    ] if p.is_file()]


def _claude_settings(root: Path) -> Path | None:
    f = root / ".claude" / "settings.json"
    return f if f.is_file() else None


def _mcp_files(root: Path) -> list[Path]:
    return _subtree_files(root, "mcp")


# ── Plan construction ────────────────────────────────────────────────────────

def _build_common_plan(root: Path, base: Path) -> list[PlannedCopy]:
    plan = []

    for f in _agent_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "agents"))

    for f in _rule_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "rules"))

    for f in _tool_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "tools"))

    for f in _skill_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "skills"))

    for f in _config_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "config"))

    for f in _hook_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "hooks"))

    cs = _claude_settings(root)
    if cs is not None:
        plan.append(PlannedCopy(cs, base / ".claude" / "settings.json", "hooks"))

    for f in _mcp_files(root):
        rel = f.relative_to(root)
        plan.append(PlannedCopy(f, base / rel, "mcp"))

    return plan


def plan_for_target(root: Path, target: str, home: Path) -> list[PlannedCopy]:
    base = target_base(target, home)
    plan = _build_common_plan(root, base)

    if target == "codex":
        plan.append(
            PlannedCopy(
                root / "plugin.json",
                base / "plugin.json",
                "config",
            )
        )

    if target == "opencode":
        plan.extend([
            PlannedCopy(
                root / "opencode.json",
                base / "opencode.json",
                "config",
            ),
            PlannedCopy(
                root / "AGENTS.md",
                base / "AGENTS.md",
                "config",
            ),
        ])

    if target == "claude-code":
        cs = _claude_settings(root)
        if cs is not None:
            plan = [
                PlannedCopy(
                    item.source,
                    base / "settings.json",
                    item.component,
                )
                if item.destination == base / ".claude" / "settings.json"
                else item
                for item in plan
            ]

    if target == "aider":
        plan.append(
            PlannedCopy(
                root / "Hercules.md",
                base / ".aider.rules.md",
                "config",
            )
        )

    if target == "cursor":
        plan = [
            PlannedCopy(item.source, base / "rules" / item.source.relative_to(root), item.component)
            if item.component == "rules"
            else item
            for item in plan
        ]

    if target == "windsurf":
        plan = [
            PlannedCopy(item.source, base / "rules" / item.source.relative_to(root), item.component)
            if item.component == "rules"
            else item
            for item in plan
        ]

    if target == "cline":
        plan.append(
            PlannedCopy(
                root / "Hercules.md",
                base / ".clinerules",
                "config",
            )
        )

    if target == "github-copilot":
        plan.append(
            PlannedCopy(
                root / "Hercules.md",
                base / ".github" / "copilot-instructions.md",
                "config",
            )
        )

    return plan


# ── File operations ──────────────────────────────────────────────────────────

def same_file_content(source: Path, destination: Path) -> bool:
    return destination.exists() and source.read_bytes() == destination.read_bytes()


def ensure_destination_safe(destination: Path) -> None:
    if destination.exists() and destination.is_dir():
        raise AdapterInstallError(
            f"Destination is a directory, expected file: {destination}"
        )
    if destination.is_symlink():
        raise AdapterInstallError(
            f"Refusing to overwrite symlink destination: {destination}"
        )


def backup_path_for(destination: Path) -> Path:
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate = destination.with_name(destination.name + f".{stamp}.bak")
    counter = 1
    while candidate.exists():
        candidate = destination.with_name(
            destination.name + f".{stamp}.{counter}.bak"
        )
        counter += 1
    return candidate


def atomic_copy(source: Path, destination: Path) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        delete=False, dir=str(destination.parent)
    ) as handle:
        temp_path = Path(handle.name)
    try:
        shutil.copy2(source, temp_path)
        temp_path.replace(destination)
    except Exception:
        temp_path.unlink(missing_ok=True)
        raise


def copy_file(
    source: Path, destination: Path, apply: bool, backup: bool
) -> str:
    if not source.is_file():
        raise FileNotFoundError(source)
    ensure_destination_safe(destination)
    if same_file_content(source, destination):
        print(f"  {dim('SKIP')} unchanged  {destination}")
        return "skipped"
    if not apply:
        print(f"  {yellow('DRY-RUN')}  {source.name} -> {destination}")
        return "planned"
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists() and backup:
        backup_path = backup_path_for(destination)
        shutil.copy2(destination, backup_path)
        print(f"  {yellow('BACKUP')}  {destination} -> {backup_path}")
    atomic_copy(source, destination)
    print(f"  {green('COPY')}    {source.name} -> {destination}")
    return "copied"


def filter_plan_by_component(
    plan: list[PlannedCopy], component: str
) -> list[PlannedCopy]:
    if component == "all":
        return plan
    return [item for item in plan if item.component == component]


# ── Target override resolution ───────────────────────────────────────────────

def resolve_target_root_override(
    plan: list[PlannedCopy], default_base: Path, override_base: Path
) -> list[PlannedCopy]:
    resolved = []
    for item in plan:
        try:
            rel = item.destination.relative_to(default_base)
        except ValueError:
            resolved.append(item)
            continue
        resolved.append(
            PlannedCopy(item.source, override_base / rel, item.component)
        )
    return resolved


# ── Summary printing ─────────────────────────────────────────────────────────

def print_summary(totals: dict[str, int]) -> None:
    parts = []
    for key in ["planned", "copied", "skipped", "failed"]:
        val = totals.get(key, 0)
        if key == "failed" and val:
            parts.append(red(f"{key}={val}"))
        elif key == "copied" and val:
            parts.append(green(f"{key}={val}"))
        elif key == "planned" and val:
            parts.append(yellow(f"{key}={val}"))
        else:
            parts.append(f"{key}={val}")
    print(f"\n{cyan('Summary:')} {' '.join(parts)}")


# ── Main ─────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--target",
        choices=["all", *TARGETS],
        help="Target CLI to install into (or 'all' for every target)",
    )
    parser.add_argument(
        "--home",
        type=Path,
        default=home_dir(),
        help="Override user home directory (default: ~)",
    )
    parser.add_argument(
        "--target-root",
        type=Path,
        help="Install into <target-root>/<target> instead of standard paths. "
        "Useful for staging or dry-run previews.",
    )
    parser.add_argument(
        "--component",
        choices=COMPONENT_NAMES,
        default="all",
        help="Install only one component group (default: all)",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write files to target directories. Required to actual install.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show planned file operations without writing anything.",
    )
    parser.add_argument(
        "--list-targets",
        action="store_true",
        help="Print supported target names and exit.",
    )
    parser.add_argument(
        "--no-backup",
        action="store_true",
        help="Skip timestamped backups when overwriting existing files.",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop at the first copy error instead of continuing.",
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Print version and exit.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print("jiggy-adapter 1.0.0")
        return 0

    if args.list_targets:
        print(f"Hercules-Hunt supports {len(TARGETS)} agentic CLI targets:\n")
        for t in TARGETS:
            base = target_base(t, home_dir())
            print(f"  {t:<18} -> {base}")
        print(f"\nRun with --target all --dry-run to preview, or --target <name> --apply to install.")
        return 0

    if not args.target:
        print(
            red("Error:") + " --target is required (use --list-targets to see options)",
            file=sys.stderr,
        )
        parser.print_usage(sys.stderr)
        return 2

    if not args.apply and not args.dry_run:
        print(
            red("Error:") + " Refusing to write without --apply. "
            "Use --dry-run to preview what would happen.",
            file=sys.stderr,
        )
        return 2

    try:
        root = repo_root()
    except AdapterInstallError as error:
        print(f"{red('Installer preflight failed:')} {error}", file=sys.stderr)
        return 1

    if args.target_root:
        args.target_root = args.target_root.resolve()

    targets = TARGETS if args.target == "all" else [args.target]

    totals: dict[str, int] = {"planned": 0, "copied": 0, "skipped": 0, "failed": 0}

    for target in targets:
        print(f"\n{cyan('=' * 50)}")
        print(f"{cyan(f'  Target: {target}')}")
        print(f"{cyan('=' * 50)}")

        try:
            plan = plan_for_target(root, target, args.home)
        except Exception as error:
            totals["failed"] += 1
            print(f"  {red('ERROR planning')} {target}: {error}", file=sys.stderr)
            if args.fail_fast:
                return 1
            continue

        if args.target_root:
            default_base = target_base(target, args.home)
            override_base = target_base(target, args.home, args.target_root)
            plan = resolve_target_root_override(plan, default_base, override_base)

        plan = filter_plan_by_component(plan, args.component)

        if not plan:
            print(f"  {yellow('No files selected')} for target={target} component={args.component}")
            continue

        for item in plan:
            try:
                result = copy_file(
                    item.source,
                    item.destination,
                    apply=args.apply,
                    backup=not args.no_backup,
                )
                totals[result] += 1
            except Exception as error:
                totals["failed"] += 1
                print(
                    f"  {red('ERROR')} {item.source.name} -> {item.destination}: {error}",
                    file=sys.stderr,
                )
                if args.fail_fast:
                    print(f"\n{red('Stopped because --fail-fast was set.')}", file=sys.stderr)
                    return 1

    total_ops = sum(totals.values())
    if total_ops == 0:
        print(f"\n{yellow('No operations performed.')}")
    else:
        print_summary(totals)

    if totals.get("planned", 0) > 0 and not args.apply:
        print(
            f"\n{yellow('Run with --apply to write these files.')}"
        )

    return 1 if totals["failed"] else 0


# ── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    raise SystemExit(main())
