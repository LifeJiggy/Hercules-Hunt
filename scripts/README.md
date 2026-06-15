# Scripts Module

Installation and setup scripts for the Hercules-Hunt toolkit. Handles copying modules, installing dependencies, and deploying to 18 agentic CLI targets.

## Installers

| File | Platform | What it does |
|------|----------|-------------|
| `install.ps1` | Windows PowerShell | Copies 23 modules to `~/.jiggy/`, configures `$PROFILE`, installs Python/Node deps, runs `jiggy-adapter.py` |
| `install.sh` | Linux/macOS/WSL | Same pipeline for Bash — copies modules to `~/.jiggy/`, sources `jiggy.sh` in shell rc, installs deps, runs adapter |

### Usage

```powershell
# Windows — preview then install
powershell -File scripts/install.ps1 -DryRun
powershell -File scripts/install.ps1
```

```bash
# Linux/macOS — preview then install
bash scripts/install.sh
```

## Adapter

| File | Description |
|------|-------------|
| `jiggy-adapter.py` | Universal adapter — deploys Hercules-Hunt to 18 agentic CLIs |

### Adapter Usage

```bash
# Install to all 18 targets
python scripts/jiggy-adapter.py --target all --apply

# Install to a single target
python scripts/jiggy-adapter.py --target claude-code --apply

# Preview
python scripts/jiggy-adapter.py --target all --dry-run

# List all targets
python scripts/jiggy-adapter.py --list-targets
```

### Supported Targets

```
codex, claude-code, opencode, kilocode, kimi-code, hermes-agent,
aider, gemini-cli, goose, cursor, windsurf, cline, roo-code,
continue, zed, sourcegraph-cody, github-copilot, jetbrains-ai
```

## Hunt Launcher

| File | Description |
|------|-------------|
| `hunt.sh` | Linux/macOS hunt launcher — sourced from shell rc, provides `hunt` command |

## Community Skills

| File | Description |
|------|-------------|
| `install-community-skills.sh` | Installs community-contributed skill definitions |

## Dependencies

The installers handle all dependencies automatically:

- **Python**: `pip install -r requirements.txt` + 10 MCP server `requirements.txt` files
- **Node.js**: `npm install` in `tools/javascript/`
