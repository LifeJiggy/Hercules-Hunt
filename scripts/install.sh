#!/usr/bin/env bash
# =====================================================================
# install.sh — Install Hercules-Hunt Bug Bounty Toolkit
#
# Copies all modules into ~/.jiggy/, deploys to 18+ agentic CLI targets
# via jiggy-adapter, sources shell entry points, and installs deps.
#
# Idempotent: safe to re-run.
# Requires: bash, python3, curl (optional).
# =====================================================================
set -e

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
INSTALL_DIR="${JIGGY_HOME:-$HOME/.jiggy}"

echo ""
echo "+----------------------------------------------+"
echo "|     Hercules-Hunt Bug Bounty System           |"
echo "|     Version 1.0.0                            |"
echo "+----------------------------------------------+"
echo ""

# Count resources
echo "=== Module Inventory ==="
count_files() {
  local dir="$REPO_DIR/$1"
  if [ -d "$dir" ]; then
    if [ "$1" = "mcp" ]; then
      find "$dir" -type f -not -path '*__pycache__*' 2>/dev/null | wc -l
    else
      find "$dir" -maxdepth 1 -type f 2>/dev/null | wc -l
    fi
  else
    echo 0
  fi
}
for mod in agents rules bug-bounty recon security-arsenal report-writing triage-validation context memory storage tasks task-presistence utils adapters config hooks mcp "tools/bash" "tools/python" "tools/powershell" "tools/javascript" "tools/markdown" doc scripts; do
  c=$(count_files "$mod" | tr -d ' ')
  printf "  %-25s %s\n" "${mod}" "$c"
done

# --- Step 1: Copy all modules ---
echo ""
echo "=== Copying modules to $INSTALL_DIR ==="
mkdir -p "$INSTALL_DIR"

copy_dir() {
  local src="$REPO_DIR/$1"
  local dst="$INSTALL_DIR/$1"
  if [ -d "$src" ]; then
    mkdir -p "$(dirname "$dst")"
    cp -r "$src" "$dst"
  fi
}

for dir in agents rules bug-bounty recon security-arsenal report-writing triage-validation context memory storage tasks task-presistence utils adapters config hooks mcp doc scripts "tools/bash" "tools/python" "tools/powershell" "tools/javascript" "tools/markdown"; do
  copy_dir "$dir"
done

# Copy root configs
for cfg in Hercules.md opencode.json plugin.json AGENTS.md opencode.jsonc requirements.txt; do
  [ -f "$REPO_DIR/$cfg" ] && cp "$REPO_DIR/$cfg" "$INSTALL_DIR/$cfg"
done

# Copy .claude settings
mkdir -p "$INSTALL_DIR/.claude"
[ -f "$REPO_DIR/.claude/settings.json" ] && cp "$REPO_DIR/.claude/settings.json" "$INSTALL_DIR/.claude/settings.json"

# Copy hunt.sh
cp "$REPO_DIR/scripts/hunt.sh" "$INSTALL_DIR/scripts/hunt.sh"
chmod +x "$INSTALL_DIR/scripts/hunt.sh"

echo "  [OK] All modules installed to $INSTALL_DIR"

# --- Step 2: Shell rc setup ---
echo ""
echo "=== Shell rc setup ==="
SHELL_RC=""
if [ -n "${ZDOTDIR:-}" ] && [ -f "$ZDOTDIR/.zshrc" ]; then
  SHELL_RC="$ZDOTDIR/.zshrc"
elif [ -f "$HOME/.zshrc" ]; then
  SHELL_RC="$HOME/.zshrc"
elif [ -f "$HOME/.bashrc" ]; then
  SHELL_RC="$HOME/.bashrc"
elif [ -f "$HOME/.bash_profile" ]; then
  SHELL_RC="$HOME/.bash_profile"
fi

if [ -n "$SHELL_RC" ]; then
  if grep -q "jiggy.sh" "$SHELL_RC" 2>/dev/null; then
    echo "  [OK] jiggy.sh already sourced from $SHELL_RC"
  else
    {
      echo ""
      echo "# Hercules-Hunt Bug Bounty Toolkit"
      echo "source ~/.jiggy/tools/bash/jiggy.sh"
    } >> "$SHELL_RC"
    echo "  [OK] Added jiggy.sh to $SHELL_RC"
  fi
else
  echo "  [WARN] No shell rc found. Add manually:"
  echo "       source ~/.jiggy/tools/bash/jiggy.sh"
fi

# --- Step 3: Dependencies ---
echo ""
echo "=== Dependencies ==="
if command -v python3 &>/dev/null; then
  if [ -f "$REPO_DIR/requirements.txt" ]; then
    pip3 install -q -r "$REPO_DIR/requirements.txt" 2>/dev/null && echo "  [OK] Python deps installed" || echo "  [WARN] pip install had issues"
  fi
  # MCP server deps
  for srv in "$REPO_DIR/mcp"/*/; do
    [ -f "${srv}requirements.txt" ] && pip3 install -q -r "${srv}requirements.txt" 2>/dev/null
  done
fi

if command -v npm &>/dev/null && [ -f "$REPO_DIR/tools/javascript/package.json" ]; then
  (cd "$REPO_DIR/tools/javascript" && npm install --silent 2>/dev/null) && echo "  [OK] Node deps installed" || echo "  [WARN] npm install had issues"
fi

# --- Step 4: Deploy to agentic CLIs ---
echo ""
echo "=== Agentic CLI deployment ==="
ADAPTER="$REPO_DIR/scripts/jiggy-adapter.py"
if [ -f "$ADAPTER" ]; then
  python3 "$ADAPTER" --target all --apply 2>&1 | tail -5
  echo "  [OK] Deployed to all 18 CLI targets"
else
  echo "  [WARN] jiggy-adapter.py not found"
fi

# Source in current shell
# shellcheck disable=SC1091
source "$INSTALL_DIR/tools/bash/jiggy.sh" 2>/dev/null || true

echo ""
echo "============================================"
echo "  Install complete"
echo "============================================"
echo ""
echo "  Modules:   $INSTALL_DIR"
echo "  CLI tools: 18 agentic CLI targets"
echo ""
echo "  Next: open a new terminal or run:"
echo "    source ~/.jiggy/tools/bash/jiggy.sh"
echo "    jiggy recon target.com"
echo ""
echo "  On Windows:"
echo "    powershell -File scripts/install.ps1"
