#!/usr/bin/env bash
# =====================================================================
# install.sh — Install Hercules-Hunt Bug Bounty Toolkit
#
# Copies all bundled content into ~/.jiggy/:
#   - agents/*      → ~/.jiggy/agents/
#   - rules/*       → ~/.jiggy/rules/
#   - tools/*       → ~/.jiggy/tools/
#   - scripts/hunt.sh → ~/.jiggy/scripts/hunt.sh + sourced from shell rc
#
# Idempotent: safe to re-run.
# Requires: bash, curl (optional), python3 (optional).
# =====================================================================

set -e

REPO_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"
INSTALL_DIR="${JIGGY_HOME:-$HOME/.jiggy}"
AGENTS_DEST="$INSTALL_DIR/agents"
RULES_DEST="$INSTALL_DIR/rules"
TOOLS_DEST="$INSTALL_DIR/tools"
SCRIPTS_DEST="$INSTALL_DIR/scripts"

mkdir -p "$AGENTS_DEST" "$RULES_DEST" "$TOOLS_DEST" "$SCRIPTS_DEST"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║     Hercules-Hunt Bug Bounty System  ║"
echo "║     Version 1.0.0                    ║"
echo "╚══════════════════════════════════════╝"
echo ""

# === Install agents ===
echo "Agents →  $AGENTS_DEST"
if [ -d "$REPO_DIR/agents" ]; then
  for agent_file in "$REPO_DIR/agents"/*.md; do
    [ -e "$agent_file" ] || continue
    agent_name="$(basename "$agent_file")"
    [ -f "$AGENTS_DEST/$agent_name" ] && [ ! -L "$AGENTS_DEST/$agent_name" ] && \
      mv "$AGENTS_DEST/$agent_name" "$AGENTS_DEST/${agent_name%.md}.backup-$(date +%Y%m%d-%H%M%S).md"
    cp "$agent_file" "$AGENTS_DEST/$agent_name"
    echo "  ✓ Installed agent: ${agent_name%.md}"
  done
fi

# === Install rules ===
echo "Rules →  $RULES_DEST"
if [ -d "$REPO_DIR/rules" ]; then
  for rule_file in "$REPO_DIR/rules"/*.md; do
    [ -e "$rule_file" ] || continue
    rule_name="$(basename "$rule_file")"
    [ -f "$RULES_DEST/$rule_name" ] && [ ! -L "$RULES_DEST/$rule_name" ] && \
      mv "$RULES_DEST/$rule_name" "$RULES_DEST/${rule_name%.md}.backup-$(date +%Y%m%d-%H%M%S).md"
    cp "$rule_file" "$RULES_DEST/$rule_name"
    echo "  ✓ Installed rule: ${rule_name%.md}"
  done
fi

# === Install tools ===
echo "Tools →  $TOOLS_DEST"
if [ -d "$REPO_DIR/tools" ]; then
  cp -r "$REPO_DIR/tools"/* "$TOOLS_DEST/"
  echo "  ✓ Tools copied"
fi

# === Install hunt shell command ===
cp "$REPO_DIR/scripts/hunt.sh" "$SCRIPTS_DEST/hunt.sh"
chmod +x "$SCRIPTS_DEST/hunt.sh"
echo "  ✓ Installed hunt command at $SCRIPTS_DEST/hunt.sh"

# === Copy root config ===
for cfg in AGENTS.md Hercules.md opencode.json; do
  [ -f "$REPO_DIR/$cfg" ] && cp "$REPO_DIR/$cfg" "$INSTALL_DIR/$cfg" && echo "  ✓ Config: $cfg"
done

# Detect shell rc file
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
  if grep -q "jiggy/scripts/hunt.sh" "$SHELL_RC" 2>/dev/null; then
    echo "  ✓ hunt.sh already sourced from $SHELL_RC"
  else
    echo "" >> "$SHELL_RC"
    echo "# Hercules-Hunt bug bounty toolkit" >> "$SHELL_RC"
    echo "source ~/.jiggy/scripts/hunt.sh" >> "$SHELL_RC"
    echo "  ✓ Added 'source ~/.jiggy/scripts/hunt.sh' to $SHELL_RC"
  fi
else
  echo "  ⚠ No shell rc detected. Add this line manually:"
  echo "       source ~/.jiggy/scripts/hunt.sh"
fi

# Source in current shell
# shellcheck disable=SC1091
source "$SCRIPTS_DEST/hunt.sh" 2>/dev/null || true

echo ""
echo "============================================"
echo "✓ Install complete"
echo "============================================"
echo ""
echo "Agents installed at: $AGENTS_DEST"
echo "Rules installed at:  $RULES_DEST"
echo "Tools installed at:  $TOOLS_DEST"
echo "Hunt command at:     $SCRIPTS_DEST/hunt.sh"
echo ""
echo "Next: open a new terminal and try:"
echo "    hunt target.com"
echo ""
echo "On Windows, use:"
echo "    powershell -File scripts/install.ps1"
