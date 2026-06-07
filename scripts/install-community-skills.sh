#!/usr/bin/env bash
# =====================================================================
# install-community-skills.sh — OPTIONAL: refresh community skills from upstream
#
# Hercules-Hunt ships a bundled skill set. This script lets you pull the
# LATEST community skills (shuvonsec's claude-bug-bounty repo) into your
# ~/.claude/skills/ for newer hunt-* patterns, updated VRT mappings, etc.
#
# It clones shuvonsec/claude-bug-bounty into ~/security-research/community-skills/
# and runs its installer. Existing skills are backed up before overwrite.
#
# Idempotent: safe to re-run.
# Requires: git, bash.
# =====================================================================

set -e

COMMUNITY_DIR="$HOME/security-research/community-skills"
mkdir -p "$COMMUNITY_DIR"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  Hercules-Hunt Community Skills      ║"
echo "╚══════════════════════════════════════╝"
echo ""

# === shuvonsec/claude-bug-bounty (foundation) ===
if [ ! -d "$COMMUNITY_DIR/claude-bug-bounty" ]; then
  echo "Cloning shuvonsec/claude-bug-bounty..."
  git clone --depth=1 https://github.com/shuvonsec/claude-bug-bounty.git \
    "$COMMUNITY_DIR/claude-bug-bounty"
else
  echo "shuvonsec/claude-bug-bounty already cloned — pulling latest"
  ( cd "$COMMUNITY_DIR/claude-bug-bounty" && git pull --ff-only ) || true
fi

# === Backup existing bug-bounty skill if needed ===
if [ -d "$HOME/.claude/skills/bug-bounty" ] && [ ! -L "$HOME/.claude/skills/bug-bounty" ]; then
  if grep -q "Master workflow" "$HOME/.claude/skills/bug-bounty/SKILL.md" 2>/dev/null; then
    echo "✓ shuvonsec bug-bounty already installed"
  else
    backup="$HOME/.claude/skills/bug-bounty.backup-$(date +%Y%m%d-%H%M%S)"
    echo "Backing up existing custom bug-bounty skill to $backup"
    mv "$HOME/.claude/skills/bug-bounty" "$backup"
  fi
fi

# === Run shuvonsec's installer ===
echo "Running shuvonsec installer..."
cd "$COMMUNITY_DIR/claude-bug-bounty"
chmod +x install.sh

echo "n" | ./install.sh || {
  echo "⚠ shuvonsec installer reported errors — check output above"
  echo "If skills still installed correctly, you can ignore."
}

cd - >/dev/null

echo ""
echo "============================================"
echo "✓ Community skills installed"
echo "============================================"
echo ""
echo "Skills now in $HOME/.claude/skills/:"
ls "$HOME/.claude/skills/" 2>/dev/null | sort
echo ""
echo "Next steps:"
echo "  1. Run ./scripts/install.sh to install Hercules-Hunt agent bundle"
echo "  2. Review available hunt-* skills in ~/.claude/skills/"
echo "  3. See Hercules.md for documentation"
echo ""
echo "See the project README for full setup walkthrough."
