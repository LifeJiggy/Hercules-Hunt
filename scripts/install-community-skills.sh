#!/usr/bin/env bash
# =====================================================================
# install-community-skills.sh — OPTIONAL: refresh community skills for Hercules-Hunt
#
# Hercules-Hunt ships a bundled skill set. This script lets you pull the
# LATEST community skills from the Hercules-Hunt GitHub repo into your
# ~/.claude/skills/ for newer hunt-* patterns, updated methodology, etc.
#
# It clones LifeJiggy/Hercules-Hunt into ~/security-research/hercules-hunt/
# and links the skills. Existing skills are backed up before overwrite.
#
# Idempotent: safe to re-run.
# Requires: git, bash.
# =====================================================================

set -e

COMMUNITY_DIR="$HOME/security-research/hercules-hunt"
mkdir -p "$COMMUNITY_DIR"

echo ""
echo "╔══════════════════════════════════════╗"
echo "║  Hercules-Hunt Community Skills      ║"
echo "╚══════════════════════════════════════╝"
echo ""

# === Hercules-Hunt (upstream) ===
if [ ! -d "$COMMUNITY_DIR/Hercules-Hunt" ]; then
  echo "Cloning LifeJiggy/Hercules-Hunt..."
  git clone --depth=1 https://github.com/LifeJiggy/Hercules-Hunt.git \
    "$COMMUNITY_DIR/Hercules-Hunt"
else
  echo "LifeJiggy/Hercules-Hunt already cloned — pulling latest"
  ( cd "$COMMUNITY_DIR/Hercules-Hunt" && git pull --ff-only ) || true
fi

# === Link agents to ~/.jiggy/ ===
JIGGY_DEST="$HOME/.jiggy"
mkdir -p "$JIGGY_DEST/agents" "$JIGGY_DEST/rules" "$JIGGY_DEST/scripts"

echo "Syncing agents..."
for agent_file in "$COMMUNITY_DIR/Hercules-Hunt/agents"/*.md; do
  [ -e "$agent_file" ] || continue
  name="$(basename "$agent_file")"
  if [ -f "$JIGGY_DEST/agents/$name" ] && [ ! -L "$JIGGY_DEST/agents/$name" ]; then
    backup="$JIGGY_DEST/agents/${name%.md}.backup-$(date +%Y%m%d-%H%M%S).md"
    mv "$JIGGY_DEST/agents/$name" "$backup"
    echo "  ↺ Backed up $name → $(basename "$backup")"
  fi
  cp "$agent_file" "$JIGGY_DEST/agents/$name"
  echo "  ✓ Agent: ${name%.md}"
done

echo "Syncing rules..."
for rule_file in "$COMMUNITY_DIR/Hercules-Hunt/rules"/*.md; do
  [ -e "$rule_file" ] || continue
  name="$(basename "$rule_file")"
  [ -f "$JIGGY_DEST/rules/$name" ] && [ ! -L "$JIGGY_DEST/rules/$name" ] && \
    mv "$JIGGY_DEST/rules/$name" "$JIGGY_DEST/rules/${name%.md}.backup-$(date +%Y%m%d-%H%M%S).md"
  cp "$rule_file" "$JIGGY_DEST/rules/$name"
  echo "  ✓ Rule: ${name%.md}"
done

# === Link skills to ~/.claude/skills/ ===
if [ -d "$COMMUNITY_DIR/Hercules-Hunt/SKILL.md" ]; then
  SKILLS_DEST="$HOME/.claude/skills"
  mkdir -p "$SKILLS_DEST"
  
  # Link the main bug-bounty skill
  if [ -f "$COMMUNITY_DIR/Hercules-Hunt/SKILL.md" ]; then
    if [ -d "$SKILLS_DEST/bug-bounty" ] && [ ! -L "$SKILLS_DEST/bug-bounty" ]; then
      backup="$SKILLS_DEST/bug-bounty.backup-$(date +%Y%m%d-%H%M%S)"
      mv "$SKILLS_DEST/bug-bounty" "$backup"
      echo "  ↺ Backed up existing bug-bounty skill"
    fi
    mkdir -p "$SKILLS_DEST/bug-bounty"
    cp "$COMMUNITY_DIR/Hercules-Hunt/SKILL.md" "$SKILLS_DEST/bug-bounty/SKILL.md"
    echo "  ✓ Skill: bug-bounty"
  fi
fi

# === Update scripts ===
cp "$COMMUNITY_DIR/Hercules-Hunt/scripts/hunt.sh" "$JIGGY_DEST/scripts/hunt.sh"
chmod +x "$JIGGY_DEST/scripts/hunt.sh"
echo "  ✓ hunt.sh updated"

# === Copy core context files ===
for cfg in Hercules.md AGENTS.md README.md soul.md purpose.md goal.md; do
  [ -f "$COMMUNITY_DIR/Hercules-Hunt/$cfg" ] && cp "$COMMUNITY_DIR/Hercules-Hunt/$cfg" "$JIGGY_DEST/$cfg"
done

echo ""
echo "============================================"
echo "✓ Hercules-Hunt community skills installed"
echo "============================================"
echo ""
echo "Agents in:  $JIGGY_DEST/agents/"
echo "Rules in:   $JIGGY_DEST/rules/"
echo "Skills in:  $HOME/.claude/skills/bug-bounty/"
echo "Scripts in: $JIGGY_DEST/scripts/"
echo ""
echo "Next steps:"
echo "  1. Run scripts/install.sh (or install.ps1 on Windows)"
echo "  2. Review rules in $JIGGY_DEST/rules/"
echo "  3. See Hercules.md for the full reference"
