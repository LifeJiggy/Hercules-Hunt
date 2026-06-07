# =====================================================================
# hunt — Hercules-Hunt engagement scaffolding
#
# Adds a `hunt` shell function that creates a per-target working folder
# under ~/Targets/ with ENGAGEMENT.md, scope.md, submissions tracker,
# findings folder, evidence folder (gitignored), and notes scratchpad.
#
# Part of the Hercules-Hunt bug bounty toolkit.
# See Hercules.md for the full agent registry, rules, and workflow.
#
# Usage:
#   hunt target.com     # creates ~/Targets/target.com/ with full template
#   hunt                # shows usage
#
# Customize HUNT_BASE in your environment to override the parent dir:
#   export HUNT_BASE="$HOME/security-research/Targets"
#
# Install: source this file from your ~/.zshrc or ~/.bashrc
#   echo 'source ~/.jiggy/scripts/hunt.sh' >> ~/.zshrc
#   source ~/.zshrc
# =====================================================================

hunt() {
  local target="$1"
  local base="${HUNT_BASE:-$HOME/Targets}"
  local dir="$base/$target"

  if [ -z "$target" ]; then
    echo "Usage: hunt <target>"
    echo "Creates a new engagement folder at \$HUNT_BASE/<target>"
    echo "Default \$HUNT_BASE is $HOME/Targets"
    return 1
  fi

  if [ -d "$dir" ]; then
    echo "Target '$target' already exists at $dir"
    echo "cd $dir to continue working on it."
    return 0
  fi

  mkdir -p "$dir/findings" "$dir/evidence"

  # ============== ENGAGEMENT.md ==============
  cat > "$dir/ENGAGEMENT.md" <<ENGMD
# Engagement: $target

**Target:** $target
**Started:** $(date -u +"%Y-%m-%d")
**Platform:** [TBD — Bugcrowd / HackerOne / Intigriti / Immunefi / private]
**Program URL:** [paste the program page URL here]

## Hunter's Foundation

Before you start, internalize the three forces from \`soul.md\`:

1. **Curiosity** — Why does this feature work this way? What shortcut did the developer take?
2. **Discipline** — Stop when the signal is gone. 10-20 min per test. Rotate.
3. **Integrity** — Prove it or drop it. No theoretical findings.

Read the full philosophy: \`cat ~/.jiggy/soul.md\`

## Purpose (from \`purpose.md\`)

> "The best bug bounty hunters are not the ones who run the most tools.
> They are the ones who understand the deepest."

See: \`cat ~/.jiggy/purpose.md\`

## North Star (from \`goal.md\`)

**Every session produces one of two outcomes: a verified finding or a documented dead end.**

See all 10 goals: \`cat ~/.jiggy/goal.md\`

## Engagement context

This folder is the working directory for a single bug-bounty engagement.
Files in this folder:

- \`scope.md\` — parsed scope, OOS list, focus areas, bounty bands
- \`findings/\` — one markdown file per finding (naming: \`finding-<NN>-<short-name>.md\`)
- \`submissions.txt\` — submission IDs tracker (for chain cross-references)
- \`evidence/\` — screenshots, HARs, raw transcripts (gitignored)
- \`notes.md\` — running notes, leads, dead ends

## Workflow

1. **Plan** — fill in \`scope.md\` from the program page. Note Focus Areas and Bounty bands.
2. **Recon** — subdomain enumeration, tech fingerprinting, JS analysis, cloud asset discovery.
3. **Hunt** — per-class bug hunting (IDOR, SSRF, XSS, auth bypass, business logic, chains).
4. **Validate** — run the 7-Question Gate on every lead BEFORE drafting a report.
5. **Capture evidence** — redact cookies/PII in screenshots before attaching.
6. **Report** — impact-first writing, CVSS 3.1 scoring.
7. **Track** — append every submitted finding's UUID to \`submissions.txt\`.

## Engagement rules

- All testing on accounts I own.
- Stop on encountering other-user PII; document and report.
- No public disclosure until program explicitly approves.
- Burp proxy capturing through all browser sessions for this target.
ENGMD

  # ============== scope.md ==============
  cat > "$dir/scope.md" <<SCOPEMD
# Scope — $target

## In scope

- (paste in-scope asset list here)

## Out of scope

- (paste OOS list here, including excluded bug classes)

## Focus areas

- (paste Focus Areas / accepted impacts — highest-leverage targets)

## Bounty bands

| Severity | Band |
|---|---|
| P1 (Critical) | |
| P2 (High) | |
| P3 (Medium) | |
| P4 (Low) | |
| P5 (Info) | (often unrewarded) |

## Account / testing setup

- **Test account email:**
- **Test account uid:**
- **Production vs QA:**
- **Mobile builds:** (Android APK / iOS IPA URLs if provided)
- **Authentication notes:** (SSO, MFA enrollment, etc.)
SCOPEMD

  # ============== submissions.txt ==============
  cat > "$dir/submissions.txt" <<SUBSEOF
# Submissions tracker — $target
# Format (tab-separated):
# <UUID>  <severity>  <class>  <one-line title>

SUBSEOF

  # ============== findings/README.md ==============
  cat > "$dir/findings/README.md" <<FINDREADME
# Findings — $target

One markdown file per lead. Naming: \`finding-<NN>-<short-name>.md\`

Each finding file should have:
1. Status (lead / validated / drafted / submitted / triaged / paid / closed)
2. Finding summary (7-Question Gate format)
3. Reproduction steps with exact requests/responses
4. Evidence inventory (path to redacted screenshots in ../evidence/)
5. Severity reasoning + CVSS 3.1
6. Submission UUID (once filed)
FINDREADME

  # ============== notes.md ==============
  cat > "$dir/notes.md" <<NOTESMD
# Notes — $target

## Leads to investigate

## Hypotheses being tested

## Dead ends (so I don't re-investigate)

## Tooling / setup notes
NOTESMD

  # ============== .gitignore ==============
  cat > "$dir/.gitignore" <<GITIGNORE
evidence/
*.har
*.png
*.jpg
*.jpeg
*.mp4
.DS_Store
Thumbs.db
.env
*.pem
*.key
GITIGNORE

  echo ""
  echo "============================================"
  echo "☰ Hercules-Hunt engagement: $target"
  echo "============================================"
  echo ""
  echo "  ENGAGEMENT.md       - Hercules-Hunt engagement context (refs soul/purpose/goal)"
  echo "  scope.md            - parsed scope template"
  echo "  submissions.txt     - submission UUID tracker"
  echo "  findings/README.md  - findings folder convention"
  echo "  notes.md            - running scratchpad"
  echo "  evidence/           - gitignored screenshot/HAR folder"
  echo "  .gitignore          - excludes evidence + secrets"
  echo ""
  echo "  Next: source ~/.jiggy/scripts/hunt.sh (if not already)"
  echo "  Then: cd $dir && cat ENGAGEMENT.md"
  echo "  Docs: cat ~/.jiggy/Hercules.md"
  echo ""
}
