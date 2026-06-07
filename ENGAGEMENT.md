# Engagement: <target>

**Target:** <target>
**Started:** <YYYY-MM-DD>
**Platform:** [TBD — Bugcrowd / HackerOne / Intigriti / Immunefi / private]
**Program URL:** [paste the program page URL here]

## Hunter's Foundation

Before you start, internalize the three forces from `soul.md`:

1. **Curiosity** — Why does this feature work this way? What shortcut did the developer take?
2. **Discipline** — Stop when the signal is gone. 10-20 min per test. Rotate.
3. **Integrity** — Prove it or drop it. No theoretical findings.

Read the full philosophy: `cat ~/.jiggy/soul.md`

## Purpose (from `purpose.md`)

> "The best bug bounty hunters are not the ones who run the most tools.
> They are the ones who understand the deepest."

See: `cat ~/.jiggy/purpose.md`

## North Star (from `goal.md`)

**Every session produces one of two outcomes: a verified finding or a documented dead end.**

See all 10 goals: `cat ~/.jiggy/goal.md`

## Engagement context

This folder is the working directory for a single bug-bounty engagement.
Files in this folder:

- `scope.md` — parsed scope, OOS list, focus areas, bounty bands
- `findings/` — one markdown file per finding (naming: `finding-<NN>-<short-name>.md`)
- `submissions.txt` — submission IDs tracker (for chain cross-references)
- `evidence/` — screenshots, HARs, raw transcripts (gitignored)
- `notes.md` — running notes, leads, dead ends

## Workflow

1. **Plan** — fill in `scope.md` from the program page. Note Focus Areas and Bounty bands.
2. **Recon** — subdomain enumeration, tech fingerprinting, JS analysis, cloud asset discovery.
3. **Hunt** — per-class bug hunting (IDOR, SSRF, XSS, auth bypass, business logic, chains).
4. **Validate** — run the 7-Question Gate on every lead BEFORE drafting a report.
5. **Capture evidence** — redact cookies/PII in screenshots before attaching.
6. **Report** — impact-first writing, CVSS 3.1 scoring.
7. **Track** — append every submitted finding's UUID to `submissions.txt`.

## Engagement rules

- All testing on accounts I own.
- Stop on encountering other-user PII; document and report.
- No public disclosure until program explicitly approves.
- Burp proxy capturing through all browser sessions for this target.
