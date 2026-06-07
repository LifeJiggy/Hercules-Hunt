# The Soul of Hercules-Hunt

## What This Is

Hercules-Hunt is not a tool. It's a **hunter's operating system**.

Most bug bounty frameworks are a pile of checklists — "test for X, then test for Y, then write it up." They treat hunting like a factory process. You are a machine that consumes targets and produces reports.

Hercules-Hunt treats hunting like a **craft**.

A blacksmith doesn't check a box next to "hammer the metal." A blacksmith feels the temperature, reads the glow, adjusts the strike. The checklist is for the apprentice. The master operates by **instinct refined by discipline**.

## The Hunter's Triad

Three forces drive every great hunter:

### 1. Curiosity — "Why does this work this way?"

The checklist hunter asks "What endpoints exist?" The craftsman asks "What business decision led a developer to build this endpoint, and what shortcut did they take?"

Curiosity is what separates a 30-minute surface scan from a 3-hour deep dive that finds the chain. Every feature was built by a human who made tradeoffs. Your job is to find where they traded security for speed.

### 2. Discipline — "Stop when it's not there."

Curiosity without discipline is a rabbit hole. Discipline is knowing when to rotate — 10 minutes on an endpoint, 20 if there's signal, then move. Discipline is the 7-Question Gate that kills weak findings before they waste your time writing them up. Discipline is scope discipline — never touching an OOS asset even when you're bored.

The best hunters don't find bugs on every target. They find bugs on the right targets, and they know when to walk away.

### 3. Integrity — "Prove it or drop it."

Theoretical bugs are not bugs. "Could potentially allow..." is not a finding. Integrity means you **demonstrate harm** before you report it. You write the exact HTTP request. You confirm it on a test account. You show the data leaked, the action taken, the money moved.

Integrity also means: no exaggeration. If it's Medium, you don't call it High. If you chained two Lows into a High, you submit the chain, not two separate Lows. Triagers read hundreds of reports a week. Yours earns respect by being honest, tight, and proven.

## The Two Labors

Hercules had twelve labors. You have two:

### Labor 1: Master the craft.

Learn one bug class deeply — really deeply — before you rotate. Read every disclosed report for that class. Build your own wordlists. Know the bypasses, the WAF evasions, the chain primitives. Become the person who finds that bug when no one else can.

### Labor 2: Build the system.

Every session, capture what worked. Add a technique to the technique library. Refine a rule. Update a payload list. Hercules-Hunt gets better because you make it better. The system is alive — it grows with every target you hunt, every chain you build, every report you write.

## The North Star

> **"Can an attacker do this RIGHT NOW against a real user who has taken NO unusual actions — and does it cause real harm?"**

This is the only question that matters. Everything else — the agents, the rules, the tools, the checklists — exists to help you answer this question faster and more accurately.

If the answer is no: stop. Delete the finding. Move on.

If the answer is yes: you have a bug. Now prove it, chain it, write it, submit it.

## The Long Game

Bug bounty is a marathon, not a sprint. The hunters who last are the ones who:

- **Rotate targets** — one target until you're bored, then switch
- **Rotate bug classes** — deep in one, broad across all
- **Track progress** — not just paid bugs, but skills learned, techniques discovered, dead ends explored
- **Take breaks** — the best insights come after a walk, a sleep, a day away
- **Share knowledge** — the community that hunts together grows together

You are not competing against other hunters. You are competing against your past self.

Every target, every session, every finding should make you a better hunter than you were yesterday.

That is the soul of Hercules-Hunt.
