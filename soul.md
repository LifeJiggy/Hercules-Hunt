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

## Hunter Archetypes

Every hunter follows one of these patterns. Know which one you are — and which one you want to become.

### The Scanner
Runs nuclei, ffuf, subfinder against every target. Accumulates output. Rarely finds anything beyond misconfigured S3 buckets and outdated Wordpress versions. Produces volume, not impact.

**Upgrade path:** Stop scanning. Read one disclosed report for the target before sending a single request. Learn what human-tested bugs look like.

### The Checklist Follower
Has a methodology document open in one window and Burp in the other. Checks boxes: IDOR ✓, XSS ✓, SSRF ✓. Misses chains because each test is isolated. Finds Low-to-Medium bugs reliably. Misses Criticals.

**Upgrade path:** Learn chain primitives. Every test is not "does this endpoint have IDOR" but "if this endpoint has IDOR, what can I pair it with?"

### The Craftsman
Reads the target's blog, engineering posts, and job listings before testing. Understands the business model — what data is valuable, what actions are irreversible, where the money moves. Spends 2 hours learning before the first probe. Finds bugs that scanners and checklist followers miss because they test the *logic*, not the *surface*.

**Upgrade path:** Teach others. Writing forces you to formalize what you know.

### The Chain-Builder
Finds a Low and asks "What B do I need to turn this into a Critical?" Actively hunts for primitives — IDOR + no rate limit on password change = ATO. SSRF + cloud metadata + exposed S3 = full data exfil. They don't submit singles. They submit chains that scare platform owners.

**Upgrade path:** Read acquisition reports from offensive security firms. Study how nation-state actors chain primitives.

### The Reporter
Mediocre at finding bugs, exceptional at writing them up. Converts a P3 into a program-accepted P2 because the impact narrative is undeniable. PoCs are tight, clear, and reproducible in one click.

**Upgrade path:** You're one technique library away from being elite. Learn to hunt deeper.

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

## The Ego and The Hunt

Your ego is both your greatest asset and your greatest liability.

### When Ego Helps

Ego drives you to pursue the hard bug that everyone else missed. Ego makes you refuse to accept "it's not a bug" when you've clearly demonstrated impact. Ego pushes you to write cleaner reports, build better PoCs, and maintain a reputation that opens doors.

### When Ego Hurts

Ego makes you stay on a dead-end test for two hours because you told yourself "I can figure this out." Ego makes you inflate a P3 to P1 because you can't admit your finding is medium-impact. Ego makes you test OOS because you think you found something the program didn't consider. Ego makes you argue with triagers instead of learning from the N/A.

### The Ego Check

Before every submission, ask: "Am I submitting this because it's a real bug that causes real harm, or because I want the validation of a paid finding?"

If you can't answer honestly, have someone else read your report. A fresh pair of eyes sees ego inflation immediately.

---

## Deep Work vs Shallow Testing

Cal Newport's concept of "deep work" applies directly to bug hunting:

**Shallow testing:** Running nuclei, checking disclosed reports, scanning subdomains, reading documentation. This is necessary but low-cognitive-load work. You can do it while distracted.

**Deep hunting:** Tracing data flows through a complex feature, building a custom exploit chain, reverse-engineering a JS bundle character by character. This is high-cognitive-load work. It requires uninterrupted focus.

### Structuring Your Day

| Time | Type | Activity |
|------|------|----------|
| First 90 min | Deep | Active hunting on primary target |
| Break | — | Walk, water, eyes off screen |
| Next 60 min | Deep | Validate leads, build PoCs |
| Lunch | — | Full break |
| Last 60 min | Shallow | Recon, technique capture, note cleanup |

Never start shallow work when you're capable of deep work. Shallow work fills available time — if you give it the morning, it will take the morning.

---

## The Emotional Cycle of a Hunt

Bug bounty hunting is an emotional sport. Understanding the cycle keeps you from quitting on a downswing.

### Phase 1: Optimism
New target, fresh attack surface. Everything looks promising. You find a few low-hanging endpoints. "This target is going to pay."

### Phase 2: The Plateau
First few hours in. The low-hanging fruit is gone. You've probed the obvious endpoints. Nothing critical yet. Self-doubt creeps in. "Maybe I'm not good enough for this target."

**This is where most hunters quit.** The difference between a beginner and a pro is what they do in this phase.

### Phase 3: The Deep Read
The pro shifts from probing to reading. Disclosed reports. The target's API docs. Their changelog, their blog, their job postings. Understanding the business logic behind the features. This is the craftsman's phase.

### Phase 4: The Find
Something clicks. An endpoint that looked boring reveals an interesting behavior under a specific condition. A parameter that was ignored in the first pass now looks suspicious. The chain forms in your head. You test it. It works.

### Phase 5: The Rush
Adrenaline. You have a bug. You need to write it up, capture evidence, submit. This is the most dangerous phase — you make mistakes here (bad screenshots with cookies showing, incomplete PoCs, forgetting to redact).

**Discipline is hardest when you're excited.** Pause. Breathe. Follow the protocol.

### Phase 6: The Wait
Submission sent. Now you refresh the platform every 30 minutes. Triage takes days. You're tempted to submit more findings prematurely.

**Rules:**
- Do not check the platform more than twice a day.
- Start a new target immediately. The next bug is waiting.
- Do not adjust the submitted report while it's in triage unless triager asks.

### Phase 7: Resolution
Accepted or N/A. Either way: document what you learned. If accepted, study what made the report work. If N/A, study why — was it a validation failure or a scope issue?

Every resolution is data. Use it.

## Flow State and Hunting Zen

The best hunting happens in flow — when time disappears and you're just reading responses, testing hypotheses, moving with instinct. Flow is not something you can force, but you can create the conditions for it.

### Conditions for Flow

1. **Clear goal.** "I am testing the password reset flow on this target for race conditions." Not "I am hunting this target."
2. **Immediate feedback.** Every request gives you data. You know within seconds whether a test produced signal.
3. **Skill-challenge balance.** The target is hard enough to be interesting but not so hard that you're lost. If you're frustrated, you need more learning. If you're bored, you need a deeper test.
4. **No interruptions.** Notifications off. Phone on silent. One Burp project, one target, one train of thought.
5. **Time boxed.** 90 minutes max. After that, diminishing returns. Take a break.

### The Anti-Pattern: Context Switching

Jumping between targets, tools, and bug classes destroys flow. Every switch costs 15-20 minutes of mental ramp-up. If you've switched targets three times in an hour, you're not hunting — you're browsing.

**Rule:** One target per session. One bug class per 90-minute block. No exceptions.

## Decision Fatigue and Mental Models

A single hunting session involves hundreds of micro-decisions: "Is this response normal?" "Should I dig deeper or rotate?" "Is this worth capturing as evidence?" Decision fatigue is real — by hour four of a session, your judgment is degraded.

### Mental Models to Reduce Decision Load

**The 80/20 Rule:** 80% of the signal comes from 20% of the endpoints. Focus on the authentication flows, payment processing, privilege escalation paths, and data export features. The blog page almost never has a critical bug.

**Occam's Razor for Findings:** The simplest explanation is usually right. That weird response is probably a rate limiter, not a race condition. Test the simple theory first before building a complex exploit chain.

**The Reversal Test:** If the finding requires more than three conditions to be true simultaneously, it's probably not exploitable. "If the user is logged in, on Chrome, with an expired session, after midnight GMT — no. That's not a bug."

**The Outside View:** You've tested 20 endpoints today and found nothing. Your instinct says "keep going, the next one will be the one." The outside view says: if 20 endpoints had no signal, the probability of the 21st having signal is not higher. Rotate to a different approach.

## The Hunter's Relationship with Targets

### Respect the Target
Every target is someone's business. A bug bounty program exists because the company decided to invite researchers to help them improve security. Treat their assets with care. Don't scrape aggressively. Don't brute-force login pages. Don't DOS their API. Running nuclei with 100 threads against a startup's production API is not testing — it's vandalism.

### Respect Yourself
Your time is valuable. If a target has:
- No disclosed reports
- A confusing scope document
- A history of slow triage
- Low bounty bands for the complexity

...consider whether it's worth your time. The best hunters are selective. They don't hunt every target — they hunt the right targets.

### Respect the Community
When you submit a well-written, well-evidenced report, you raise the bar for everyone. When you submit a vague, unproven finding, you lower it. Every report you file is a signal about what kind of researcher you are. Make it a good signal.

## Handling Burnout

Bug bounty burnout is real and common. Symptoms:
- Dreading opening Burp Suite
- Feeling nothing when a finding is accepted
- Checking the platform obsessively
- Comparing yourself to other hunters' earnings
- Testing OOS because you're bored with in-scope targets

### Burnout Protocol

1. **Stop immediately.** Not after this test, not after this target — right now.
2. **Take 72 hours off.** No reading security content. No Twitter security discussions. No disclosed reports.
3. **After the break, answer:** Why was I hunting? Was it for money, recognition, learning, or fun? The reason changes the solution.
4. **If for money:** Take a month off hunting. Focus on skill-building. The money follows skill, not the other way around.
5. **If for recognition:** Take a month off submissions. Hunt without reporting. Find bugs, prove them, then delete the evidence. Reconnect with the craft without the validation loop.
6. **If for learning:** You're in the right headspace. Keep going.
7. **If for fun:** Are you still having fun? If not, find the source of the drag — is it a specific target, a specific bug class, or the process itself? Fix that one thing.

## The Ethics of Disclosure

### Responsible Disclosure Flow

1. Find the bug.
2. Verify it on your own account (never other users' data).
3. Capture redacted evidence.
4. Submit through the program's official channel (HackerOne, Bugcrowd, etc.).
5. Wait for triage. Do not post publicly.
6. If triage confirms: wait for the fix. Do not disclose until the fix is live AND the program approves.
7. If the program goes silent for 90+ days after confirmation: follow the program's disclosure policy (if any). If no policy exists, consider disclosing after 120 days with a proof-of-concept that does not contain active exploit code.

### What Never to Do

- Never test on other users' accounts or data.
- Never download PII even if accessible (document access, don't exfil).
- Never brute-force login pages or password reset tokens.
- Never use automated scanners at full throttle against production.
- Never publicly disclose without program approval.
- Never threaten to disclose for faster triage/extortion.

## The Craftsmanship Mindset

### On Tools

Tools find the surface. You find the bugs.

Nuclei, ffuf, and subfinder will never find a business logic flaw. They will never chain two Lows into a Critical. They will never read the target's API changelog and realize a deprecated endpoint is still active with weaker auth.

A master carpenter doesn't blame their hammer. A master hunter doesn't blame their tools. If you're not finding bugs, the problem is probably not your toolset — it's your methodology.

### On Methodology

Methodology is not a checklist. Methodology is a way of thinking about applications:

- **Data flow:** Where does user input enter the system? Where does it go? What transforms happen along the way?
- **Trust boundaries:** What does the server trust that it shouldn't? A header? A cookie? A JWT claim? A hidden field?
- **State machines:** What states can an object be in? What transitions are allowed? Are there implicit transitions that bypass auth?
- **Business invariants:** What must always be true? (e.g., "order.total must equal sum of line items") What happens if it's violated?

### On Reading Disclosed Reports

This is the single highest-ROI activity in bug bounty. One disclosed report can teach you a technique that produces multiple findings across different targets.

**How to read a disclosed report:**
1. Read the vulnerability class. Do you understand it? If not, pause and learn it before reading the exploit.
2. Read the endpoint and parameter names. What was the attack surface?
3. Read the request/response. Reconstruct the logic.
4. Read the impact statement. How did they frame it?
5. Ask: "Could I have found this on my current target?"

**Target:** One disclosed report per day, minimum.

## Pattern Recognition Development

Elite hunters see patterns that others miss. This is not magic — it's a trained skill.

### How to Train Pattern Recognition

1. **Volume.** Read 100 disclosed reports for the same bug class. Patterns emerge.
2. **Compare across targets.** You saw a race condition in Target A's password reset. Target B has a similar reset flow. Test it.
3. **Build mental triggers.** Train your brain to fire "IDOR?" when you see a UUID in a URL. Fire "SSRF?" when you see a URL parameter in an API call. Fire "mass assignment?" when you see a POST to /api/user/profile.
4. **Study WAF bypasses.** WAF patterns tell you what the developer thought was dangerous. If a WAF blocks `../` but not `..%2f`, you learned something about the infrastructure.

### The Pattern Library in Your Head

Build categories:
- **Auth patterns:** Where sessions are created, validated, destroyed
- **State change patterns:** Where data transitions between states (draft → published, pending → approved)
- **Export patterns:** Where data is serialized and sent to the client
- **Import patterns:** Where data enters the system (CSV upload, API import, webhook)
- **Render patterns:** Where user input is reflected in output (with or without encoding)

Each pattern has a default "bug smell." Train yourself to smell them.

## The Art of the Chain

A single Medium is a report. A chain is a story.

### Chain Types

**Parallel Chain:** Two primitives occur on the same endpoint. Example: IDOR to read another user's draft + mass assignment to overwrite their permissions. Submit as one finding.

**Sequential Chain:** Primitive A enables Primitive B. Example: SSRF to reach cloud metadata + metadata returns IAM credentials + credentials give S3 access = full data exfil. This is one report — "SSRF-to-RCE-to-data-exfil via cloud metadata."

**Conditional Chain:** Primitive A only works under condition C. Example: XSS only when the user has admin privileges + CSRF to make the admin visit the XSS page. Submit the chain, not the individual cross-site vectors.

### When NOT to Chain

- Two independent Mediums on different attack surfaces = two reports
- A Low that doesn't unlock anything = kill it, don't chain it to another Low to make a fake Medium
- Two bugs that require completely different conditions to trigger = probably not a chain

## On Failure

You will spend 90% of your hunting time not finding bugs. This is normal.

Every dead end IS data:
- You learned that a particular endpoint is hardened against IDOR
- You learned that a specific WAF blocks path traversal
- You learned that the target's session management is solid

Document dead ends. They save you time on the same target later and on similar targets in the future.

The difference between a 10-year veteran and a 1-year hunter is not talent. It's that the veteran has 10 years of dead ends documented and doesn't repeat them.

### The Failure Log

Keep a running log of every dead end. Format:

```
2026-06-08 | {target} | {endpoint} | {test tried} | {result} | {technique learned}
```

Example:
```
2026-06-08 | example.com | /api/users | IDOR on user_id | blocked by server-side check | not vulnerable, but learned they validate user_id against session token
```

After 50 entries, patterns emerge. You'll know which bug classes are worth your time on which tech stacks.

---

## Teaching Others

Teaching is the highest form of learning. When you explain a technique to someone else, you discover gaps in your own understanding.

### Ways to Teach

1. **Write a disclosed report walkthrough** — Pick a bug you found and write a detailed post-mortem. Post it on your blog or Medium.
2. **Pair with a newer hunter** — Watch them test an endpoint. Point out what you notice that they're missing.
3. **Contribute to technique libraries** — Every technique you add to Hercules-Hunt is a teaching moment.
4. **Review someone else's report before submission** — Fresh eyes catch ego inflation and missing evidence.

### What Teaching Unlocks

- You formalize your methodology (writing forces structure)
- You discover blind spots (explaining reveals what you don't actually understand)
- You build reputation (the community recognizes contributors)
- You learn from the questions you receive (newbies ask "obvious" questions that reveal assumptions you never questioned)

## The Long Game

Bug bounty is a marathon, not a sprint. The hunters who last are the ones who:

- **Rotate targets** — one target until you're bored, then switch
- **Rotate bug classes** — deep in one, broad across all
- **Track progress** — not just paid bugs, but skills learned, techniques discovered, dead ends explored
- **Take breaks** — the best insights come after a walk, a sleep, a day away
- **Share knowledge** — the community that hunts together grows together

You are not competing against other hunters. You are competing against your past self.

### The 5-Year Horizon

Year 1: Learn one bug class deeply. Find 10 verified bugs.
Year 2: Learn 3 bug classes. Chaining starts to click. 30 verified bugs.
Year 3: Method becomes instinct. You read a feature description and already know where the bug is. 60 verified bugs.
Year 4: You've seen most patterns. New targets feel familiar. You start teaching. 100 verified bugs.
Year 5: Full craftsman. You can assess a target's security posture in an hour and prioritize the highest-value test in 10 minutes. You chain routinely. 150+ verified bugs.

This is a slow game. There are no shortcuts.

### Monthly Review Questions

At the end of every month, answer:
1. What bug class did I improve at most this month?
2. What was my most valuable lesson learned (from a success OR a failure)?
3. What one thing should I change about my process for next month?
4. Am I enjoying this? If not, what needs to change?

---

## The Hunter's Reading List

Books and resources that develop the craftsman mindset:

### On Methodology
- **The Web Application Hacker's Handbook** (Stuttard & Pinto) — The foundational text. Still relevant.
- **Real-World Bug Hunting** (Peter Yaworski) — Case studies of real findings. Read one chapter per week.
- **Bug Bounty Bootcamp** (Vickie Li) — Structured introduction to the main bug classes.

### On Mindset
- **Atomic Habits** (James Clear) — 1% improvement per session compounds rapidly.
- **Deep Work** (Cal Newport) — Focus is a superpower. Learn to cultivate it.
- **The Art of War** (Sun Tzu) — Strategy principles apply directly to target selection and engagement planning.

### On Technical Depth
- **HTTP: The Definitive Guide** (Gourley & Totty) — Understanding HTTP deeply pays off in every hunting session.
- **The Tangled Web** (Michal Zalewski) — Browser security architecture. Essential for XSS and CSRF understanding.

### Disclosed Report Sources
- **HackerOne Hacktivity** — Live feed of disclosed reports. Read daily.
- **HackerOne Reports on GitHub** — Community-curated collections.
- **PentesterLand** — Curated write-ups by category.

---

## The Final Ritual

Before every session, read this:

> "I am here to find the bug that matters.
> I will check scope before I test.
> I will stop when the signal is gone.
> I will prove harm before I report.
> I will capture what I learn.
> I will leave the system better than I found it."

One minute. No tools. No requests. Just intention.

Then hunt.

Every target, every session, every finding should make you a better hunter than you were yesterday.

---

## The Hunter's Journal

Keep a hunting journal. Not a technique library — a personal journal. One entry per session.

### What to Write

After every session, write a free-form entry:
- What was I feeling at the start of the session? (energetic, tired, distracted, focused)
- What did I actually do versus what I planned to do?
- When did I feel most engaged? When did I feel most frustrated?
- What would I tell Past Me about this session?

### Why It Matters

After 30 entries, patterns emerge:
- You learn which times of day you're most productive
- You learn which bug classes energize you vs drain you
- You learn the emotional tells that precede a breakthrough or a rabbit hole
- You build a record of growth that's more honest than a bounty total

The journal is for you. No one else reads it. Be brutally honest.

---

## On Imposter Syndrome

Every hunter experiences imposter syndrome. At every level. The $100K/year hunter feels it. The $1M/year hunter feels it. The person who found a bug in Google's authentication flow feels it.

### What Imposter Syndrome Sounds Like

- "That finding was luck. I just happened to try the right endpoint."
- "I don't actually understand how this exploit works. I just copied the payload."
- "Real hunters find bugs every week. I've been staring at this target for 3 hours with nothing."
- "I don't belong in this Discord/server/community. They're all better than me."

### The Truth

- Luck is when preparation meets opportunity. You prepared. The opportunity presented itself. That's not luck — that's skill.
- Copying a payload and modifying it for a new context IS understanding. That's how expertise develops — pattern matching with adaptation.
- Three hours with nothing is normal. See "The Emotional Cycle of a Hunt." You're in Phase 2.
- Every hunter in that community started where you are. The difference is they kept going.

### The Antidote

Keep a "wins" file. Every time you do something right — find a bug, learn a technique, write a clean report, help someone — write it down.

When imposter syndrome hits, read the wins file. It's objective evidence that you're not an imposter.

---

## The Role of Luck in Bug Hunting

Let's be honest: luck plays a role. Two hunters with identical skill can test the same target and one finds a Critical while the other finds nothing.

### What Luck Looks Like

- The developer chose to use that deprecated API endpoint on the same day you checked it
- A WAF rule expired and your payload went through  
- The program just expanded scope and you were the first to test the new asset
- A disclosed report was published yesterday that showed you exactly how to exploit the tech stack you're testing

### What Skill Looks Like

- You systematically test every endpoint that the deprecated API could affect
- You rotate through 5 WAF bypass techniques in 10 minutes
- You monitor program scope changes and show up on day one
- You read disclosed reports daily and have a mental library of techniques

### The Relationship

Luck determines the OUTCOME of a single session. Skill determines the AVERAGE outcome across 100 sessions.

You can't control luck. You can control skill. Focus on what you control.

---

## Comparing Yourself to Other Hunters

The bug bounty community publishes earnings, findings, and success stories. It's easy to feel behind.

### Why Comparison Is Dangerous

- You see the highlight reel, not the 100 hours of dead ends
- You see one person's success and compare it to your average
- You see different targets, different skill levels, different available time
- You see confirmation bias — you remember their wins and forget your own

### What to Compare Instead

- Compare your current self to your past self
- Compare your process today to your process 30 days ago
- Compare your technique library size to last month's size

External comparison is noise. Internal comparison is signal.

---

## The Hunter's Toolbox: Mental Models for Faster Decisions

A mental model is a thinking framework that speeds up decisions by giving you a default response pattern.

### The 10-Minute Rule

When you encounter an interesting response, spend EXACTLY 10 minutes investigating before deciding to go deeper or rotate.

- At 10 minutes: if you have a confirmed signal (the response changed in a meaningful way), continue for another 10 minutes
- At 20 minutes: if you've confirmed the signal is exploitable, continue
- At 30 minutes: rotation time regardless of progress — you can come back

Why this works: 10 minutes is enough to test one hypothesis. If the hypothesis is wrong, you've only lost 10 minutes. Without this constraint, a "quick check" becomes a 2-hour rabbit hole.

### The Hypothesis Test

Every test should start with a hypothesis:
- "If I change user_id to 1337, the response will return user 1337's data"
- "If I inject a URL parameter, the server will fetch that URL"

Test the hypothesis. The response either confirms it (signal) or disproves it (dead end). If the response is ambiguous, formulate a new hypothesis and test again.

This prevents aimless testing — "let me try this parameter and see what happens" is not a hypothesis.

### The Compare-Contrast Pattern

For every modified request, send the legitimate request immediately before or after. Compare the responses line by line.

Most bugs manifest as a DIFFERENCE between the authorized response and the unauthorized response:
- Same response = no auth check (potential IDOR)
- Different response = auth is enforced (but how? Is it user-level or role-level?)
- Same response but with different data = IDOR confirmed
- Error response = some validation is happening (what specifically triggered it?)

### The Three-Attempt Rule

When a test doesn't produce the expected result, try exactly THREE variations before giving up:

1. **Same technique, different parameter.** The IDOR might be on `account_id` instead of `user_id`.
2. **Same parameter, different technique.** The IDOR might require a different HTTP method (PUT instead of GET).
3. **Same endpoint, different context.** The endpoint might be vulnerable when accessed from a different user role or after a specific state change.

If three variations produce nothing, the technique probably doesn't work on this endpoint. Move on.

---

## The Final Word

This system — Hercules-Hunt — is not the destination. It's the vehicle.

The agents, rules, tools, and techniques are scaffolding. They exist to support you until the methodology becomes instinct. Until you don't need to read the rule because you already know what to do. Until you don't need to check the checklist because the checklist is in your head.

When that happens — when the system fades into the background and you're just hunting, operating on instinct refined by discipline — then you've become what the system was designed to create.

Not a user of a framework.
A hunter.

That is the soul of Hercules-Hunt.
