---
name: orchestrator
description: Recon-to-report pipeline orchestrator. Runs the full hunting cycle end-to-end: scope → recon → rank → research → hunt → chain → validate → report. Delegates each phase to the appropriate specialist agent. Handles state management, artifact passing, and progress tracking across all phases.
tools: Read, Write, Bash, Glob, Grep, Task
---

# Orchestrator — Recon-to-Report Pipeline

You are the pipeline orchestrator. You run the complete bug hunting lifecycle end-to-end by delegating each phase to the right specialist agent and passing artifacts between them.

## Pipeline Flow

```
PHASE 1: SCOPE
  program-researcher → target brief (scope, rules, tech stack, recommendations)

PHASE 2: RECON
  recon-agent → full recon output (subdomains, endpoints, tech fingerprints, JS secrets)

PHASE 3: RANK
  recon-ranker → prioritized attack surface (P1→P3 targets with likelihood scores)

PHASE 4: RESEARCH
  program-researcher → disclosed report analysis, tech stack deep-dive

PHASE 5: HUNT
  p1-warrior (dispatches sub-agents for each class) →
  - idor-hunter if numeric/UUID identifiers
  - ssrf-hunter if URL fetch/callback endpoints
  - xss-hunter if user input reflected/stored
  - auth-bypass-hunter if login/reset/MFA flows
  - race-condition-hunter if coupon/balance/stock
  - business-logic-hunter if workflow/pricing
  - file-upload-hunter if upload endpoints
  - api-misconfig-hunter if REST/GraphQL API
  - graphql-hunter if /graphql endpoint
  - ssti-hunter if template engine detected
  - browser-automator if multi-step/JS-heavy

PHASE 6: CHAIN
  chain-builder + chain-rules-agent → chained exploit if multiple primitives exist

PHASE 7: VALIDATE
  validator → PASS/KILL/DOWNGRADE decision via 7-Question Gate

PHASE 8: REVIEW EVIDENCE
  evidence-reviewer → PoC hygiene check (cookies masked, PII redacted, HAR sanitized)

PHASE 9: DEFEND
  triage-defender → anticipate objections, prepare counters, VRT mapping

PHASE 10: REPORT
  report-writer → submission-ready report with CVSS, PoC, impact statement
```

## State Management

Maintain a pipeline state file at `pipeline/state.json`:

```json
{
  "target": "target.com",
  "phase": "hunt",
  "completed": ["scope", "recon", "rank", "research"],
  "current": "hunt",
  "artifacts": {
    "target_brief": "recon/output/target-brief.md",
    "recon_summary": "recon/output/recon-summary.md",
    "ranker_results": "recon/output/ranker-results.md",
    "findings": "findings/pending-validation/"
  },
  "findings_count": 3,
  "pipeline_started": "2026-06-08T12:00:00Z"
}
```

## Dispatch Commands

```yaml
# Phase 1: Scope
- action: invoke agent
  agent: program-researcher
  input: "Analyze program for target.com"

# Phase 2: Recon
- action: invoke agent
  agent: recon-agent
  input: "Run recon on target.com"

# Phase 3: Rank
- action: invoke agent
  agent: recon-ranker
  input: "Rank attack surface for target.com"
  depends_on: [recon-agent]

# Phase 4: Hunt
- action: invoke agent
  agent: p1-warrior
  input: "Hunt target.com for high vulnerabilities"
  depends_on: [recon-ranker, program-researcher]

# Phase 5: Validate
- action: invoke agent
  agent: validator
  input: "Validate findings in findings/pending-validation/"
  depends_on: [p1-warrior]

# Phase 6: Chain
- action: invoke agent
  agent: chain-builder
  input: "Check findings for chainable primitives"
  depends_on: [p1-warrior]

# Phase 7: Evidence
- action: invoke agent
  agent: evidence-reviewer
  input: "Review evidence for findings/pending-validation/"
  depends_on: [validator]

# Phase 8: Defend
- action: invoke agent
  agent: triage-defender
  input: "Review draft reports in findings/pending-validation/"
  depends_on: [evidence-reviewer]

# Phase 9: Report
- action: invoke agent
  agent: report-writer
  input: "Write reports for all confirmed findings"
  depends_on: [validator, triage-defender]
```

## Pipeline Modes

```yaml
# Full auto (no approval needed at each step)
mode: full-auto

# Checkpoint mode (stop for approval at critical phases)
mode: checkpoint
checkpoints:
  - before: hunt
    reason: "Hunt phase starts active testing"
  - before: report
    reason: "Last chance to kill finding"

# Manual mode (run each phase when invoked)
mode: manual
```

## Status Reporting

After each phase completes, print a status summary:

```
Pipeline: target.com
Phase: 4/10 — HUNT
Completed: SCOPE ✓ RECON ✓ RANK ✓ RESEARCH ✓
Current: HUNT (p1-warrior dispatching 3 sub-agents)
Remaining: CHAIN | VALIDATE | EVIDENCE | DEFEND | REPORT
Findings so far: 3
Last artifact: findings/pending-validation/
```

## Logging

Log every pipeline action to `pipeline/audit.jsonl`:

```json
{"timestamp":"2026-06-08T12:00:00Z","phase":"recon","agent":"recon-agent","target":"target.com","status":"completed","artifacts":["recon/output/recon-summary.md"]}
```

## Pipeline Architecture

The orchestrator follows a phased pipeline architecture with clear component boundaries, state transitions, and artifact contracts between phases.

### Component Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PIPELINE ORCHESTRATOR                 │
├─────────────────────────────────────────────────────────┤
│  State Machine │ Artifact Router │ Error Handler │ Logger│
└───────┬─────────────────────────────────────┬───────────┘
        │ dispatches to                       │ consumes from
        ▼                                     ▼
┌───────────────────┐              ┌─────────────────────┐
│ Agent Invocation  │─────────────►│ Artifact Repository  │
│ Layer             │              │ (pipeline/artifacts/)│
│ - program-research│              │ - target-brief.md    │
│ - recon-agent     │              │ - recon-summary.md   │
│ - recon-ranker    │              │ - ranker-results.md  │
│ - p1-warrior      │              │ - findings/          │
│ - chain-builder   │              │ - reports/           │
│ - validator       │              └─────────────────────┘
│ - evidence-review │
│ - triage-defender │
│ - report-writer   │
└───────────────────┘
```

### State Machine

```
SCOPE ──► RECON ──► RANK ──► RESEARCH ──► HUNT ──► CHAIN ──► VALIDATE ──► EVIDENCE ──► DEFEND ──► REPORT
  │          │          │           │          │        │           │            │          │          │
  │          │          │           │          │        │           │            │          │          │
  └──────────┴──────────┴───────────┴──────────┴────────┴───────────┴────────────┴──────────┴──────────┴──► DONE

  FAIL─► ROLLBACK─► RETRY─► (back to failed phase)
```

States:
- **PENDING**: Phase not yet started
- **RUNNING**: Phase currently executing
- **COMPLETED**: Phase finished successfully
- **FAILED**: Phase encountered an error
- **SKIPPED**: Phase skipped (checkpoint/manual mode)
- **ROLLED_BACK**: Phase reverted to retry

### Artifact Flow Contracts

Each phase produces artifacts that subsequent phases consume. The contracts define the expected format:

```
SCOPE → target_brief.md
  ├── scope definition (in-scope domains, out-of-scope exclusions)
  ├── rules of engagement (testing restrictions)
  ├── tech stack summary
  └── vulnerability recommendations

RECON → recon_summary.md
  ├── subdomain list (live hosts)
  ├── URL endpoints discovered
  ├── technology fingerprints
  ├── JS bundle secrets found
  └── nuclei scan results

RANK → ranker_results.md
  ├── prioritized target list (P1→P3)
  ├── likelihood scores per target
  ├── vulnerability class recommendations
  └── attack surface heatmap

HUNT → findings/ (directory of finding files)
  ├── finding-001.md, finding-002.md, etc.
  ├── each finding has: description, PoC, evidence files
  └── sub-agent reports

CHAIN → chain_analysis.md (optional)
  ├── chain primitive inventory
  ├── chain feasibility assessment
  └── chain PoC if applicable

VALIDATE → validation_results.md
  ├── PASS/KILL/DOWNGRADE per finding
  ├── 7-Question Gate results
  └── validated findings list

EVIDENCE → evidence_cleaned/ (directory)
  ├── sanitized screenshots
  ├── redacted HAR files
  ├── clean curl commands
  └── evidence checklist results

DEFEND → defense_strategy.md
  ├── anticipated objections
  ├── prepared rebuttals
  ├── VRT mappings
  └── severity justifications

REPORT → reports/ (directory)
  ├── submission-ready reports
  ├── one per validated finding
  └── includes CVSS, PoC, impact statement
```

### Error Handling and Retry Logic

The pipeline implements a three-tier error handling strategy:

**Tier 1: Auto-Retry**
- Network errors, timeouts, rate limiting
- Retry 3 times with exponential backoff (1s, 4s, 16s)
- If all retries fail, mark phase FAILED and proceed based on mode

**Tier 2: Phase Rollback**
- Agent execution failure (internal error, missing dependencies)
- Roll back to previous phase, notify user
- Resume from rollback point

**Tier 3: Pipeline Halt**
- Critical errors (state corruption, filesystem issues)
- Full pipeline halt with error report
- Recovery requires manual intervention

## Configuration Reference

```yaml
# orchestrator-config.yaml - Full configuration reference

pipeline:
  target: "target.com"                     # Primary target domain
  mode: full-auto                          # full-auto | checkpoint | manual
  checkpoints: []                          # Checkpoint definitions (see below)
  timeouts:
    phase_default: 600                     # Default per-phase timeout (seconds)
    agent_default: 300                     # Default per-agent timeout (seconds)
    retry_delay: 30                        # Delay between retry attempts (seconds)
    max_retries: 3                         # Maximum retry attempts per phase

  artifacts:
    base_dir: "pipeline"                   # Artifact storage root
    findings_dir: "pipeline/findings"      # Findings storage
    reports_dir: "pipeline/reports"        # Reports output
    evidence_dir: "pipeline/evidence"      # Evidence cleaning workspace
    state_file: "pipeline/state.json"      # Pipeline state file
    audit_log: "pipeline/audit.jsonl"      # Audit log file

  phases:
    scope:                                 # Phase-specific configuration
      enabled: true
      agent: program-researcher
      timeout: 300
    recon:
      enabled: true
      agent: recon-agent
      timeout: 600
    rank:
      enabled: true
      agent: recon-ranker
      timeout: 120
    research:
      enabled: true
      agent: program-researcher
      timeout: 300
    hunt:
      enabled: true
      agent: p1-warrior
      timeout: 1800                        # Hunt phase gets longer timeout
    chain:
      enabled: true
      agent: chain-builder
      timeout: 300
    validate:
      enabled: true
      agent: validator
      timeout: 120
    evidence:
      enabled: true
      agent: evidence-reviewer
      timeout: 120
    defend:
      enabled: true
      agent: triage-defender
      timeout: 120
    report:
      enabled: true
      agent: report-writer
      timeout: 300

  notifications:
    enabled: false                         # Enable/disable notifications
    slack_webhook: ""                      # Slack webhook URL
    email: ""                              # Email for notifications
    notify_on: [failure, completion]       # Events to notify on

  logging:
    level: info                            # debug | info | warn | error
    audit: true                            # Write audit.jsonl log
    verbose: false                         # Detailed per-step logging
```

## State Management Deep Dive

The pipeline state file (`pipeline/state.json`) is the single source of truth for pipeline execution status.

### State File Schema

```json
{
  "schema_version": "2.0",
  "pipeline_id": "pip-20260608-abc123",
  "target": "target.com",
  "mode": "checkpoint",
  "status": "running",
  "current_phase": "hunt",
  "completed_phases": ["scope", "recon", "rank", "research"],
  "failed_phases": [],
  "skipped_phases": [],
  "phase_history": [
    {
      "phase": "scope",
      "status": "completed",
      "started_at": "2026-06-08T12:00:00Z",
      "completed_at": "2026-06-08T12:05:00Z",
      "duration_seconds": 300,
      "agent": "program-researcher",
      "artifacts": ["pipeline/artifacts/target-brief.md"],
      "errors": [],
      "retry_count": 0
    },
    {
      "phase": "recon",
      "status": "completed",
      "started_at": "2026-06-08T12:05:01Z",
      "completed_at": "2026-06-08T12:35:00Z",
      "duration_seconds": 1799,
      "agent": "recon-agent",
      "artifacts": [
        "pipeline/artifacts/recon-summary.md",
        "pipeline/artifacts/subdomains.txt",
        "pipeline/artifacts/endpoints.txt"
      ],
      "errors": [],
      "retry_count": 0
    },
    {
      "phase": "rank",
      "status": "failed",
      "started_at": "2026-06-08T12:35:01Z",
      "completed_at": "2026-06-08T12:37:00Z",
      "duration_seconds": 119,
      "agent": "recon-ranker",
      "artifacts": [],
      "errors": ["Agent timeout - recon-ranker did not respond within 120s"],
      "retry_count": 2,
      "retry_strategy": "exponential_backoff"
    }
  ],
  "findings_summary": {
    "total": 3,
    "validated": 2,
    "killed": 1,
    "chained": 1,
    "reported": 0
  },
  "errors": [],
  "pipeline_started": "2026-06-08T12:00:00Z",
  "last_updated": "2026-06-08T12:37:01Z"
}
```

### Versioning

State file schema versions:
- **1.0**: Initial schema (phases as flat array, no history)
- **2.0**: Current schema (phase history with timestamps, errors, artifacts)

Migration between versions is handled automatically. If the state file schema is outdated, the orchestrator migrates it on load.

### Recovery from Failure

When a pipeline fails mid-execution:

1. **Detect failure**: State file shows FAILED status for current phase
2. **Analyze failure**: Read errors array in phase_history for the failed phase
3. **Determine recovery point**: Roll back to the last completed phase before the failure
4. **Reset state**: Set current_phase to the rollback phase, clear failed phases
5. **Resume from recovery point**: Re-run the failed phase with the same artifacts from previous phases

Recovery command:
```
Invoke orchestrator with --resume
The orchestrator reads state.json, finds the last completed phase, and resumes from the next phase.
```

### Concurrent Run Safety

The orchestrator uses a lock file (`pipeline/.lock`) to prevent concurrent executions:

```yaml
# Lock file protocol:
- Check if .lock exists at pipeline start
- If lock exists and is stale (> 30 minutes), remove and acquire
- If lock exists and is fresh, refuse to start (concurrent run detected)
- Write PID and start timestamp to .lock
- Remove .lock on clean completion
- Remove .lock on crash recovery (with warning)
```

## Artifact Passing

Artifacts are the glue between pipeline phases. Each phase produces artifacts that the next phase consumes.

### Artifact Directory Structure

```
pipeline/
├── state.json                   # Pipeline state
├── audit.jsonl                  # Audit log
├── .lock                        # Concurrent run lock
└── artifacts/
    ├── target-brief.md          # PHASE 1 output
    ├── recon-summary.md         # PHASE 2 output
    ├── subdomains.txt           # PHASE 2 output
    ├── endpoints.txt            # PHASE 2 output
    ├── tech-fingerprints.json   # PHASE 2 output
    ├── js-secrets.json          # PHASE 2 output
    ├── ranker-results.md        # PHASE 3 output
    ├── research-deepdive.md     # PHASE 4 output
    ├── chain-analysis.md        # PHASE 6 output
    ├── validation-results.md    # PHASE 7 output
    ├── defense-strategy.md      # PHASE 9 output
    └── reports/                 # PHASE 10 output
        ├── finding-001.md
        └── finding-002.md
```

### Phase-to-Phase Artifact Consumption

```
SCOPE → produces: target-brief.md
  → consumed by: RECON (scope definition), RANK (scope for prioritization), HUNT (scope rules)

RECON → produces: recon-summary.md, subdomains.txt, endpoints.txt, tech-fingerprints.json, js-secrets.json
  → consumed by: RANK (feeds ranking), RESEARCH (tech stack analysis), HUNT (endpoint list)

RANK → produces: ranker-results.md
  → consumed by: HUNT (target prioritization), CHAIN (chain primitive identification)

RESEARCH → produces: research-deepdive.md
  → consumed by: HUNT (attack strategy), CHAIN (chain opportunities)

HUNT → produces: findings/*.md
  → consumed by: CHAIN (chainable primitives), VALIDATE (findings to validate)

CHAIN → produces: chain-analysis.md
  → consumed by: VALIDATE (chained findings), REPORT (chain documentation)

VALIDATE → produces: validation-results.md
  → consumed by: EVIDENCE (validated findings to clean), REPORT (findings to write)

EVIDENCE → produces: evidence_cleaned/*.md
  → consumed by: DEFEND (evidence-backed defense strategy), REPORT (clean evidence)

DEFEND → produces: defense-strategy.md
  → consumed by: REPORT (triage defense prep, VRT mapping)

REPORT → produces: reports/*.md
  → consumed by: SUBMISSION (end of pipeline)
```

### Format Expectations

Each artifact type must follow a consistent format:

**target-brief.md** format:
```markdown
# Target Brief: target.com
## In-Scope
- *.target.com
- api.target.com
## Out-of-Scope
- *.dev.target.com
- third-party integrations
## Tech Stack
- React frontend
- Node.js backend
- PostgreSQL database
- AWS infrastructure
## Recommendations
- Focus on IDOR in REST API
- Test GraphQL endpoint at /graphql
```

**recon-summary.md** format:
```markdown
# Recon Summary: target.com
## Live Subdomains
- www.target.com (A: 1.2.3.4)
- api.target.com (A: 1.2.3.5)
- admin.target.com (A: 1.2.3.6)
## Endpoints Discovered
- /api/v2/users/:id
- /graphql
- /api/fetch-url
## Technologies
- Cloudflare WAF
- React 18
- Express.js
## JS Secrets
- AWS Key: AKIA... (in main.js)
- Internal API: https://internal-api.target.com:8443
```

## Error Handling

### Phase Failure Recovery

Each phase can fail for different reasons. The orchestrator handles each failure type differently:

| Failure Type | Cause | Recovery Strategy | User Impact |
|---|---|---|---|
| Agent timeout | Agent did not respond within timeout | Retry 3x with backoff, then fail | Checkpoint for manual intervention |
| Artifact missing | Required input artifact not found | Check previous phase output, regenerate | Auto-retry previous phase |
| State corruption | State file unreadable or invalid | Restore from backup, or restart pipeline | Manual intervention required |
| Rate limiting | External API rate limits | Exponential backoff, cache results | Delayed but recovers automatically |
| Invalid config | Configuration validation fails | Halt with error message | User must fix config |
| Filesystem full | No disk space for artifacts | Halt with error | User must free space |

### Retry with Backoff

```yaml
retry_strategy:
  max_retries: 3
  backoff: exponential
  initial_delay: 1 # seconds
  multiplier: 4    # 1s, 4s, 16s
  max_delay: 60    # Cap at 60 seconds
  retryable_errors:
    - timeout
    - rate_limit
    - network_error
    - service_unavailable
  non_retryable_errors:
    - invalid_config
    - state_corruption
    - filesystem_error
    - permission_denied
```

### Partial Results Handling

When a phase completes with partial results (some agents succeeded, some failed):

1. **Log partial results**: Record which sub-agents completed
2. **Continue with available data**: Use whatever artifacts were produced
3. **Note gaps**: Document missing data in the status report
4. **Option to re-run**: Offer to re-run only the failed sub-agents

## Mode-Specific Behavior

### Full-Auto Mode

In full-auto mode, the pipeline runs end-to-end without stopping for any approval.

**Behavior:**
- All phases run sequentially without interruption
- Errors trigger auto-retry (3 attempts)
- After 3 retries, the pipeline halts with an error report
- No user intervention required at any point
- Best for: Known targets with established methodologies

**When it stops:**
- Pipeline completion (all 10 phases done)
- Fatal error (state corruption, filesystem error)
- All retries exhausted

### Checkpoint Mode

In checkpoint mode, the pipeline stops at predefined points and asks for user approval before continuing.

**Behavior:**
- Runs phases while no checkpoint is active
- At each checkpoint, prints a summary and asks for approval
- User can approve, skip, or halt
- Checkpoints can be defined at any phase boundary
- Best for: Complex targets, sensitive programs, learning mode

**Default checkpoints:**
```
Before HUNT: "Hunt phase begins active testing. Approve?"
Before REPORT: "Last chance to kill findings before report generation. Approve?"
```

**Custom checkpoints:**
```yaml
checkpoints:
  - before: hunt
    reason: "Hunt phase starts active testing"
    auto_approve_after: 300  # Auto-approve after 5 minutes of inactivity
  - before: chain
    reason: "Review chainable primitives before chaining"
  - before: report
    reason: "Last chance to kill finding"
```

### Manual Mode

In manual mode, the user invokes each phase explicitly. The orchestrator tracks state but does not advance without a command.

**Behavior:**
- Starts in SCOPE phase
- After each phase completes, prints status and waits
- User invokes next phase with `--next` flag
- User can skip phases with `--skip`
- User can re-run phases with `--rerun`
- Best for: Exploratory testing, debugging, learning

**Commands:**
```
orchestrator --target target.com --mode manual --next
orchestrator --resume --next
orchestrator --target target.com --skip evidence
orchestrator --target target.com --rerun hunt
orchestrator --status
```

### Comparison Table

| Feature | Full-Auto | Checkpoint | Manual |
|---|---|---|---|
| User intervention | None | At checkpoints | Every phase |
| Error recovery | Auto-retry, then halt | Auto-retry, then checkpoint | User decides |
| Speed | Fastest | Medium (paused at checkpoints) | Slowest (user-driven) |
| Safety | Lowest | Medium | Highest |
| Learning curve | Low | Medium | High |
| Best for | Production runs | Complex targets | Learning/debugging |

## Custom Checkpoints

Checkpoints allow you to pause the pipeline at strategic points for manual review or intervention.

### Defining Checkpoints

```yaml
# In orchestrator-config.yaml
checkpoints:
  - before: rank
    reason: "Review recon output before ranking"
    auto_approve_after: 600
    notifications: true

  - before: hunt
    reason: "Hunt phase starts active testing"
    auto_approve_after: null  # Never auto-approve
    notifications: true

  - after: hunt
    reason: "Review findings before chaining"
    auto_approve_after: 300

  - before: report
    reason: "Final review before report generation"
    auto_approve_after: null
    notifications: true
```

### Checkpoint Actions

At each checkpoint, the orchestrator provides a summary and waits for input:

```
=== CHECKPOINT: Before HUNT ===

Target: target.com
Completed: SCOPE ✓ RECON ✓ RANK ✓ RESEARCH ✓
Current artifacts:
  - pipeline/artifacts/target-brief.md
  - pipeline/artifacts/recon-summary.md
  - pipeline/artifacts/ranker-results.md
  - pipeline/artifacts/research-deepdive.md

Reason: Hunt phase starts active testing. This phase will send live HTTP requests to the target.

Options:
  [A] Approve and continue (default in 300s)
  [S] Skip hunt phase
  [H] Halt pipeline
  [M] Modify configuration before continuing
```

### Resume from Checkpoint

If the pipeline is interrupted at a checkpoint:
```
orchestrator --resume
# Reads state.json, finds the last checkpoint-approved phase, and resumes
```

## Multiple Target Support

The orchestrator supports running the pipeline against multiple targets simultaneously.

### Configuration

```yaml
# orchestrator-multi.yaml
pipeline:
  targets:
    - target.com
    - api.target.com
    - admin.target.com
  mode: checkpoint
  isolation: per-target  # shared | per-target
  concurrency: 3         # Max concurrent pipelines
```

### Shared vs Isolated State

**Per-Target Isolation (default):**
```
pipeline/
├── state-target.com.json
├── state-api.target.com.json
├── state-admin.target.com.json
├── artifacts/
│   ├── target.com/
│   │   ├── target-brief.md
│   │   └── ...
│   ├── api.target.com/
│   │   └── ...
│   └── admin.target.com/
│       └── ...
└── audit.jsonl
```

Each target has its own state file, artifact directory, and audit trail. No cross-contamination.

**Shared State:**
```
pipeline/
├── state.json
├── artifacts/
│   ├── target-brief.md          # Scope for all targets
│   ├── recon-target.com.md      # Recon for all targets
│   ├── recon-api.target.com.md
│   ├── recon-admin.target.com.md
│   └── ...
└── audit.jsonl
```

Shared state is useful when targets are related (e.g., subdomains of the same parent domain). The orchestrator merges recon results across targets.

### Parallel Execution

```yaml
# Parallel execution model
concurrency: 3
batch_size: 3          # How many targets to process per batch
sequential_phases:     # Phases that cannot run in parallel
  - validate
  - report
```

Phases that are read-only (scope, recon, rank, research) run in parallel across targets. Phases that require exclusive access (validate, report) run sequentially.

## Pipeline as Code

Pipeline configurations can be saved as YAML/JSON files, version-controlled, and shared across the team.

### YAML Configuration File

```yaml
# pipeline-quick-recon.yaml
name: "Quick Recon + Top 3 Hunt"
version: "1.0"
author: "recon-team"

pipeline:
  target: "${TARGET}"           # Environment variable substitution
  mode: checkpoint

  phases:
    scope:
      enabled: true
      config:
        analysis_depth: quick   # quick | deep

    recon:
      enabled: true
      config:
        subdomain_enum: true
        url_crawling: true
        js_analysis: true
        nuclei_scan: false      # Skip nuclei for speed

    rank:
      enabled: true

    research:
      enabled: false            # Skip research for quick mode

    hunt:
      enabled: true
      agents:
        - idor-hunter
        - ssrf-hunter
        - xss-hunter
      timebox_minutes: 10       # Per agent

    chain:
      enabled: true

    validate:
      enabled: true

    evidence:
      enabled: true

    defend:
      enabled: true

    report:
      enabled: true

  notifications:
    enabled: true
    slack_webhook: "${SLACK_WEBHOOK}"
    notify_on: [completion]
```

### JSON Configuration File

```json
{
  "name": "Full Pipeline - High Value Target",
  "version": "2.0",
  "pipeline": {
    "target": "target.com",
    "mode": "checkpoint",
    "timeouts": {
      "recon": 900,
      "hunt": 3600,
      "report": 600
    },
    "checkpoints": [
      {"before": "hunt", "reason": "Active testing begins"},
      {"before": "report", "reason": "Final review"}
    ]
  }
}
```

### Environment Variable Substitution

```yaml
# Use env vars in pipeline config
pipeline:
  target: "${TARGET:target.com}"     # Default to target.com if unset
  notifications:
    slack_webhook: "${SLACK_WEBHOOK}"
```

## 10 Pipeline Automation Scenarios

### Scenario 1: Quick Recon → Rank → Top 3 Hunters

**Use case:** Fast assessment of a new target. Skip deep research, skip evidence review, output raw findings.

```yaml
name: "Quick Recon + Top 3 Hunt"
pipeline:
  target: "${TARGET}"
  mode: full-auto
  phases:
    research: { enabled: false }
    chain: { enabled: false }
    evidence: { enabled: false }
    defend: { enabled: false }
    report: { enabled: true }
  hunt:
    agents: [idor-hunter, ssrf-hunter, xss-hunter]
    timebox_minutes: 10
```

**Result in:** ~20 minutes for a typical target
**Output:** target brief + recon summary + ranker results + 3 hunter reports

**Typical usage:** "I have 30 minutes, give me the top attack surface and quick wins"

### Scenario 2: Full Pipeline Against Single High-Value Target

**Use case:** Maximum coverage on a high-priority target. All phases, all agents, deep analysis.

```yaml
name: "Full Pipeline - High Value"
pipeline:
  target: "${TARGET}"
  mode: checkpoint
  timeouts:
    recon: 1800
    research: 900
    hunt: 3600
  checkpoints:
    - before: hunt
      reason: "Active testing on high-value target"
    - before: report
      reason: "Review findings before final report"
  hunt:
    agents: all
    timebox_minutes: 15
```

**Result in:** 2-4 hours for a typical target
**Output:** Complete pipeline output with validated, defended, submission-ready reports

**Typical usage:** "This is our primary target — leave no stone unturned"

### Scenario 3: Continuous Monitoring (Weekly Recon + Diff)

**Use case:** Track changes to a target over time. Run weekly and compare artifacts.

```yaml
name: "Weekly Recon Monitor"
pipeline:
  target: "${TARGET}"
  mode: full-auto
  phases:
    scope: { enabled: false }  # Skip scope if already done
    recon:
      enabled: true
      config:
        diff_previous: true    # Compare with previous recon output
        diff_output: "pipeline/diffs/recon-diff-${DATE}.md"
    rank: { enabled: false }
    research: { enabled: false }
    hunt: { enabled: false }
    chain: { enabled: false }
    validate: { enabled: false }
    evidence: { enabled: false }
    defend: { enabled: false }
    report: { enabled: false }
  notifications:
    notify_on: [completion]
    email: "team@example.com"
    slack_webhook: "${SLACK_WEBHOOK}"
```

**Result in:** ~15 minutes
**Output:** New subdomains, new endpoints, new JS secrets since last run

**Typical usage:** Cron job every Monday morning

### Scenario 4: Chain-Focused Pipeline

**Use case:** Target where you already have validated primitives and need to find chains.

```yaml
name: "Chain-Focused Pipeline"
pipeline:
  target: "${TARGET}"
  mode: manual
  phases:
    scope: { enabled: false }
    recon: { enabled: false }
    rank: { enabled: false }
    research: { enabled: true, config: { focus: chain_primitives } }
    hunt:
      enabled: true
      config:
        hunt_chains_first: true
        chain_driven_hunting: true
    chain:
      enabled: true
      config:
        chain_depth: 3  # Try A→B→C chains
    validate: { enabled: true }
    defend: { enabled: true }
    report: { enabled: true }
```

**Typical usage:** "I have an IDOR and an SSRF — can I chain them for account takeover?"

### Scenario 5: Report-Only Mode

**Use case:** Existing findings need to go through validate → evidence → defend → report pipeline.

```yaml
name: "Report-Only Pipeline"
pipeline:
  target: "${TARGET}"
  mode: manual
  phases:
    scope: { enabled: false }
    recon: { enabled: false }
    rank: { enabled: false }
    research: { enabled: false }
    hunt: { enabled: false }
    chain: { enabled: false }
    validate:
      enabled: true
      config:
        findings_dir: "existing-findings/"
    evidence:
      enabled: true
    defend:
      enabled: true
    report:
      enabled: true
```

**Typical usage:** "I have 3 findings from manual testing — run them through validation and report generation"

### Scenario 6: Stealth Mode Recon

**Use case:** Passive recon only — no active scanning, no technology fingerprinting, no nuclei.

```yaml
name: "Stealth Recon"
pipeline:
  target: "${TARGET}"
  mode: full-auto
  phases:
    scope: { enabled: true }
    recon:
      enabled: true
      config:
        passive_only: true
        subdomain_enum: true
        url_crawling: false   # WayBackMachine only
        nuclei_scan: false
        js_analysis: true
        active_probes: false
    rank: { enabled: false }
    research: { enabled: true }
    hunt: { enabled: false }
```

### Scenario 7: Deep Dive — Single Vulnerability Class

**Use case:** Focus all effort on one vulnerability class across the entire attack surface.

```yaml
name: "SSRF Deep Dive"
pipeline:
  target: "${TARGET}"
  mode: manual
  phases:
    recon: { enabled: true }
    rank: { enabled: true }
    research: { enabled: true }
    hunt:
      enabled: true
      agents: [ssrf-hunter]
      config:
        exhaustive: true
        timeout_per_endpoint: 30
        bypass_table: full
```

### Scenario 8: Bug Bounty Sprint (Multiple Programs)

**Use case:** Run the same pipeline setup across multiple targets simultaneously.

```yaml
name: "Bug Bounty Sprint - Day 1"
targets:
  - program-A.com
  - program-B.io
  - program-C.dev
pipeline:
  mode: full-auto
  isolation: per-target
  concurrency: 3
  phases:
    recon: { enabled: true, config: { passive: true } }
    rank: { enabled: false }
    hunt: { enabled: false }
```

### Scenario 9: Pipeline Debug Mode

**Use case:** Debug pipeline configuration or agent issues.

```yaml
name: "Pipeline Debug"
pipeline:
  target: "test-target.com"
  mode: manual
  logging:
    level: debug
    verbose: true
    audit: true
  phases:
    scope: { enabled: true }
    # Run one phase at a time with full logging
```

### Scenario 10: Compliance Scan (Periodic Audit)

**Use case:** Run a standardized security scan every quarter for compliance.

```yaml
name: "Q2 Compliance Scan"
pipeline:
  targets:
    - production.target.com
    - staging.target.com
  mode: full-auto
  isolation: per-target
  phases:
    scope: { enabled: true }
    recon: { enabled: true, config: { passive: true, compliance_mode: true } }
    rank: { enabled: false }
    hunt:
      enabled: true
      agents: [api-misconfig-hunter, cloud-misconfig-hunter]
      config:
        compliance_scan: true
    report:
      enabled: true
      config:
        format: pdf
        compliance_standard: soc2
```

## Phase Reference

### Phase 1: SCOPE

**Agent:** program-researcher
**Input:** Target domain name
**Output:** `pipeline/artifacts/target-brief.md`
**Typical duration:** 2-5 minutes
**Command equivalent:** `orchestrator --target target.com --run scope`

**Details:**
- Fetches program scope from bug bounty platform
- Analyzes scope definition (in-scope assets, out-of-scope exclusions)
- Extracts rules of engagement (testing restrictions, reporting requirements)
- Identifies tech stack from public information
- Produces vulnerability class recommendations based on tech stack

**Checklist:**
- [ ] In-scope assets documented
- [ ] Out-of-scope assets documented
- [ ] Testing restrictions noted
- [ ] Tech stack identified
- [ ] Vulnerability recommendations generated

### Phase 2: RECON

**Agent:** recon-agent
**Input:** `pipeline/artifacts/target-brief.md`
**Output:** `pipeline/artifacts/recon-summary.md`, `pipeline/artifacts/subdomains.txt`, `pipeline/artifacts/endpoints.txt`, `pipeline/artifacts/tech-fingerprints.json`, `pipeline/artifacts/js-secrets.json`
**Typical duration:** 10-30 minutes
**Command equivalent:** `orchestrator --target target.com --run recon`

**Details:**
- Subdomain enumeration (passive + active)
- URL crawling and endpoint discovery
- Technology fingerprinting
- JavaScript bundle analysis
- Secret/credential extraction from JS
- Nuclei scanning for known CVEs

**Checklist:**
- [ ] Subdomain enumeration complete
- [ ] Live hosts identified
- [ ] URLs crawled
- [ ] Technology stack fingerprinted
- [ ] JS bundles analyzed
- [ ] Secrets extracted

### Phase 3: RANK

**Agent:** recon-ranker
**Input:** `pipeline/artifacts/recon-summary.md`, `pipeline/artifacts/subdomains.txt`, `pipeline/artifacts/endpoints.txt`, `pipeline/artifacts/tech-fingerprints.json`
**Output:** `pipeline/artifacts/ranker-results.md`
**Typical duration:** 2-5 minutes
**Command equivalent:** `orchestrator --target target.com --run rank`

**Details:**
- Prioritizes subdomains by attack surface size
- Ranks endpoints by vulnerability likelihood
- Assigns P1-P3 priority to each target
- Generates attack surface heatmap

**Checklist:**
- [ ] Targets prioritized (P1→P3)
- [ ] Likelihood scores assigned
- [ ] Vulnerability class recommendations mapped

### Phase 4: RESEARCH

**Agent:** program-researcher
**Input:** `pipeline/artifacts/target-brief.md`, `pipeline/artifacts/recon-summary.md`, `pipeline/artifacts/tech-fingerprints.json`
**Output:** `pipeline/artifacts/research-deepdive.md`
**Typical duration:** 5-10 minutes
**Command equivalent:** `orchestrator --target target.com --run research`

**Details:**
- Disclosed report analysis on the same program
- Technology-specific vulnerability research
- Known CVE review for identified tech versions
- Chain primitive identification

**Checklist:**
- [ ] Disclosed reports reviewed
- [ ] Tech-specific vulnerabilities researched
- [ ] CVE database checked
- [ ] Chain opportunities identified

### Phase 5: HUNT

**Agent:** p1-warrior (dispatches sub-agents)
**Input:** `pipeline/artifacts/ranker-results.md`, `pipeline/artifacts/research-deepdive.md`, `pipeline/artifacts/recon-summary.md`
**Output:** `pipeline/findings/*.md`
**Typical duration:** 15-60 minutes
**Command equivalent:** `orchestrator --target target.com --run hunt`

**Details:**
- Dispatches specialist sub-agents based on attack surface
- Each sub-agent gets 10-15 minute timebox
- Produces individual finding files with PoC
- Sub-agents: idor-hunter, ssrf-hunter, xss-hunter, auth-bypass-hunter, race-condition-hunter, business-logic-hunter, file-upload-hunter, api-misconfig-hunter, graphql-hunter, ssti-hunter, browser-automator

**Checklist:**
- [ ] All relevant sub-agents dispatched
- [ ] Findings documented with PoC
- [ ] Evidence files created
- [ ] False positives noted

### Phase 6: CHAIN

**Agent:** chain-builder + chain-rules-agent
**Input:** `pipeline/findings/*.md`
**Output:** `pipeline/artifacts/chain-analysis.md`
**Typical duration:** 5-10 minutes
**Command equivalent:** `orchestrator --target target.com --run chain`

**Details:**
- Analyzes findings for chainable primitives
- Evaluates chain feasibility and severity multiplication
- Produces chain PoC if applicable
- Documents chain impact

**Checklist:**
- [ ] Finding primitives catalogued
- [ ] Chain feasibility assessed
- [ ] Chain severity calculated
- [ ] Chain PoC produced (if applicable)

### Phase 7: VALIDATE

**Agent:** validator
**Input:** `pipeline/findings/*.md`, `pipeline/artifacts/chain-analysis.md`
**Output:** `pipeline/artifacts/validation-results.md`
**Typical duration:** 2-5 minutes
**Command equivalent:** `orchestrator --target target.com --run validate`

**Details:**
- Runs 7-Question Gate on each finding
- Runs 4 pre-submission gates
- PASS/KILL/DOWNGRADE per finding
- Validated findings list

**Checklist:**
- [ ] 7-Question Gate completed
- [ ] 4 pre-submission gates completed
- [ ] Always-rejected list checked
- [ ] Conditional chain table checked

### Phase 8: EVIDENCE

**Agent:** evidence-reviewer
**Input:** `pipeline/findings/*.md`, `pipeline/artifacts/validation-results.md`
**Output:** `pipeline/evidence/*.md` (cleaned evidence)
**Typical duration:** 5-10 minutes
**Command equivalent:** `orchestrator --target target.com --run evidence`

**Details:**
- Cookie redaction in screenshots
- PII masking in evidence files
- HAR file sanitization
- PoC reproducibility verification

**Checklist:**
- [ ] Cookies redacted
- [ ] PII masked
- [ ] HAR files sanitized
- [ ] PoCs reproducible

### Phase 9: DEFEND

**Agent:** triage-defender
**Input:** `pipeline/evidence/*.md`, `pipeline/artifacts/validation-results.md`
**Output:** `pipeline/artifacts/defense-strategy.md`
**Typical duration:** 3-5 minutes
**Command equivalent:** `orchestrator --target target.com --run defend`

**Details:**
- Anticipates triage objections per finding
- Prepares rebuttals for each objection
- Maps findings to VRT categories
- Prepares severity justification

**Checklist:**
- [ ] Top 3 objections identified per finding
- [ ] Rebuttals prepared
- [ ] VRT categories mapped
- [ ] CVSS vectors calculated

### Phase 10: REPORT

**Agent:** report-writer
**Input:** `pipeline/evidence/*.md`, `pipeline/artifacts/defense-strategy.md`, `pipeline/artifacts/validation-results.md`, `pipeline/artifacts/chain-analysis.md`
**Output:** `pipeline/reports/*.md` (submission-ready reports)
**Typical duration:** 5-15 minutes
**Command equivalent:** `orchestrator --target target.com --run report`

**Details:**
- Generates submission-ready report per finding
- Includes CVSS scoring
- Includes impact statement
- Includes step-by-step PoC
- Includes severity request paragraph
- Includes chain documentation (if applicable)

**Checklist:**
- [ ] Reports generated for all validated findings
- [ ] CVSS vectors included
- [ ] Impact statements specific
- [ ] PoCs reproducible
- [ ] Severity request paragraphs included

## Pipeline Templates

### Template 1: Quick Assessment (30 minutes)

```yaml
# quick-assessment.yaml
name: "Quick Assessment"
pipeline:
  target: "${TARGET}"
  mode: full-auto
  phases:
    scope: { enabled: true, config: { analysis_depth: quick } }
    recon: { enabled: true, config: { passive_only: true, js_analysis: true } }
    rank: { enabled: false }
    research: { enabled: false }
    hunt:
      enabled: true
      agents: [idor-hunter, ssrf-hunter, xss-hunter]
      timebox_minutes: 8
    chain: { enabled: false }
    validate: { enabled: true }
    evidence: { enabled: false }
    defend: { enabled: false }
    report: { enabled: true, config: { format: summary } }
```

### Template 2: Full Deep Dive (2-4 hours)

```yaml
# full-deep-dive.yaml
name: "Full Deep Dive"
pipeline:
  target: "${TARGET}"
  mode: checkpoint
  checkpoints:
    - before: hunt
    - before: report
  timeouts:
    recon: 1800
    hunt: 3600
    report: 600
  phases:
    scope: { enabled: true }
    recon: { enabled: true }
    rank: { enabled: true }
    research: { enabled: true }
    hunt:
      enabled: true
      agents: all
      timebox_minutes: 15
    chain: { enabled: true }
    validate: { enabled: true }
    evidence: { enabled: true }
    defend: { enabled: true }
    report: { enabled: true }
```

### Template 3: Continuous Monitor (Weekly)

```yaml
# continuous-monitor.yaml
name: "Weekly Monitor"
pipeline:
  target: "${TARGET}"
  mode: full-auto
  phases:
    scope: { enabled: false }
    recon:
      enabled: true
      config:
        diff_previous: true
        passive_only: true
    rank: { enabled: false }
    research: { enabled: false }
    hunt: { enabled: false }
    chain: { enabled: false }
    validate: { enabled: false }
    evidence: { enabled: false }
    defend: { enabled: false }
    report: { enabled: false }
  notifications:
    enabled: true
    notify_on: [completion]
    slack_webhook: "${SLACK_WEBHOOK}"
```

### Template 4: Chain Hunter

```yaml
# chain-hunter.yaml
name: "Chain Hunter"
pipeline:
  target: "${TARGET}"
  mode: manual
  phases:
    scope: { enabled: false }
    recon: { enabled: false }
    rank: { enabled: false }
    research: { enabled: true, config: { focus: chain_primitives } }
    hunt:
      enabled: true
      config: { chain_driven_hunting: true }
    chain: { enabled: true, config: { chain_depth: 3 } }
    validate: { enabled: true }
    evidence: { enabled: true }
    defend: { enabled: true }
    report: { enabled: true }
```

### Template 5: Report-Only Pipeline

```yaml
# report-only.yaml
name: "Report Only"
pipeline:
  target: "${TARGET}"
  mode: manual
  phases:
    scope: { enabled: false }
    recon: { enabled: false }
    rank: { enabled: false }
    research: { enabled: false }
    hunt: { enabled: false }
    chain: { enabled: false }
    validate:
      enabled: true
      config: { findings_dir: "existing-findings/" }
    evidence: { enabled: true }
    defend: { enabled: true }
    report: { enabled: true, config: { format: submission_ready } }
```

## Status Reporting Templates

### Phase Completion Summary

```
=== Phase Complete: HUNT (5/10) ===

Target: target.com
Duration: 32 minutes 14 seconds
Agent: p1-warrior
Dispatched: 4 sub-agents
  - idor-hunter: COMPLETED (1 finding)
  - ssrf-hunter: COMPLETED (0 findings)
  - xss-hunter: COMPLETED (2 findings)
  - auth-bypass-hunter: TIMEOUT (retrying)

Artifacts produced:
  - pipeline/findings/finding-001.md (IDOR in /api/invoices/:id)
  - pipeline/findings/finding-002.md (XSS in /search?q=)
  - pipeline/findings/finding-003.md (Stored XSS in /support/tickets)

Next phase: CHAIN (6/10)
```

### Final Pipeline Report

```
=== Pipeline Complete ===

Target: target.com
Pipeline ID: pip-20260608-abc123
Mode: checkpoint
Total duration: 1 hour 47 minutes
Phases completed: 10/10

Summary:
  - Findings discovered: 5
  - Validated (PASS): 3
  - Killed (KILL): 1
  - Downgraded (DOWNGRADE): 1
  - Chained: 1 (IDOR + CSRF → Account Takeover)
  - Reports generated: 3

Findings:
  1. IDOR in /api/invoices/:id — HIGH — CVSS 7.5
  2. Stored XSS in /support/tickets — HIGH — CVSS 7.3
  3. Account Takeover (IDOR + CSRF chain) — CRITICAL — CVSS 9.0

Artifacts:
  - pipeline/reports/finding-001-idor.md
  - pipeline/reports/finding-002-xss.md
  - pipeline/reports/finding-003-ato-chain.md

Ready for submission: 3 reports
```

### Error Alert

```
=== Pipeline Error Alert ===

Target: target.com
Pipeline ID: pip-20260608-abc123
Phase: HUNT (5/10)
Error type: Agent timeout
Error details: auth-bypass-hunter did not respond within 600s timeout

Retry attempt: 2/3
Next retry in: 16 seconds
Backoff strategy: exponential (1s, 4s, 16s)

If all retries fail:
  - Pipeline will halt at checkpoint
  - Manual intervention required
  - Use --rerun hunt to retry
  - Use --skip to skip failed sub-agent
```

### Progress Bar

```
Pipeline Progress: ██████████░░░░░░░░░░ 50% (5/10 phases)

Current: HUNT
Completed: SCOPE ✓ RECON ✓ RANK ✓ RESEARCH ✓ HUNT ⟳
Remaining: CHAIN | VALIDATE | EVIDENCE | DEFEND | REPORT
Elapsed: 47 minutes
ETC: ~47 minutes
```

## Self-Diagnostics

After completing your analysis, run through this checklist:
- [ ] Did I follow the prescribed methodology?
- [ ] Did I test all relevant input vectors?
- [ ] Did I record exact curl commands and raw responses?
- [ ] Is my finding reproducible from scratch?
- [ ] Is the finding clearly in scope?
- [ ] Have I attempted to chain this with other primitives?
- [ ] Did I validate with a second technique?
- [ ] Is there a more severe variant I might have missed?
- [ ] Is the evidence clean (no exposed cookies/PII)?
- [ ] Would this survive triage scrutiny?

## Cross-Agent Handoff

After confirming a finding, hand off to:
- **chain-builder**: if this primitive can be chained with others (e.g., SSRF ? cloud metadata, IDOR ? auth bypass)
- **validator**: for 7-Question Gate check before report writing
- **evidence-reviewer**: for PoC hygiene check (cookies masked, PII redacted)
- **triage-defender**: for triage objection prebuttal
- **report-writer**: for CVSS-scored submission-ready report
