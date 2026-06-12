# Hooks Module

Session lifecycle hooks for Claude Code and other agentic CLIs. Hooks fire on session start/stop to check scope, verify tools, and enforce discipline.

| File | Description |
|------|-------------|
| `hooks.json` | Base hook configuration for session lifecycle management |
| `autopilot-hooks.json` | Hooks for autonomous hunt loop sessions |
| `chain-builder-hooks.json` | Hooks for exploit chain building sessions |
| `js-analysis-hooks.json` | Hooks for JavaScript analysis sessions |
| `recon-ranker-hooks.json` | Hooks for attack surface ranking sessions |
| `security-reviewer-hooks.json` | Hooks for security code review sessions |
