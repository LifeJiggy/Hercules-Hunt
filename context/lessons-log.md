# Lessons Log

Central repository for lessons learned from disclosed bug bounty reports,
personal findings, and red-team engagements. Updated whenever a significant
lesson or technique is discovered.

---

## Table of Contents

1. [Vulnerability Lessons](#1-vulnerability-lessons)
2. [Technique Discoveries](#2-technique-discoveries)
3. [Tool Workflow Improvements](#3-tool-workflow-improvements)
4. [Chain Construction Lessons](#4-chain-construction-lessons)
5. [Report Writing Lessons](#5-report-writing-lessons)
6. [Triage & Validation Lessons](#6-triage--validation-lessons)
7. [WAF/CDN Bypass Techniques](#7-wafcdn-bypass-techniques)
8. [Target-Specific Lessons](#8-target-specific-lessons)
9. [Tool Updates Needed](#9-tool-updates-needed)
10. [Reading List](#10-reading-list)

---

## 1. Vulnerability Lessons

### IDOR
- *2026-06-06:* UUID-based IDOR bypass — change last few chars, try negative numbers, try array format `[id1,id2]`. Many UUID implementations are not cryptographically random.
- *2026-06-05:* GraphQL IDOR — batch queries can bypass per-request auth. Use `{"query":"{user(id:1){email}}"}`, then iterate IDs.

### SSRF
- *2026-06-04:* Gopher SSRF to Redis — Redis commands via SSRF can write SSH keys or trigger RCE via cron. Format: `gopher://redis:6379/_*3%0d%0a$3%0d%0aSET%0d%0a...`
- *2026-06-03:* IMDSv1 still works on many AWS accounts — always test `169.254.169.254` even if IMDSv2 is assumed.

### Auth
- *2026-06-02:* JWT `kid` injection — servers that look up the key by `kid` identifier are vulnerable if they don't validate the key server response. Path traversal in `kid` can read arbitrary files.
- *2026-06-01:* MFA step-skip — navigating directly to `/dashboard` after login bypasses the MFA challenge on many apps.

### File Upload
- *2026-06-01:* Magic byte spoofing — prepending PNG header (`\x89PNG\r\n\x1a\n`) to a PHP payload bypasses server-side MIME validation that only checks magic bytes.

## 2. Technique Discoveries

### Parallel Request Testing
*2026-06-07:* Running 5+ parallel requests to the same endpoint with different IDs can bypass sequential IDOR rate limiting. Use Burp Intruder with 5+ threads.

### Blind SSRF Detection
*2026-06-06:* Even if no visible response change, blind SSRF can be confirmed via collaborator DNS lookup. Always include collaborator URLs in SSRF param fuzzing.

### Chaining Approach
*2026-06-05:* When testing ATO primitives, always test in this order: password reset → session fixation → MFA bypass → OAuth → cookie theft. Each primitive builds on the next for chain construction.

## 3. Tool Workflow Improvements

### Python Tools
- *2026-06-07:* 17 Python modules complete. Next improvement: add multi-threading to all P1 hunters for faster batch scanning.
- *2026-06-06:* Orchestrator checkpoint/resume works well — always save checkpoint before running long batch operations.

### PowerShell Tools
- *2026-06-05:* `js-analyzer.ps1` — add recursive endpoint extraction for nested JS bundles (webpack chunks).
- *2026-06-04:* `recon-toolkit.ps1` — add crt.sh certificate transparency search.

## 4. Chain Construction Lessons

- Open redirect + OAuth redirect_uri bypass = OAuth token theft (High/Critical)
- SSRF + cloud metadata = IAM credentials (Critical)
- XSS + CSRF token theft = account takeover (High)
- Subdomain takeover + OAuth redirect_uri = auth code theft (Critical)
- IDOR + mass assignment = privilege escalation (High)
- Weak password reset token + user enumeration = ATO (High)
- SSRF + Redis gopher = RCE (Critical)

## 5. Report Writing Lessons

- *2026-06-05:* Impact-first writing pays more. First sentence must state the business impact.
- *2026-06-04:* Never use "could potentially" — either you demonstrated it or you didn't.
- *2026-06-03:* Always include CVSS 3.1 vector string, not just score.
- *2026-06-02:* Screenshot PoC with and without the exploit for clear before/after.

## 6. Triage & Validation Lessons

- *2026-06-05:* Self-XSS with no impact path is always rejected — don't waste time reporting it.
- *2026-06-04:* Missing rate limiting on login is N/A unless you demonstrate account lockout bypass or credential stuffing.
- *2026-06-03:* Information disclosure of internal IPs is usually N/A on Bugcrowd — check VRT.
- *2026-06-02:* If a finding requires an authenticated session with specific privileges, it's Medium at best unless you can chain it.

## 7. WAF/CDN Bypass Techniques

| Technique | Details |
|-----------|---------|
| IP bypass | Use `1.1.1.1` instead of `1.0.0.1`, try all CNAME IPs as origin |
| HTTP/2 downgrade | Send HTTP/2 request that translates to HTTP/1.1 with smuggled headers |
| Encoding | UTF-16 XML for XXE bypass, Unicode XSS payloads |
| Case | Mixed case on blocklisted strings: `<sCrIpT>` |
| Parameter pollution | Duplicate params: `?id=1&id=2` |
| Method override | `X-HTTP-Method-Override: POST` |

## 8. Target-Specific Lessons

*(Add entries per target)*

## 9. Tool Updates Needed

- [ ] Add multi-threading to all 7 P1 hunters
- [ ] Add collaborator integration to SSRF hunter
- [ ] Add blind callback detection to RCE hunter
- [ ] Add JWT secret wordlist to auth_hunter.py
- [ ] Add DOCX XXE template to file_upload_hunter.py
- [ ] Add rate limit detection report to auth_hunter.py

## 10. Reading List

- [ ] H1 disclosed reports for SSRF → IAM credential chains
- [ ] PortSwigger research on HTTP request smuggling (2026)
- [ ] OWASP Top 10 API Security Risks — 2026 update
- [ ] PentesterLab SSRF challenges
- [ ] Bugcrowd VRT updates

---

*End of lessons-log.md*
