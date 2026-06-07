---
name: Immunefi
description: Immunefi-specific report writing guide for smart contract and bug bounty report submissions. Technical depth expectations, PoC requirements, severity for crypto bugs, and platform-specific submission optimization.
---

# Immunefi Report Writing Guide

## Platform Overview

Immunefi is the leading bug bounty platform for Web3 / smart contract security. Reports require deep technical analysis, working proof-of-concept code, and precise impact quantification in financial terms. The audience is experienced smart contract auditors and protocol developers.

---

## Report Format on Immunefi

### Required Fields
- **Title** — bug class + affected contract + financial impact
- **Severity** — Critical, High, Medium, Low, Informational
- **Description** — Detailed technical analysis
- **Proof of Concept** — working Foundry/Hardhat script or transaction data
- **Impact** — financial quantification (max $ at risk)
- **Affected Code** — file paths, function names, line numbers
- **Recommended Fix** — specific code changes

### Key Differences From Web2 Reports
- PoC is NOT optional — you must show exploitation
- Gas estimates are irrelevant, exploit profitability is relevant
- Describe the exact function calls and state changes
- Reference specific lines of code, not just contract names

---

## Severity for Crypto Bugs

| Severity | CVSS Range | Financial Impact | Typical Bugs |
|----------|-----------|-----------------|-------------|
| Critical | 9.0-10.0 | >$1M at risk | Direct fund theft, infinite mint, oracle manipulation with large pool |
| High | 7.0-8.9 | $100K-$1M | Accounting desync, access control bypass, signature replay |
| Medium | 4.0-6.9 | $10K-$100K | Griefing, temporary fund lock, minor accounting errors |
| Low | 1.0-3.9 | <$10K | Frontend bugs, gas inefficiencies, informational |
| Informational | 0.0 | $0 | Best practices, code style |

### Severity Rules Specific to Immunefi
- Financial impact drives severity more than CVSS
- Always quantify max potential loss in USD
- Consider all possible attack paths, not just the obvious one
- Liquidity pool size matters — check TVL before claiming severity
- Chain impact: can you drain one pool, or all pools?

---

## Proof of Concept Requirements

### Minimum Viable PoC
```
1. Setup: state before exploit (who holds what)
2. Exploit transaction(s): exact calldata, function calls
3. Result: state after exploit (attacker gained X tokens worth $Y)
4. Verification: show the imbalance, not just "it worked"
```

### Foundry PoC Template
```solidity
// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/Vulnerable.sol";

contract ExploitTest is Test {
    Vulnerable vuln;
    address attacker = address(0x1337);
    
    function setUp() public {
        vm.startPrank(owner);
        vuln = new Vulnerable();
        // Setup initial state
        deal(address(vuln), 1000 ether);
        vm.stopPrank();
        
        // Fund attacker
        deal(attacker, 10 ether);
    }
    
    function testExploit() public {
        vm.startPrank(attacker);
        
        // Step 1: Setup exploit
        // Step 2: Execute attack
        // Step 3: Verify result
        
        assertGt(address(attacker).balance, 1000 ether);
        vm.stopPrank();
    }
}
```

### When Code PoC Isn't Possible
- Describe exact transaction construction
- Include calldata hex and expected state changes
- Reference existing exploit contracts (e.g., "similar to Euler Finance exploit")
- Show math: token amounts, price manipulation, profit calculation

---

## Technical Depth Expectations

### What Immunefi Triagers Expect
- Read the affected code before writing
- Understand the protocol's accounting model
- Identify the root cause (not just the symptom)
- Describe the exact attack path with function names and line numbers
- Quantify in token amounts AND USD

### What Gets Rejected
- "I think this might be a bug" — test it first
- No PoC — show the exploit or don't report
- Wrong contract version — verify you're testing the latest
- Theoretical impact — prove the fund movement
- Copy-pasted analysis without original thought

---

## Report Structure

### Title Format
```
[Vuln Class] in [Contract:Function] allows [loss type] of up to [$X]
```

**Examples:**
- `Accounting desync in Vault:redeem allows draining 2x shares, $500K at risk`
- `Access control missing in Staking:emergencyWithdraw allows any user to steal staked funds`
- `Signature replay in Bridge:relay allows unlimited token minting`

### Description
```
## Root Cause
[What line(s) cause the bug? Why does the check fail?]

## Attack Path
1. [Step 1] — call Vault.deposit(amount) with attacker's tokens
2. [Step 2] — call Vault.redeem(shares) before accounting updates
3. [Step 3] — repeat until pool is drained

## Affected Code
- Vault.sol:L42-L48 — `redeem()` uses cached balance instead of updated balance
- Vault.sol:L120 — missing `updateAccounting()` modifier

## Proof of Concept
[Foundry test or transaction trace]

## Impact
Attacker can drain [X] tokens worth $[Y] from [pool/liquidity source].
Max loss: $[Z] if attacker has sufficient funds to execute at scale.

## Recommended Fix
[Specific code change with line references]
```

---

## Handling Triage

### Common Questions From Triagers
- "Can this be done in one transaction?" — answer yes/no with evidence
- "Does this require a flash loan?" — explain the capital requirement
- "What's the max practical loss?" — calculate with current TVL
- "Is this a duplicate of (similar bug class)?" — show the distinction

### Severity Negotiation
- Immunefi triagers are technical — they read the code
- If they downgrade, read their reasoning carefully
- Counter with financial evidence, not emotion
- If they're right, accept and learn

---

## Immunefi-Specific Tips

### Pre-Submission Research
- Check TVL before submitting — low TVL = low severity
- Read the protocol's bug bounty page for specific rules
- Some protocols have "no duplicate" policies for similar bugs
- Check disclosed reports to understand what pays

### Common Kill Signals
- TVL < $500K (unless critical impact)
- Bug requires social engineering (phishing, private key compromise)
- Bug only affects testnet
- Protocol explicitly excludes your bug class
- Bug requires unrealistic market conditions

### Chain Reports
- Chain bugs (A→B→C) are welcomed but require full PoC
- Each step must be independently verified
- Show the combined financial impact, not piecemeal

---

## Submission Checklist (Immunefi-Specific)

```
[ ] Title includes financial impact ($ amount)
[ ] Affected code referenced with file:line
[ ] Root cause explained (not just symptom)
[ ] Attack path described step-by-step
[ ] Foundry/Hardhat PoC included (or detailed tx trace)
[ ] Financial impact quantified in USD
[ ] TVL checked — severity matches pool size
[ ] Scope verified against program policy
[ ] Not a known/common bug class that's excluded
[ ] Read disclosed reports to avoid duplicates
[ ] Protocol version verified (latest)
[ ] PoC reproduces consistently
[ ] One transaction attack or multi-tx explained
[ ] Remediation: specific code change, not generic advice
```

---

## Resources

- Immunefi PoC Template: [report template on Immunefi docs]
- Foundry Book: https://book.getfoundry.sh/
- CVSS 3.1 Calculator: https://www.first.org/cvss/calculator/3.1
- OpenZeppelin Audit Guide: https://blog.openzeppelin.com/security-audits/
