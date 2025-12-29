# EIP-7702 Inspector

A comprehensive verification tool for EIP-7702 (EOA Code Delegation) implementations. This tool is designed based on test patterns from go-ethereum and reth implementations.

## Overview

EIP-7702 introduces a new transaction type (0x04) that allows Externally Owned Accounts (EOAs) to temporarily delegate their code execution to a contract. This inspector verifies:

- **Delegation Code**: Correct format (0xef0100 + address)
- **Authorization Signing**: Proper SigHash calculation and authority recovery
- **SetCode Transactions**: Structure validation and error handling
- **Gas Calculation**: Correct intrinsic gas with authorization costs

## Installation

```bash
cd eip7702-inspector
go mod tidy
go build
```

## Deployed Contracts (Sepolia Testnet)

Smart contracts for EIP-7702 testing are deployed on Sepolia:

| Contract | Address | Description |
|----------|---------|-------------|
| **BatchExecutor** | [`0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85`](https://sepolia.etherscan.io/address/0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85) | Batch transaction execution |
| **SimpleAccount** | [`0x62DAAf50Fab4Bb37BF2C94C9F308fAD90EfE7152`](https://sepolia.etherscan.io/address/0x62DAAf50Fab4Bb37BF2C94C9F308fAD90EfE7152) | ERC-4337 compatible AA account |
| **MultisigLogic** | [`0xfdBEC6aD9A98A2e9bF1cf740A2FDe3Bf15b78CfC`](https://sepolia.etherscan.io/address/0xfdBEC6aD9A98A2e9bF1cf740A2FDe3Bf15b78CfC) | N-of-M multisig |
| **SessionKeyManager** | [`0xc0EE9C061ABfC80bd96a130CCAb053c7ED7B4d0B`](https://sepolia.etherscan.io/address/0xc0EE9C061ABfC80bd96a130CCAb053c7ED7B4d0B) | Session key management |
| **PaymasterHelper** | [`0x362BF4810C647AF570Bb6F6c583b53c422C026Bf`](https://sepolia.etherscan.io/address/0x362BF4810C647AF570Bb6F6c583b53c422C026Bf) | Gas sponsorship integration |

**Network**: Sepolia (Chain ID: 11155111)
**EntryPoint (ERC-4337)**: `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`

## Usage

### Quick Verification (Offline)

```bash
./eip7702-inspector -quick
```

### Full Inspection (Offline)

```bash
./eip7702-inspector -verbose
```

### Network Testing (Sepolia Testnet)

Test EIP-7702 transactions on a live network.

#### Using Private Key

```bash
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0xYOUR_PRIVATE_KEY" \
  -target "0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85"
```

#### Using Mnemonic

```bash
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -mnemonic "your twelve word mnemonic phrase here" \
  -target "0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85"
```

#### Contract-Specific Test Examples

```bash
# Delegate to BatchExecutor
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0x..." \
  -target "0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85"

# Delegate to MultisigLogic
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0x..." \
  -target "0xfdBEC6aD9A98A2e9bF1cf740A2FDe3Bf15b78CfC"

# Delegate to SessionKeyManager
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0x..." \
  -target "0xc0EE9C061ABfC80bd96a130CCAb053c7ED7B4d0B"
```

### Options

| Flag | Description | Default |
|------|-------------|---------|
| `-chain-id` | Chain ID for testing | 1 |
| `-key` | Private key hex for signing | (test key) |
| `-mnemonic` | BIP39 mnemonic for key derivation | - |
| `-quick` | Run quick verification only | false |
| `-verbose` | Show detailed output | false |
| `-network` | Run network tests against live node | false |
| `-rpc` | RPC URL for network testing | http://localhost:8545 |
| `-target` | Target contract address for delegation | 0x42 |
| `-security` | Run security analysis on target address | false |
| `-attack` | Run attack simulations | false |
| `-validate` | Validate authorization or contract security | false |

## Security Analysis

EIP-7702 Inspector includes comprehensive security analysis tools to detect vulnerabilities and validate best practices.

### Security Analysis

Analyze an address for EIP-7702 security risks:

```bash
# Analyze a specific address
./eip7702-inspector -security -target 0x1234...

# With RPC connection for on-chain analysis
./eip7702-inspector -security -target 0x1234... -rpc "https://eth-mainnet.g.alchemy.com/v2/..."
```

**Output includes:**
- Delegation status and target
- Known malicious contract detection
- Audit status verification
- Risk score (0-10)
- Security findings and recommendations

### Attack Simulation

Simulate known EIP-7702 attack vectors:

```bash
./eip7702-inspector -attack
```

**Simulated Attack Types:**

| Attack | Description | Risk Level |
|--------|-------------|------------|
| **Cross-Chain Replay** | Authorization with chainId=0 replayed across multiple chains | Critical |
| **Front-Running** | Attacker front-runs wallet initialization | Critical |
| **Whitelist Bypass** | Delegated address bypasses msg.sender whitelist | High |
| **Nonce Manipulation** | Re-delegation enables signature replay | High |
| **Storage Collision** | Different contract storage layouts conflict | High |

**Example Output:**
```
=== Cross-Chain Replay Attack Simulation ===
Type: CROSS_CHAIN_REPLAY
Impact: Complete loss of assets on ALL EVM chains

Attack Steps:
  1. [victim] Victim signs authorization with chainId=0
  2. [attacker] Attacker observes the signed authorization
  3. [attacker] Attacker replays on Ethereum Mainnet
  4. [attacker] Attacker replays on Arbitrum
  ...

Simulation Result: VULNERABLE
Recommendations:
  * NEVER sign authorizations with chainId=0
  * Wallets should block or warn about chainId=0 authorizations
```

### Authorization Validation

Validate an authorization against security best practices:

```bash
# Validate with specific chainId (safe)
./eip7702-inspector -validate -target 0x0000...0042 -chain-id 1

# Validate with chainId=0 (detects vulnerability)
./eip7702-inspector -validate -target 0x0000...0042 -chain-id 0
```

**Validation Checks:**

| Check | Category | Description |
|-------|----------|-------------|
| **ChainID Zero Check** | Cross-Chain Security | Detects chainId=0 replay risk |
| **Trusted Contract Check** | Contract Security | Verifies against trusted contract list |
| **BP001: Use Specific ChainID** | Best Practice | Recommends specific chainId |

**Example Output (Safe):**
```
Authorization Valid: true
Authorization Safe: true
Should Block: false

[PASS] ChainID Validation - ChainID is properly set
[PASS] Trusted Contract Check - Target contract is trusted
[PASS] BP001: Use Specific ChainID - ChainID is properly specified
```

**Example Output (Vulnerable):**
```
Authorization Valid: true
Authorization Safe: false
Should Block: true
Block Reason: Authorization uses chainId=0 which is valid on ALL chains

[FAIL] [CRITICAL] ChainID Zero Check
       Authorization uses chainId=0 which is valid on ALL chains
       Suggestion: Use specific chainId for the target network
```

### Security Documentation

For comprehensive security documentation, see [`docs/SECURITY.md`](docs/SECURITY.md), which covers:

- Detailed vulnerability explanations
- Attack flow diagrams
- Mitigation code examples
- Security checklists for developers, wallets, and users

### Security Notice

> **Warning**: Private keys or mnemonics entered on the command line are stored in shell history. Use environment variables in production:

```bash
export PRIVATE_KEY="0x..."
./eip7702-inspector -network -key "$PRIVATE_KEY" ...
```

## Test Categories

### 1. Delegation Tests

Based on go-ethereum's `TestParseDelegation`:

- Valid delegation format (0xef0100 + 20-byte address)
- Invalid prefix handling
- Wrong length detection
- Edge cases (nil, empty, partial)

### 2. Authorization Tests

Based on go-ethereum's `SignSetCode` and `Authority`:

- SigHash calculation (0x05 prefix)
- Signature creation and verification
- Authority recovery from signature
- Chain ID validation (including wildcard 0)

### 3. SetCode Transaction Tests

Based on go-ethereum's `TestEIP7702` and reth's error handling:

- Empty auth list detection (`ErrEmptyAuthList`)
- Chain ID verification
- Multiple authorization handling
- Gas limit validation

### 4. Gas Calculation Tests

Based on EIP-7702 specification:

- Base cost: 25,000 per authorization (`PER_EMPTY_ACCOUNT_COST`)
- Refund: 12,500 for existing accounts (`PER_AUTH_BASE_COST`)
- Calldata costs (4 for zero, 16 for non-zero bytes)
- Access list costs

## EIP-7702 Specification Reference

### Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `DELEGATION_PREFIX` | 0xef0100 | 3-byte prefix for delegation code |
| `DELEGATION_CODE_LENGTH` | 23 | Total length (prefix + address) |
| `AUTHORIZATION_SIGNING_PREFIX` | 0x05 | Prefix for authorization signing |
| `SET_CODE_TX_TYPE` | 0x04 | Transaction type for EIP-7702 |
| `PER_EMPTY_ACCOUNT_COST` | 25,000 | Gas per authorization (new account) |
| `PER_AUTH_BASE_COST` | 12,500 | Refund for existing account |

### Authorization Structure

```go
type SetCodeAuthorization struct {
    ChainID uint256         // Chain ID (0 = any chain)
    Address common.Address  // Target contract address
    Nonce   uint64          // Account nonce
    V       uint8           // Signature V
    R       uint256         // Signature R
    S       uint256         // Signature S
}
```

### SigHash Calculation

```
keccak256(0x05 || rlp([chain_id, address, nonce]))
```

## Library Usage

```go
import "github.com/stable-net/eip7702-inspector/inspector"

// Verify delegation code
result := inspector.VerifyDelegation(code)
if !result.Valid {
    fmt.Println("Invalid:", result.ErrorMessage)
}

// Create and sign authorization
auth := inspector.SetCodeAuthorization{
    Address: targetAddr,
    Nonce:   0,
}
signedAuth, err := inspector.SignSetCode(privateKey, auth)

// Verify SetCode transaction
txResult := inspector.VerifySetCodeTx(tx, chainID)

// Run full inspection
insp := inspector.NewInspector(chainID, privateKeyHex)
report, err := insp.RunFullInspection()
```

### Security Library Usage

```go
import "github.com/stable-net/eip7702-inspector/inspector"

// Security Analysis
analyzer := inspector.NewSecurityAnalyzer()
result := analyzer.AnalyzeAddress(addr, code)
fmt.Printf("Risk Score: %.1f/10\n", result.RiskScore)
for _, finding := range result.Findings {
    fmt.Printf("[%s] %s: %s\n", finding.Risk, finding.Title, finding.Description)
}

// Authorization Security Check
check := analyzer.AnalyzeAuthorization(auth, chainID)
if !check.IsSafe {
    fmt.Println("Warning:", check.Warnings)
}

// Attack Simulation
simulator, _ := inspector.NewAttackSimulator(chainID, privateKeyHex)
results := simulator.RunAllAttackSimulations(targetContract)
for _, r := range results {
    if r.Vulnerable {
        fmt.Printf("Vulnerable to %s: %s\n", r.Attack.Type, r.Attack.Impact)
    }
}

// Validation
validator := inspector.NewValidator(chainID)
validator.AddTrustedContract(trustedAddr)
validator.AddBlockedContract(maliciousAddr, "Known phishing contract")

validationResult := validator.ValidateAuthorization(auth)
if validationResult.ShouldBlock {
    fmt.Println("Block:", validationResult.BlockReason)
}

// Best Practice Checking
bpc := inspector.NewBestPracticeChecker()
checks := bpc.CheckAuthorizationBestPractices(auth)
for _, c := range checks {
    status := "PASS"
    if !c.Passed {
        status = "FAIL"
    }
    fmt.Printf("[%s] %s\n", status, c.CheckName)
}
```

## Smart Contracts

Smart contracts available for EIP-7702 delegation are located in the `contracts/` directory.

### Contract Descriptions

| Contract | Description | Use Case |
|----------|-------------|----------|
| **BatchExecutor** | Execute multiple calls in one transaction | DeFi batch operations, multi-transfers |
| **SimpleAccount** | ERC-4337 EntryPoint compatible AA account | Account Abstraction |
| **MultisigLogic** | N-of-M multisig requirement | Jointly managed accounts |
| **SessionKeyManager** | Issue temporary keys with limited permissions | Games, dApp sessions |
| **PaymasterHelper** | Paymaster integration for gas sponsorship | Gasless transactions |

### Build and Deploy Contracts

```bash
cd contracts

# Build
forge build

# Test
forge test -vv

# Deploy to Sepolia
export PRIVATE_KEY=0x...
forge script script/Deploy.s.sol:Deploy \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --broadcast
```

### EIP-7702 Flow Diagram

```
┌─────────────────────────────────────────────────────────────────┐
│                        EIP-7702 Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. EOA signs SetCodeAuthorization                              │
│     ┌──────────────┐                                            │
│     │     EOA      │ ──sign──> Authorization{target, nonce}     │
│     └──────────────┘                                            │
│                                                                 │
│  2. Send SetCode transaction (type 0x04)                        │
│     ┌──────────────┐      ┌──────────────┐                      │
│     │     EOA      │ ──TX──>│   Network   │                     │
│     └──────────────┘      └──────────────┘                      │
│                                                                 │
│  3. EOA code is set to delegation code                          │
│     ┌──────────────┐      ┌──────────────┐                      │
│     │     EOA      │──────│ 0xef0100... │ (delegation prefix)   │
│     │  (has code)  │      │ + target    │                       │
│     └──────────────┘      └──────────────┘                      │
│                                                                 │
│  4. EOA can call contract functions                             │
│     ┌──────────────┐      ┌──────────────┐                      │
│     │     EOA      │──call──>│BatchExecutor│                    │
│     │              │      │.executeBatch()│                     │
│     └──────────────┘      └──────────────┘                      │
│                                  │                              │
│                    ┌─────────────┼─────────────┐                │
│                    ▼             ▼             ▼                │
│              [Target A]    [Target B]    [Target C]             │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Example Transactions (Sepolia Testnet)

Example EIP-7702 transactions executed on Sepolia testnet.

### 1. SetCode Transaction (EIP-7702 Delegation Setup)

Sets BatchExecutor contract as delegation for the EOA.

| Item | Value |
|------|-------|
| **TxHash** | [`0xb703bf51385a8469f58caae0b8e5aa0c8e59ffd84ff128f94273fb07ce873a91`](https://sepolia.etherscan.io/tx/0xb703bf51385a8469f58caae0b8e5aa0c8e59ffd84ff128f94273fb07ce873a91) |
| **EOA (Authority)** | `0x309F618825AfaCFCb532ba47420106F766B84048` |
| **Target Contract** | `0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85` (BatchExecutor) |
| **Tx Type** | `0x04` (SetCode) |

### 2. Batch Execution (Function Execution via EIP-7702)

Calls `executeBatch()` from the delegated EOA to send ETH to multiple addresses.

| Item | Value |
|------|-------|
| **TxHash** | [`0xb96be303c8bbe90fdddcab0187b8d0e4fae15039deca57ef80485acefa8fc5e7`](https://sepolia.etherscan.io/tx/0xb96be303c8bbe90fdddcab0187b8d0e4fae15039deca57ef80485acefa8fc5e7) |
| **Caller (EOA)** | `0x309F618825AfaCFCb532ba47420106F766B84048` |
| **Tx Type** | `0x02` (EIP-1559) |

### How It Works

1. **EOA** (`0x309F618825AfaCFCb532ba47420106F766B84048`) sets **BatchExecutor** contract (`0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85`) as delegation
2. EIP-1559 transaction calls self (EOA) with `executeBatch()` function
3. Sends 0.0001 ETH each to 2 addresses:
   - `0x000000000000000000000000000000000000dEaD` (burn address)
   - `0x0000000000000000000000000000000000000001` (ecrecover precompile)

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Example: Batch ETH Transfer                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Step 1: SetCode Transaction (type 0x04)                              │
│  ┌─────────────────┐      ┌─────────────────┐                         │
│  │       EOA       │─────>│   BatchExecutor │                         │
│  │ 0x309F61...     │      │   0xA6E8CF...   │                         │
│  └─────────────────┘      └─────────────────┘                         │
│         │                                                             │
│         ▼                                                             │
│  EOA Code: 0xef0100a6e8cf0671563914489f2ec2436cebccd17b7a85           │
│                                                                       │
│  Step 2: Batch Execution (type 0x02)                                  │
│  ┌─────────────────┐                                                  │
│  │       EOA       │──call self──> executeBatch(                      │
│  │   (delegated)   │                [0xdead, 0x0001],                 │
│  └─────────────────┘                [0.0001 ETH, 0.0001 ETH],         │
│         │                           [[], []]                          │
│         │                          )                                  │
│         ▼                                                             │
│  ┌──────────┬──────────┐                                              │
│  │  0xdEaD  │  0x0001  │                                              │
│  │ +0.0001  │ +0.0001  │                                              │
│  └──────────┴──────────┘                                              │
│                                                                       │
└──────────────────────────────────────────────────────────────────────┘
```

## Test Sources

This inspector's test patterns are derived from:

### go-ethereum

- `core/types/tx_setcode.go`: Core EIP-7702 implementation
- `core/types/tx_setcode_test.go`: Delegation parsing tests
- `core/blockchain_test.go`: Integration tests (TestEIP7702)
- `core/state_processor_test.go`: Error handling tests

### reth

- `crates/transaction-pool/src/error.rs`: EIP-7702 error types
- `crates/storage/codecs/src/alloy/authorization_list.rs`: Authorization encoding
- `crates/payload/validator/src/prague.rs`: Prague field validation

## Related Projects

- **go-stablenet**: go-ethereum fork with EIP-7702 and fee delegation
- **go-ethereum**: Reference Ethereum implementation
- **reth**: Rust Ethereum execution client

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
