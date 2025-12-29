# EIP-7702 Security Guide

## Overview

EIP-7702 introduces powerful capabilities for EOAs but also creates new attack surfaces. This document provides comprehensive security guidance for developers, auditors, and users.

---

## Table of Contents

1. [Vulnerability Summary](#vulnerability-summary)
2. [Critical Vulnerabilities](#critical-vulnerabilities)
3. [Attack Vectors](#attack-vectors)
4. [Mitigation Strategies](#mitigation-strategies)
5. [Security Checklists](#security-checklists)
6. [Code Patterns](#code-patterns)

---

## Vulnerability Summary

| Vulnerability | Severity | Impact | Exploited in Wild |
|---------------|----------|--------|-------------------|
| Phishing via Delegation | Critical | Full asset theft | Yes ($12M+) |
| Cross-Chain Replay | Critical | Multi-chain compromise | Yes |
| Front-Running Initialization | High | Account takeover | Yes |
| Storage Collision | High | Fund loss, logic errors | Potential |
| Whitelist Bypass | Medium | Privilege escalation | Potential |
| msg.sender Assumption Break | Medium | Contract logic bypass | Potential |

---

## Critical Vulnerabilities

### 1. Phishing via Malicious Delegation

**Description**: Attackers trick users into signing authorization tuples that delegate their EOA to malicious contracts.

**Attack Flow**:
```
1. Victim visits malicious dApp
2. dApp requests "normal looking" signature
3. Signature is actually an EIP-7702 authorization
4. Victim's EOA code is set to malicious contract
5. All incoming transactions are intercepted
6. Attacker drains all assets
```

**Impact**:
- Complete loss of all ETH and tokens
- Permanent until delegation is revoked
- Can affect future deposits

**Real-World Stats**:
- $12M+ stolen from 15,000+ wallets
- 90%+ of observed delegations are malicious
- Single victim losses up to $1.54M

**Detection**:
```go
// Check if address has suspicious delegation
func IsSuspiciousDelegation(code []byte, knownMalicious map[common.Address]bool) bool {
    if !IsDelegation(code) {
        return false
    }
    target, _ := ParseDelegation(code)
    return knownMalicious[target]
}
```

### 2. Cross-Chain Replay Attack

**Description**: Authorization with `chainId = 0` is valid on ALL EVM chains.

**Attack Flow**:
```
1. Victim signs authorization with chainId = 0
2. Attacker captures the signature
3. Attacker replays on: Mainnet, Arbitrum, Optimism, Base, Polygon, etc.
4. All chains are compromised simultaneously
```

**Vulnerable Code**:
```go
// DANGEROUS: chainId = 0 allows replay on any chain
auth := SetCodeAuthorization{
    ChainID: *uint256.NewInt(0),  // BAD!
    Address: targetContract,
    Nonce:   0,
}
```

**Safe Code**:
```go
// SAFE: Specific chainId prevents cross-chain replay
auth := SetCodeAuthorization{
    ChainID: *uint256.MustFromBig(chainID),  // GOOD!
    Address: targetContract,
    Nonce:   currentNonce,
}
```

### 3. Front-Running Initialization Attack

**Description**: EIP-7702 cannot atomically set delegation AND initialize storage.

**Attack Flow**:
```
TX1: Victim sets delegation to SmartWallet
     [Vulnerability Window]
TX2: Attacker front-runs with initialize(attackerAddress)
TX3: Victim's initialize() fails - attacker owns the wallet
```

**Vulnerable Contract**:
```solidity
// VULNERABLE: Anyone can call initialize()
contract VulnerableWallet {
    address public owner;
    bool public initialized;

    function initialize(address _owner) external {
        require(!initialized);
        owner = _owner;
        initialized = true;
    }
}
```

**Safe Contract**:
```solidity
// SAFE: Signature verification prevents front-running
contract SecureWallet {
    address public owner;

    function initialize(
        address _owner,
        uint256 deadline,
        bytes calldata signature
    ) external {
        require(owner == address(0), "Already initialized");
        require(block.timestamp <= deadline, "Expired");

        bytes32 hash = keccak256(abi.encodePacked(
            address(this), _owner, deadline, block.chainid
        ));
        require(ECDSA.recover(hash, signature) == address(this));

        owner = _owner;
    }
}
```

### 4. Storage Collision

**Description**: Re-delegating to different contracts causes storage layout conflicts.

**Example**:
```
ContractA Storage:
  slot 0: bool isActive = true (0x01)
  slot 1: address owner

ContractB Storage:
  slot 0: uint256 balance  // Reads 0x01 = 1 (WRONG!)
  slot 1: mapping(...)     // Corrupted
```

**Mitigation**: Use ERC-7201 Namespaced Storage:
```solidity
contract SafeStorage {
    // keccak256("eip7702.wallet.v1") - 1
    bytes32 private constant STORAGE_SLOT = 0x...;

    struct WalletStorage {
        address owner;
        uint256 nonce;
    }

    function _getStorage() internal pure returns (WalletStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }
}
```

---

## Attack Vectors

### Vector 1: Whitelist Bypass

**Scenario**: Protocol whitelists certain addresses for privileged operations.

**Attack**:
```
1. Alice is whitelisted
2. Alice delegates to ProxyContract (signs authorization)
3. Bob uses Alice's authorization in his transaction
4. msg.sender = Alice (passes whitelist check)
5. Bob gains Alice's privileges
```

**Detection Code**:
```go
// Detect if address is using delegation (potential whitelist bypass)
func HasDelegation(code []byte) bool {
    return len(code) == 23 &&
           code[0] == 0xef &&
           code[1] == 0x01 &&
           code[2] == 0x00
}
```

### Vector 2: Sweeper Contracts

**Description**: Malicious contracts that automatically drain all assets.

**Sweeper Pattern**:
```solidity
// Malicious sweeper contract
contract Sweeper {
    address constant ATTACKER = 0x...;

    receive() external payable {
        payable(ATTACKER).transfer(address(this).balance);
    }

    fallback() external payable {
        // Drain all tokens on any call
        _sweepAllTokens();
    }
}
```

### Vector 3: Nonce Manipulation

**Description**: Exploiting nonce handling in re-delegation scenarios.

**Risk**: If nonce tracking storage is corrupted during re-delegation, previously used signatures could be replayed.

---

## Mitigation Strategies

### For Smart Contract Developers

#### 1. Detect EIP-7702 Delegation
```solidity
modifier noEIP7702Delegation() {
    bytes memory code = msg.sender.code;
    if (code.length >= 3) {
        require(
            !(code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00),
            "Delegation not allowed"
        );
    }
    _;
}
```

#### 2. Strict EOA Check
```solidity
modifier strictlyEOA() {
    require(msg.sender == tx.origin, "Must be EOA");
    require(msg.sender.code.length == 0, "Must have no code");
    _;
}
```

#### 3. Use Namespaced Storage (ERC-7201)
```solidity
// Prevents storage collision across different delegation targets
bytes32 constant STORAGE_SLOT = keccak256("myproject.wallet.v1") - 1;
```

#### 4. Signature-Protected Initialization
```solidity
function initialize(bytes calldata signature) external {
    bytes32 hash = keccak256(abi.encodePacked(address(this), block.chainid));
    require(ECDSA.recover(hash, signature) == address(this));
    // ... initialization logic
}
```

### For Wallet/dApp Developers

#### 1. Validate Authorization Before Signing
```go
func ValidateAuthorizationRequest(auth *SetCodeAuthorization, currentChainID *big.Int) error {
    // Reject chainId = 0 (cross-chain replay risk)
    if auth.ChainID.IsZero() {
        return errors.New("chainId=0 not allowed: cross-chain replay risk")
    }

    // Verify chainId matches current network
    if auth.ChainID.ToBig().Cmp(currentChainID) != 0 {
        return errors.New("chainId mismatch: potential wrong network")
    }

    // Check against known malicious contracts
    if IsMaliciousContract(auth.Address) {
        return errors.New("target contract is flagged as malicious")
    }

    return nil
}
```

#### 2. Whitelist Trusted Contracts
```go
var TrustedDelegationTargets = map[common.Address]string{
    common.HexToAddress("0x..."): "Official SimpleAccount",
    common.HexToAddress("0x..."): "Audited BatchExecutor",
}

func IsAllowedDelegation(target common.Address) bool {
    _, exists := TrustedDelegationTargets[target]
    return exists
}
```

#### 3. Display Clear Warnings
```go
type DelegationWarning struct {
    Severity    string
    Title       string
    Description string
    Action      string
}

func GetDelegationWarnings(auth *SetCodeAuthorization) []DelegationWarning {
    var warnings []DelegationWarning

    if auth.ChainID.IsZero() {
        warnings = append(warnings, DelegationWarning{
            Severity:    "CRITICAL",
            Title:       "Cross-Chain Replay Risk",
            Description: "This authorization can be used on ANY blockchain",
            Action:      "Reject unless absolutely necessary",
        })
    }

    // ... more checks
    return warnings
}
```

### For Users

| Do | Don't |
|----|-------|
| Use wallets with EIP-7702 protection (MetaMask, OKX) | Sign authorization on unknown dApps |
| Verify delegation target before signing | Use chainId = 0 authorizations |
| Use separate wallets for high-value assets | Keep large amounts in delegated wallets |
| Monitor token approvals regularly | Ignore wallet warnings |
| Revoke delegation after use | Leave permanent delegations |

---

## Security Checklists

### Pre-Deployment Checklist (Smart Contracts)

- [ ] Contract designed specifically for EIP-7702 (not pre-existing wallet)
- [ ] Uses ERC-7201 namespaced storage
- [ ] Initialization protected by signature verification
- [ ] No storage collision risks with potential re-delegation
- [ ] Comprehensive security audit completed
- [ ] Tested against all known attack vectors

### Authorization Signing Checklist (Wallets)

- [ ] chainId != 0 (unless explicitly required)
- [ ] chainId matches current network
- [ ] Target contract is audited and whitelisted
- [ ] Nonce matches expected value
- [ ] User shown clear delegation details
- [ ] Expiration/revocation mechanism available

### Integration Checklist (Protocols)

- [ ] Updated whitelist logic to detect delegation
- [ ] Added delegation detection modifiers
- [ ] msg.sender assumptions reviewed
- [ ] Monitoring for suspicious delegation patterns
- [ ] Incident response plan for delegation exploits

---

## Code Patterns

### Safe Delegation Target Contract

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract SecureEIP7702Wallet {
    using ECDSA for bytes32;

    // ERC-7201: Namespaced storage to prevent collision
    bytes32 private constant STORAGE_SLOT =
        keccak256("securewallet.eip7702.v1") - 1;

    struct WalletStorage {
        address owner;
        uint256 nonce;
        mapping(bytes32 => bool) usedSignatures;
    }

    error AlreadyInitialized();
    error InvalidSignature();
    error SignatureExpired();
    error SignatureReused();
    error NotOwner();

    function _getStorage() internal pure returns (WalletStorage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function initialize(
        address _owner,
        uint256 deadline,
        bytes calldata signature
    ) external {
        WalletStorage storage s = _getStorage();
        if (s.owner != address(0)) revert AlreadyInitialized();
        if (block.timestamp > deadline) revert SignatureExpired();

        bytes32 hash = keccak256(abi.encodePacked(
            "\x19Ethereum Signed Message:\n32",
            keccak256(abi.encodePacked(
                address(this),
                _owner,
                deadline,
                block.chainid
            ))
        ));

        if (hash.recover(signature) != address(this)) revert InvalidSignature();
        if (s.usedSignatures[hash]) revert SignatureReused();

        s.owner = _owner;
        s.usedSignatures[hash] = true;
    }

    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable returns (bytes memory) {
        WalletStorage storage s = _getStorage();
        if (msg.sender != s.owner) revert NotOwner();

        (bool success, bytes memory result) = target.call{value: value}(data);
        require(success, "Execution failed");
        return result;
    }

    receive() external payable {}
}
```

### Delegation Detection Library

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

library EIP7702Detector {
    bytes3 constant DELEGATION_PREFIX = 0xef0100;
    uint256 constant DELEGATION_LENGTH = 23;

    function isDelegated(address account) internal view returns (bool) {
        bytes memory code = account.code;
        if (code.length != DELEGATION_LENGTH) return false;
        return code[0] == 0xef && code[1] == 0x01 && code[2] == 0x00;
    }

    function getDelegationTarget(address account) internal view returns (address target, bool success) {
        bytes memory code = account.code;
        if (code.length != DELEGATION_LENGTH) return (address(0), false);
        if (code[0] != 0xef || code[1] != 0x01 || code[2] != 0x00) {
            return (address(0), false);
        }

        assembly {
            target := mload(add(code, DELEGATION_LENGTH))
        }
        return (target, true);
    }
}
```

---

## References

- [EIP-7702 Specification](https://eips.ethereum.org/EIPS/eip-7702)
- [ERC-7201: Namespaced Storage Layout](https://eips.ethereum.org/EIPS/eip-7201)
- [Halborn: EIP-7702 Security Considerations](https://www.halborn.com/blog/post/eip-7702-security-considerations)
- [Fireblocks: Security First Approach to EIP-7702](https://www.fireblocks.com/blog/security-first-approach-to-eip-7702)
- [GoPlus Security: EIP-7702 Phishing Attacks](https://goplussecurity.medium.com/)

---

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2025-01-01 | Initial release |
