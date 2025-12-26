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

EIP-7702 테스트를 위한 스마트 컨트랙트가 Sepolia에 배포되어 있습니다:

| Contract | Address | Description |
|----------|---------|-------------|
| **BatchExecutor** | [`0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85`](https://sepolia.etherscan.io/address/0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85) | 배치 트랜잭션 실행 |
| **SimpleAccount** | [`0x62DAAf50Fab4Bb37BF2C94C9F308fAD90EfE7152`](https://sepolia.etherscan.io/address/0x62DAAf50Fab4Bb37BF2C94C9F308fAD90EfE7152) | ERC-4337 호환 AA 계정 |
| **MultisigLogic** | [`0xfdBEC6aD9A98A2e9bF1cf740A2FDe3Bf15b78CfC`](https://sepolia.etherscan.io/address/0xfdBEC6aD9A98A2e9bF1cf740A2FDe3Bf15b78CfC) | N-of-M 다중 서명 |
| **SessionKeyManager** | [`0xc0EE9C061ABfC80bd96a130CCAb053c7ED7B4d0B`](https://sepolia.etherscan.io/address/0xc0EE9C061ABfC80bd96a130CCAb053c7ED7B4d0B) | 세션 키 관리 |
| **PaymasterHelper** | [`0x362BF4810C647AF570Bb6F6c583b53c422C026Bf`](https://sepolia.etherscan.io/address/0x362BF4810C647AF570Bb6F6c583b53c422C026Bf) | 가스비 대납 통합 |

**Network**: Sepolia (Chain ID: 11155111)
**EntryPoint (ERC-4337)**: `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`

## Usage

### Quick Verification (오프라인)

```bash
./eip7702-inspector -quick
```

### Full Inspection (오프라인)

```bash
./eip7702-inspector -verbose
```

### Network Testing (Sepolia 테스트넷)

실제 네트워크에서 EIP-7702 트랜잭션을 테스트합니다.

#### 프라이빗 키 사용

```bash
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0xYOUR_PRIVATE_KEY" \
  -target "0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85"
```

#### 니모닉 사용

```bash
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -mnemonic "your twelve word mnemonic phrase here" \
  -target "0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85"
```

#### 컨트랙트별 테스트 예시

```bash
# BatchExecutor로 위임 테스트
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0x..." \
  -target "0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85"

# MultisigLogic으로 위임 테스트
./eip7702-inspector -network \
  -rpc "https://ethereum-sepolia-rpc.publicnode.com" \
  -key "0x..." \
  -target "0xfdBEC6aD9A98A2e9bF1cf740A2FDe3Bf15b78CfC"

# SessionKeyManager로 위임 테스트
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

### 주의사항

⚠️ **보안**: 커맨드 라인에 프라이빗 키나 니모닉을 직접 입력하면 쉘 히스토리에 저장됩니다. 프로덕션 환경에서는 환경변수를 사용하세요.

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
    ChainID uint256     // Chain ID (0 = any chain)
    Address common.Address  // Target contract address
    Nonce   uint64      // Account nonce
    V       uint8       // Signature V
    R       uint256     // Signature R
    S       uint256     // Signature S
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

## Smart Contracts

EIP-7702 위임 대상으로 사용할 수 있는 스마트 컨트랙트들이 `contracts/` 디렉토리에 있습니다.

### 컨트랙트 설명

| Contract | Description | Use Case |
|----------|-------------|----------|
| **BatchExecutor** | 여러 호출을 하나의 트랜잭션으로 실행 | DeFi 배치 작업, 다중 전송 |
| **SimpleAccount** | ERC-4337 EntryPoint와 호환되는 AA 계정 | Account Abstraction |
| **MultisigLogic** | N-of-M 다중 서명 요구 | 공동 관리 계정 |
| **SessionKeyManager** | 제한된 권한의 임시 키 발급 | 게임, dApp 세션 |
| **PaymasterHelper** | Paymaster 통합으로 가스비 대납 | 가스리스 트랜잭션 |

### 컨트랙트 빌드 및 배포

```bash
cd contracts

# 빌드
forge build

# 테스트
forge test -vv

# Sepolia 배포
export PRIVATE_KEY=0x...
forge script script/Deploy.s.sol:Deploy \
  --rpc-url https://ethereum-sepolia-rpc.publicnode.com \
  --broadcast
```

### EIP-7702 흐름도

```
┌─────────────────────────────────────────────────────────────────┐
│                        EIP-7702 Flow                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. EOA가 SetCodeAuthorization 서명                              │
│     ┌──────────────┐                                            │
│     │     EOA      │ ──sign──> Authorization{target, nonce}    │
│     └──────────────┘                                            │
│                                                                 │
│  2. SetCode 트랜잭션 전송 (type 0x04)                            │
│     ┌──────────────┐      ┌──────────────┐                      │
│     │     EOA      │ ──TX──>│   Network   │                     │
│     └──────────────┘      └──────────────┘                      │
│                                                                 │
│  3. EOA 코드가 위임 코드로 설정됨                                 │
│     ┌──────────────┐      ┌──────────────┐                      │
│     │     EOA      │──────│ 0xef0100... │ (delegation prefix)  │
│     │  (has code)  │      │ + target    │                       │
│     └──────────────┘      └──────────────┘                      │
│                                                                 │
│  4. EOA가 컨트랙트 함수 호출 가능                                 │
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

실제 Sepolia 테스트넷에서 실행된 EIP-7702 트랜잭션 예제입니다.

### 1. SetCode Transaction (EIP-7702 Delegation 설정)

EOA에 BatchExecutor 컨트랙트를 delegation으로 설정합니다.

| Item | Value |
|------|-------|
| **TxHash** | [`0xb703bf51385a8469f58caae0b8e5aa0c8e59ffd84ff128f94273fb07ce873a91`](https://sepolia.etherscan.io/tx/0xb703bf51385a8469f58caae0b8e5aa0c8e59ffd84ff128f94273fb07ce873a91) |
| **EOA (Authority)** | `0x309F618825AfaCFCb532ba47420106F766B84048` |
| **Target Contract** | `0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85` (BatchExecutor) |
| **Tx Type** | `0x04` (SetCode) |

### 2. Batch Execution (EIP-7702를 통한 실제 기능 실행)

Delegation이 설정된 EOA에서 `executeBatch()` 함수를 호출하여 여러 주소로 ETH를 전송합니다.

| Item | Value |
|------|-------|
| **TxHash** | [`0xb96be303c8bbe90fdddcab0187b8d0e4fae15039deca57ef80485acefa8fc5e7`](https://sepolia.etherscan.io/tx/0xb96be303c8bbe90fdddcab0187b8d0e4fae15039deca57ef80485acefa8fc5e7) |
| **Caller (EOA)** | `0x309F618825AfaCFCb532ba47420106F766B84048` |
| **Tx Type** | `0x02` (EIP-1559) |

### 동작 설명

1. **EOA** (`0x309F618825AfaCFCb532ba47420106F766B84048`)에 **BatchExecutor** 컨트랙트 (`0xA6E8CF0671563914489F2eC2436CeBCcD17B7A85`) delegation 설정
2. EIP-1559 트랜잭션으로 자신(EOA)을 호출하며 `executeBatch()` 함수 실행
3. 0.0001 ETH씩 2개 주소로 전송:
   - `0x000000000000000000000000000000000000dEaD` (burn address)
   - `0x0000000000000000000000000000000000000001` (ecrecover precompile)

```
┌──────────────────────────────────────────────────────────────────────┐
│                    Example: Batch ETH Transfer                        │
├──────────────────────────────────────────────────────────────────────┤
│                                                                       │
│  Step 1: SetCode Transaction (type 0x04)                              │
│  ┌─────────────────┐      ┌─────────────────┐                        │
│  │       EOA       │─────>│   BatchExecutor │                        │
│  │ 0x309F61...     │      │   0xA6E8CF...   │                        │
│  └─────────────────┘      └─────────────────┘                        │
│         │                                                             │
│         ▼                                                             │
│  EOA Code: 0xef0100a6e8cf0671563914489f2ec2436cebccd17b7a85          │
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

## Related Projects

- **go-stablenet**: go-ethereum fork with EIP-7702 and fee delegation
- **go-ethereum**: Reference Ethereum implementation
- **reth**: Rust Ethereum execution client

## License

MIT
