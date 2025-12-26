# EIP-7702 Contracts

EIP-7702 (EOA Code Delegation)용 스마트 컨트랙트 모음입니다.

## 컨트랙트 목록

| 컨트랙트 | 설명 | 용도 |
|---------|------|------|
| `BatchExecutor` | 배치 트랜잭션 실행 | 여러 트랜잭션을 한 번에 실행 |
| `SimpleAccount` | ERC-4337 호환 계정 | Account Abstraction 기능 추가 |
| `MultisigLogic` | 다중 서명 로직 | N-of-M 다중 서명 요구 |
| `SessionKeyManager` | 세션 키 관리 | 제한된 권한의 임시 키 발급 |
| `PaymasterHelper` | 가스비 대납 통합 | Paymaster를 통한 가스 스폰서십 |

## 빌드 및 테스트

```bash
cd contracts
forge build
forge test -vv
```

## 배포

```bash
export PRIVATE_KEY=0x...
export SEPOLIA_RPC_URL=https://ethereum-sepolia-rpc.publicnode.com

# 전체 배포
forge script script/Deploy.s.sol:Deploy --rpc-url $SEPOLIA_RPC_URL --broadcast
```

## 라이선스

MIT
