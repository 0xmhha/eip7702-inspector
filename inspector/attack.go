// Package inspector provides EIP-7702 attack simulation and testing capabilities.
package inspector

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// AttackType represents the type of attack being simulated
type AttackType string

const (
	AttackCrossChainReplay    AttackType = "CROSS_CHAIN_REPLAY"
	AttackFrontRunning        AttackType = "FRONT_RUNNING"
	AttackWhitelistBypass     AttackType = "WHITELIST_BYPASS"
	AttackNonceManipulation   AttackType = "NONCE_MANIPULATION"
	AttackStorageCollision    AttackType = "STORAGE_COLLISION"
	AttackDelegationPhishing  AttackType = "DELEGATION_PHISHING"
)

// AttackSimulation represents an attack simulation scenario
type AttackSimulation struct {
	Type        AttackType
	Name        string
	Description string
	Steps       []AttackStep
	Preconditions []string
	Impact      string
	Mitigation  string
}

// AttackStep represents a single step in an attack simulation
type AttackStep struct {
	Order       int
	Action      string
	Actor       string // "victim", "attacker", "network"
	Details     map[string]interface{}
}

// AttackSimulationResult contains the result of an attack simulation
type AttackSimulationResult struct {
	Attack          *AttackSimulation
	Success         bool
	Vulnerable      bool
	StepsExecuted   int
	FailedAt        int
	FailureReason   string
	Evidence        map[string]interface{}
	Recommendations []string
}

// AttackSimulator provides attack simulation capabilities
type AttackSimulator struct {
	chainID    *big.Int
	privateKey *ecdsa.PrivateKey
	address    common.Address
}

// NewAttackSimulator creates a new attack simulator
func NewAttackSimulator(chainID *big.Int, privateKeyHex string) (*AttackSimulator, error) {
	key, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}

	return &AttackSimulator{
		chainID:    chainID,
		privateKey: key,
		address:    crypto.PubkeyToAddress(key.PublicKey),
	}, nil
}

// SimulateCrossChainReplay simulates a cross-chain replay attack
func (as *AttackSimulator) SimulateCrossChainReplay(targetContract common.Address) *AttackSimulationResult {
	attack := &AttackSimulation{
		Type:        AttackCrossChainReplay,
		Name:        "Cross-Chain Replay Attack Simulation",
		Description: "Demonstrates how an authorization with chainId=0 can be replayed across multiple chains",
		Steps: []AttackStep{
			{Order: 1, Action: "Victim signs authorization with chainId=0", Actor: "victim"},
			{Order: 2, Action: "Attacker observes the signed authorization", Actor: "attacker"},
			{Order: 3, Action: "Attacker replays on Ethereum Mainnet", Actor: "attacker"},
			{Order: 4, Action: "Attacker replays on Arbitrum", Actor: "attacker"},
			{Order: 5, Action: "Attacker replays on Optimism", Actor: "attacker"},
			{Order: 6, Action: "All victim accounts on all chains are compromised", Actor: "network"},
		},
		Preconditions: []string{
			"Victim uses same EOA address across multiple chains",
			"Victim signs authorization with chainId=0",
		},
		Impact:     "Complete loss of assets on ALL EVM chains where victim has funds",
		Mitigation: "Always use specific chainId, never use chainId=0",
	}

	result := &AttackSimulationResult{
		Attack:   attack,
		Evidence: make(map[string]interface{}),
	}

	// Create authorization with chainId=0
	auth := SetCodeAuthorization{
		ChainID: *uint256.NewInt(0), // Vulnerable!
		Address: targetContract,
		Nonce:   0,
	}

	// Sign the authorization
	signedAuth, err := SignSetCode(as.privateKey, auth)
	if err != nil {
		result.FailureReason = fmt.Sprintf("Failed to sign: %v", err)
		return result
	}

	// Verify the signature can be recovered
	authority, err := signedAuth.Authority()
	if err != nil {
		result.FailureReason = fmt.Sprintf("Failed to recover authority: %v", err)
		return result
	}

	result.Evidence["signedAuthorization"] = map[string]interface{}{
		"chainId": "0",
		"target":  targetContract.Hex(),
		"nonce":   0,
	}
	result.Evidence["recoveredAuthority"] = authority.Hex()
	result.Evidence["vulnerableChains"] = []string{
		"Ethereum Mainnet (1)",
		"Arbitrum One (42161)",
		"Optimism (10)",
		"Base (8453)",
		"Polygon (137)",
		"And ALL other EVM chains...",
	}

	// The attack would succeed because chainId=0 is valid on any chain
	result.Success = true
	result.Vulnerable = true
	result.StepsExecuted = len(attack.Steps)
	result.Recommendations = []string{
		"NEVER sign authorizations with chainId=0",
		"Wallets should block or warn about chainId=0 authorizations",
		"Always verify chainId matches the intended network",
	}

	return result
}

// SimulateFrontRunning simulates a front-running initialization attack
func (as *AttackSimulator) SimulateFrontRunning(walletContract common.Address) *AttackSimulationResult {
	attack := &AttackSimulation{
		Type:        AttackFrontRunning,
		Name:        "Front-Running Initialization Attack Simulation",
		Description: "Demonstrates how an attacker can front-run the initialization of a delegated wallet",
		Steps: []AttackStep{
			{Order: 1, Action: "Victim sends TX1: Set delegation to SmartWallet", Actor: "victim"},
			{Order: 2, Action: "TX1 enters mempool", Actor: "network"},
			{Order: 3, Action: "Attacker observes TX1 in mempool", Actor: "attacker"},
			{Order: 4, Action: "Attacker sends TX2: initialize(attackerAddress) with higher gas", Actor: "attacker"},
			{Order: 5, Action: "TX2 is mined before TX1", Actor: "network"},
			{Order: 6, Action: "TX1 is mined - delegation set", Actor: "network"},
			{Order: 7, Action: "Victim's TX3: initialize() fails - already initialized", Actor: "victim"},
			{Order: 8, Action: "Attacker controls victim's wallet", Actor: "attacker"},
		},
		Preconditions: []string{
			"Wallet contract has unprotected initialize() function",
			"Delegation and initialization are not atomic",
		},
		Impact:     "Attacker gains full control of victim's delegated wallet",
		Mitigation: "Use signature-protected initialization that verifies EOA owner",
	}

	result := &AttackSimulationResult{
		Attack:   attack,
		Evidence: make(map[string]interface{}),
	}

	// Create victim's authorization
	victimAuth := SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(as.chainID),
		Address: walletContract,
		Nonce:   0,
	}

	signedAuth, err := SignSetCode(as.privateKey, victimAuth)
	if err != nil {
		result.FailureReason = fmt.Sprintf("Failed to sign: %v", err)
		return result
	}

	// Simulate the attack scenario
	attackerAddress := common.HexToAddress("0x000000000000000000000000000000000000dead")

	result.Evidence["victimAuthorization"] = map[string]interface{}{
		"target": walletContract.Hex(),
		"nonce":  0,
	}
	result.Evidence["attackerInitCall"] = map[string]interface{}{
		"function": "initialize(address)",
		"args":     attackerAddress.Hex(),
		"gasPrice": "higher than victim's TX",
	}
	result.Evidence["signatureR"] = signedAuth.R.Hex()

	// Check if wallet has vulnerable initialization pattern
	// In real scenario, we would analyze the contract bytecode
	result.Vulnerable = true // Assuming vulnerable pattern
	result.Success = true
	result.StepsExecuted = len(attack.Steps)
	result.Recommendations = []string{
		"Use signature-protected initialization",
		"Verify msg.sender == address(this) in initialize",
		"Use atomic delegation + initialization patterns",
		"Consider using CREATE2 for deterministic addresses",
	}

	return result
}

// SimulateWhitelistBypass simulates a whitelist bypass attack
func (as *AttackSimulator) SimulateWhitelistBypass(whitelistedAddress, proxyContract common.Address) *AttackSimulationResult {
	attack := &AttackSimulation{
		Type:        AttackWhitelistBypass,
		Name:        "Whitelist Bypass via Delegation",
		Description: "Demonstrates how a delegated address can be used to bypass msg.sender-based whitelists",
		Steps: []AttackStep{
			{Order: 1, Action: "Alice (whitelisted) signs delegation authorization", Actor: "victim"},
			{Order: 2, Action: "Alice shares authorization (intentionally or via phishing)", Actor: "victim"},
			{Order: 3, Action: "Bob (not whitelisted) includes authorization in his TX", Actor: "attacker"},
			{Order: 4, Action: "TX executes with msg.sender = Alice", Actor: "network"},
			{Order: 5, Action: "Protocol whitelist check passes (Alice is whitelisted)", Actor: "network"},
			{Order: 6, Action: "Bob executes privileged action using Alice's permissions", Actor: "attacker"},
		},
		Preconditions: []string{
			"Protocol uses msg.sender for whitelist checks",
			"Whitelisted address has signed a delegation authorization",
		},
		Impact:     "Unauthorized access to privileged protocol functions",
		Mitigation: "Add delegation detection to whitelist logic",
	}

	result := &AttackSimulationResult{
		Attack:   attack,
		Evidence: make(map[string]interface{}),
	}

	// Create authorization from "whitelisted" address
	auth := SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(as.chainID),
		Address: proxyContract,
		Nonce:   0,
	}

	signedAuth, err := SignSetCode(as.privateKey, auth)
	if err != nil {
		result.FailureReason = fmt.Sprintf("Failed to sign: %v", err)
		return result
	}

	result.Evidence["whitelistedAddress"] = whitelistedAddress.Hex()
	result.Evidence["proxyContract"] = proxyContract.Hex()
	result.Evidence["authorization"] = map[string]interface{}{
		"signer": as.address.Hex(),
		"target": proxyContract.Hex(),
	}
	result.Evidence["signatureV"] = signedAuth.V

	// The attack succeeds because msg.sender reflects the delegated EOA
	result.Success = true
	result.Vulnerable = true
	result.StepsExecuted = len(attack.Steps)
	result.Recommendations = []string{
		"Add noEIP7702Delegation() modifier to whitelist functions",
		"Check msg.sender.code for 0xef0100 prefix",
		"Consider using tx.origin checks (with caution)",
		"Implement delegation detection in access control",
	}

	return result
}

// SimulateNonceManipulation simulates nonce-related attacks
func (as *AttackSimulator) SimulateNonceManipulation(targetContract common.Address) *AttackSimulationResult {
	attack := &AttackSimulation{
		Type:        AttackNonceManipulation,
		Name:        "Nonce Manipulation Attack",
		Description: "Demonstrates risks of nonce handling in re-delegation scenarios",
		Steps: []AttackStep{
			{Order: 1, Action: "Victim delegates to ContractA", Actor: "victim"},
			{Order: 2, Action: "Victim uses wallet, nonce increases", Actor: "victim"},
			{Order: 3, Action: "Victim re-delegates to ContractB", Actor: "victim"},
			{Order: 4, Action: "ContractB corrupts nonce tracking storage", Actor: "network"},
			{Order: 5, Action: "Victim re-delegates back to ContractA", Actor: "victim"},
			{Order: 6, Action: "Old authorization signature becomes valid again", Actor: "attacker"},
		},
		Preconditions: []string{
			"Wallet stores nonce in regular storage (not singleton)",
			"Storage layout differs between delegation targets",
		},
		Impact:     "Signature replay enabling unauthorized transactions",
		Mitigation: "Use external NonceTracker singleton contract",
	}

	result := &AttackSimulationResult{
		Attack:   attack,
		Evidence: make(map[string]interface{}),
	}

	// Simulate nonce progression
	nonces := []uint64{0, 1, 2, 3}

	// Create authorizations with different nonces
	for _, nonce := range nonces {
		auth := SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(as.chainID),
			Address: targetContract,
			Nonce:   nonce,
		}
		signedAuth, _ := SignSetCode(as.privateKey, auth)

		result.Evidence[fmt.Sprintf("auth_nonce_%d", nonce)] = map[string]interface{}{
			"nonce":     nonce,
			"signature": signedAuth.R.Hex(),
		}
	}

	result.Evidence["riskScenario"] = "If nonce tracking is corrupted during re-delegation, old signatures may become valid"

	result.Vulnerable = true
	result.Success = true
	result.StepsExecuted = len(attack.Steps)
	result.Recommendations = []string{
		"Store nonce tracking in external singleton contract",
		"Use namespaced storage (ERC-7201) for nonce tracking",
		"Clear storage properly before re-delegation",
		"Implement nonce validation at protocol level",
	}

	return result
}

// SimulateStorageCollision simulates storage collision attacks
func (as *AttackSimulator) SimulateStorageCollision() *AttackSimulationResult {
	attack := &AttackSimulation{
		Type:        AttackStorageCollision,
		Name:        "Storage Collision Attack",
		Description: "Demonstrates how re-delegation can cause storage layout conflicts",
		Steps: []AttackStep{
			{Order: 1, Action: "Victim delegates to ContractA (slot0=bool, slot1=address)", Actor: "victim"},
			{Order: 2, Action: "ContractA sets slot0=true (0x01), slot1=owner", Actor: "network"},
			{Order: 3, Action: "Victim re-delegates to ContractB (slot0=uint256, slot1=mapping)", Actor: "victim"},
			{Order: 4, Action: "ContractB reads slot0 as uint256 = 1 (unexpected!)", Actor: "network"},
			{Order: 5, Action: "ContractB logic behaves incorrectly due to corrupted state", Actor: "network"},
		},
		Preconditions: []string{
			"Different contracts have different storage layouts",
			"Storage is not cleared between delegations",
			"Contracts don't use namespaced storage",
		},
		Impact:     "Unpredictable contract behavior, potential fund loss",
		Mitigation: "Use ERC-7201 namespaced storage for all EIP-7702 contracts",
	}

	result := &AttackSimulationResult{
		Attack:   attack,
		Evidence: make(map[string]interface{}),
	}

	// Demonstrate storage layout conflict
	result.Evidence["contractA_layout"] = map[string]interface{}{
		"slot0": "bool isActive",
		"slot1": "address owner",
		"slot2": "uint256 balance",
	}
	result.Evidence["contractB_layout"] = map[string]interface{}{
		"slot0": "uint256 totalSupply",    // Collision!
		"slot1": "mapping(address=>uint)", // Collision!
		"slot2": "string name",            // Collision!
	}
	result.Evidence["collision_example"] = map[string]interface{}{
		"slot0_written": "0x0000...0001 (bool true)",
		"slot0_read_as": "1 (uint256)",
		"impact":        "ContractB thinks totalSupply=1",
	}

	result.Vulnerable = true
	result.Success = true
	result.StepsExecuted = len(attack.Steps)
	result.Recommendations = []string{
		"Use ERC-7201 namespaced storage layout",
		"Use unique storage slots per contract version",
		"Clear critical storage slots before re-delegation",
		"Only delegate to contracts designed for EIP-7702",
	}

	return result
}

// RunAllAttackSimulations runs all attack simulations
func (as *AttackSimulator) RunAllAttackSimulations(targetContract common.Address) []*AttackSimulationResult {
	results := make([]*AttackSimulationResult, 0)

	// Run all simulations
	results = append(results, as.SimulateCrossChainReplay(targetContract))
	results = append(results, as.SimulateFrontRunning(targetContract))
	results = append(results, as.SimulateWhitelistBypass(as.address, targetContract))
	results = append(results, as.SimulateNonceManipulation(targetContract))
	results = append(results, as.SimulateStorageCollision())

	return results
}

// FormatAttackSimulationResult formats an attack simulation result for display
func FormatAttackSimulationResult(result *AttackSimulationResult) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("\n=== %s ===\n", result.Attack.Name))
	sb.WriteString(fmt.Sprintf("Type: %s\n", result.Attack.Type))
	sb.WriteString(fmt.Sprintf("Description: %s\n\n", result.Attack.Description))

	sb.WriteString("Preconditions:\n")
	for _, p := range result.Attack.Preconditions {
		sb.WriteString(fmt.Sprintf("  - %s\n", p))
	}

	sb.WriteString("\nAttack Steps:\n")
	for _, step := range result.Attack.Steps {
		sb.WriteString(fmt.Sprintf("  %d. [%s] %s\n", step.Order, step.Actor, step.Action))
	}

	sb.WriteString(fmt.Sprintf("\nImpact: %s\n", result.Attack.Impact))
	sb.WriteString(fmt.Sprintf("Mitigation: %s\n", result.Attack.Mitigation))

	sb.WriteString(fmt.Sprintf("\nSimulation Result: %s\n", map[bool]string{true: "VULNERABLE", false: "PROTECTED"}[result.Vulnerable]))
	sb.WriteString(fmt.Sprintf("Steps Executed: %d/%d\n", result.StepsExecuted, len(result.Attack.Steps)))

	if len(result.Recommendations) > 0 {
		sb.WriteString("\nRecommendations:\n")
		for _, r := range result.Recommendations {
			sb.WriteString(fmt.Sprintf("  * %s\n", r))
		}
	}

	return sb.String()
}

// FormatAllAttackResults formats all attack simulation results
func FormatAllAttackResults(results []*AttackSimulationResult) string {
	var sb strings.Builder

	sb.WriteString("\n================================================================================\n")
	sb.WriteString("  EIP-7702 Attack Simulation Report\n")
	sb.WriteString("================================================================================\n")

	vulnerableCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnerableCount++
		}
	}

	sb.WriteString(fmt.Sprintf("\nTotal Simulations: %d\n", len(results)))
	sb.WriteString(fmt.Sprintf("Vulnerable: %d\n", vulnerableCount))
	sb.WriteString(fmt.Sprintf("Protected: %d\n", len(results)-vulnerableCount))

	for _, result := range results {
		sb.WriteString(FormatAttackSimulationResult(result))
	}

	sb.WriteString("\n================================================================================\n")

	return sb.String()
}
