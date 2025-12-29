// Package inspector provides EIP-7702 validation and best practice checking.
package inspector

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
)

// ValidationResult represents the result of a validation check
type ValidationResult struct {
	Passed      bool
	CheckName   string
	Category    string
	Description string
	Severity    SecurityRisk
	Details     map[string]interface{}
	Suggestion  string
}

// ContractValidation contains results of contract validation
type ContractValidation struct {
	Address         common.Address
	IsEIP7702Safe   bool
	HasNamespacedStorage bool
	HasProtectedInit     bool
	HasDelegationCheck   bool
	Findings        []ValidationResult
	OverallScore    int // 0-100
}

// AuthorizationValidation contains results of authorization validation
type AuthorizationValidation struct {
	Authorization   *SetCodeAuthorization
	IsValid         bool
	IsSafe          bool
	Findings        []ValidationResult
	ShouldBlock     bool
	BlockReason     string
}

// BestPractice represents a best practice check
type BestPractice struct {
	ID          string
	Name        string
	Description string
	Category    string
	Severity    SecurityRisk
	Check       func(interface{}) bool
}

// Validator provides validation capabilities for EIP-7702
type Validator struct {
	chainID          *big.Int
	trustedContracts map[common.Address]bool
	blockedContracts map[common.Address]string
}

// NewValidator creates a new validator
func NewValidator(chainID *big.Int) *Validator {
	return &Validator{
		chainID:          chainID,
		trustedContracts: make(map[common.Address]bool),
		blockedContracts: make(map[common.Address]string),
	}
}

// AddTrustedContract adds a contract to the trusted list
func (v *Validator) AddTrustedContract(addr common.Address) {
	v.trustedContracts[addr] = true
}

// AddBlockedContract adds a contract to the blocked list
func (v *Validator) AddBlockedContract(addr common.Address, reason string) {
	v.blockedContracts[addr] = reason
}

// ValidateAuthorization validates an EIP-7702 authorization
func (v *Validator) ValidateAuthorization(auth *SetCodeAuthorization) *AuthorizationValidation {
	result := &AuthorizationValidation{
		Authorization: auth,
		IsValid:       true,
		IsSafe:        true,
		Findings:      make([]ValidationResult, 0),
	}

	// Check 1: ChainID validation
	v.checkChainID(auth, result)

	// Check 2: Target contract validation
	v.checkTargetContract(auth, result)

	// Check 3: Nonce validation
	v.checkNonce(auth, result)

	// Check 4: Zero address check
	v.checkZeroAddress(auth, result)

	// Calculate overall safety
	for _, f := range result.Findings {
		if f.Severity == RiskCritical {
			result.IsSafe = false
			result.ShouldBlock = true
			result.BlockReason = f.Description
		} else if f.Severity == RiskHigh && !result.ShouldBlock {
			result.IsSafe = false
		}
	}

	return result
}

// checkChainID validates the chainID field
func (v *Validator) checkChainID(auth *SetCodeAuthorization, result *AuthorizationValidation) {
	// Check for chainId = 0 (cross-chain replay risk)
	if auth.ChainID.IsZero() {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      false,
			CheckName:   "ChainID Zero Check",
			Category:    "Cross-Chain Security",
			Description: "Authorization uses chainId=0 which is valid on ALL chains",
			Severity:    RiskCritical,
			Suggestion:  "Use specific chainId for the target network",
			Details: map[string]interface{}{
				"chainId": "0",
				"risk":    "Cross-chain replay attack",
			},
		})
		return
	}

	// Check for chainId mismatch
	if v.chainID != nil {
		authChainID := auth.ChainID.ToBig()
		if authChainID.Cmp(v.chainID) != 0 {
			result.Findings = append(result.Findings, ValidationResult{
				Passed:      false,
				CheckName:   "ChainID Match Check",
				Category:    "Network Security",
				Description: fmt.Sprintf("Authorization chainId (%s) doesn't match current chain (%s)",
					authChainID.String(), v.chainID.String()),
				Severity:   RiskHigh,
				Suggestion: "Ensure authorization is for the correct network",
				Details: map[string]interface{}{
					"authChainId":    authChainID.String(),
					"currentChainId": v.chainID.String(),
				},
			})
		}
	}

	result.Findings = append(result.Findings, ValidationResult{
		Passed:      true,
		CheckName:   "ChainID Validation",
		Category:    "Cross-Chain Security",
		Description: "ChainID is properly set",
		Severity:    RiskInfo,
	})
}

// checkTargetContract validates the target contract
func (v *Validator) checkTargetContract(auth *SetCodeAuthorization, result *AuthorizationValidation) {
	// Check if blocked
	if reason, blocked := v.blockedContracts[auth.Address]; blocked {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      false,
			CheckName:   "Blocked Contract Check",
			Category:    "Contract Security",
			Description: fmt.Sprintf("Target contract is blocked: %s", reason),
			Severity:    RiskCritical,
			Suggestion:  "Do not delegate to this contract",
			Details: map[string]interface{}{
				"target": auth.Address.Hex(),
				"reason": reason,
			},
		})
		return
	}

	// Check if trusted
	if !v.trustedContracts[auth.Address] {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      false,
			CheckName:   "Trusted Contract Check",
			Category:    "Contract Security",
			Description: "Target contract is not in trusted list",
			Severity:    RiskMedium,
			Suggestion:  "Only delegate to audited and trusted contracts",
			Details: map[string]interface{}{
				"target": auth.Address.Hex(),
			},
		})
	} else {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      true,
			CheckName:   "Trusted Contract Check",
			Category:    "Contract Security",
			Description: "Target contract is trusted",
			Severity:    RiskInfo,
		})
	}
}

// checkNonce validates the nonce
func (v *Validator) checkNonce(auth *SetCodeAuthorization, result *AuthorizationValidation) {
	// Check for extremely high nonce (potential manipulation)
	if auth.Nonce > 1000000 {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      false,
			CheckName:   "Nonce Range Check",
			Category:    "Transaction Security",
			Description: "Unusually high nonce value",
			Severity:    RiskLow,
			Suggestion:  "Verify this is the expected nonce value",
			Details: map[string]interface{}{
				"nonce": auth.Nonce,
			},
		})
	}
}

// checkZeroAddress handles zero address (revocation)
func (v *Validator) checkZeroAddress(auth *SetCodeAuthorization, result *AuthorizationValidation) {
	if auth.Address == (common.Address{}) {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      true,
			CheckName:   "Zero Address Check",
			Category:    "Delegation Control",
			Description: "Authorization will revoke existing delegation",
			Severity:    RiskInfo,
			Suggestion:  "Confirm this is the intended action",
			Details: map[string]interface{}{
				"action": "revoke_delegation",
			},
		})
	}
}

// ValidateDelegationCode validates delegation bytecode
func (v *Validator) ValidateDelegationCode(code []byte) []ValidationResult {
	results := make([]ValidationResult, 0)

	// Check if it's a valid delegation
	if !IsDelegation(code) {
		results = append(results, ValidationResult{
			Passed:      false,
			CheckName:   "Delegation Format Check",
			Category:    "Bytecode Validation",
			Description: "Code is not a valid EIP-7702 delegation",
			Severity:    RiskInfo,
		})
		return results
	}

	target, _ := ParseDelegation(code)

	// Check target validity
	if v.blockedContracts[target] != "" {
		results = append(results, ValidationResult{
			Passed:      false,
			CheckName:   "Delegation Target Check",
			Category:    "Security",
			Description: fmt.Sprintf("Delegation points to blocked contract: %s", v.blockedContracts[target]),
			Severity:    RiskCritical,
			Suggestion:  "Revoke this delegation immediately",
			Details: map[string]interface{}{
				"target": target.Hex(),
			},
		})
	}

	results = append(results, ValidationResult{
		Passed:      true,
		CheckName:   "Delegation Format Check",
		Category:    "Bytecode Validation",
		Description: fmt.Sprintf("Valid delegation to %s", target.Hex()),
		Severity:    RiskInfo,
	})

	return results
}

// ValidateContractForEIP7702 validates a contract's suitability for EIP-7702
func (v *Validator) ValidateContractForEIP7702(code []byte) *ContractValidation {
	result := &ContractValidation{
		Findings: make([]ValidationResult, 0),
	}

	// Check for namespaced storage pattern (ERC-7201)
	// Look for keccak256 computation pattern followed by storage operations
	hasNamespacedStorage := v.detectNamespacedStorage(code)
	result.HasNamespacedStorage = hasNamespacedStorage

	if !hasNamespacedStorage {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      false,
			CheckName:   "Namespaced Storage Check",
			Category:    "Storage Safety",
			Description: "Contract may not use namespaced storage (ERC-7201)",
			Severity:    RiskHigh,
			Suggestion:  "Implement ERC-7201 namespaced storage to prevent collisions",
		})
	}

	// Check for protected initialization
	hasProtectedInit := v.detectProtectedInit(code)
	result.HasProtectedInit = hasProtectedInit

	if !hasProtectedInit {
		result.Findings = append(result.Findings, ValidationResult{
			Passed:      false,
			CheckName:   "Protected Init Check",
			Category:    "Initialization Safety",
			Description: "Contract may have unprotected initialization",
			Severity:    RiskHigh,
			Suggestion:  "Add signature verification to initialization function",
		})
	}

	// Check for delegation detection
	hasDelegationCheck := v.detectDelegationCheck(code)
	result.HasDelegationCheck = hasDelegationCheck

	// Calculate overall score
	score := 100
	for _, f := range result.Findings {
		if !f.Passed {
			switch f.Severity {
			case RiskCritical:
				score -= 40
			case RiskHigh:
				score -= 25
			case RiskMedium:
				score -= 10
			case RiskLow:
				score -= 5
			}
		}
	}
	if score < 0 {
		score = 0
	}
	result.OverallScore = score
	result.IsEIP7702Safe = score >= 70

	return result
}

// detectNamespacedStorage attempts to detect ERC-7201 namespaced storage usage
func (v *Validator) detectNamespacedStorage(code []byte) bool {
	// Look for patterns indicating namespaced storage:
	// - keccak256 hash operations
	// - Specific storage slot patterns
	// This is a heuristic check

	// ERC-7201 typically uses: keccak256("namespace.id") - 1
	// We look for subtraction of 1 after a hash operation
	subOnePattern := []byte{0x60, 0x01, 0x90, 0x03} // PUSH1 0x01, SWAP1, SUB
	return bytes.Contains(code, subOnePattern)
}

// detectProtectedInit attempts to detect protected initialization
func (v *Validator) detectProtectedInit(code []byte) bool {
	// Look for ecrecover usage (signature verification)
	// ecrecover precompile call: STATICCALL to address 0x01
	ecrecoverPattern := []byte{0x60, 0x01} // PUSH1 0x01 (precompile address)

	// Also check for signature length checks (65 bytes = 0x41)
	sigLengthCheck := []byte{0x60, 0x41} // PUSH1 0x41

	return bytes.Contains(code, ecrecoverPattern) && bytes.Contains(code, sigLengthCheck)
}

// detectDelegationCheck attempts to detect EIP-7702 delegation checking
func (v *Validator) detectDelegationCheck(code []byte) bool {
	// Look for 0xef0100 prefix check
	delegationPrefix := []byte{0x63, 0xef, 0x01, 0x00} // PUSH4 with prefix bytes
	return bytes.Contains(code, delegationPrefix)
}

// BestPracticeChecker provides best practice validation
type BestPracticeChecker struct {
	practices []BestPractice
}

// NewBestPracticeChecker creates a new best practice checker
func NewBestPracticeChecker() *BestPracticeChecker {
	return &BestPracticeChecker{
		practices: GetEIP7702BestPractices(),
	}
}

// GetEIP7702BestPractices returns all EIP-7702 best practices
func GetEIP7702BestPractices() []BestPractice {
	return []BestPractice{
		{
			ID:          "BP001",
			Name:        "Use Specific ChainID",
			Description: "Always use specific chainId instead of 0",
			Category:    "Authorization",
			Severity:    RiskCritical,
		},
		{
			ID:          "BP002",
			Name:        "Verify Target Contract",
			Description: "Only delegate to audited and trusted contracts",
			Category:    "Authorization",
			Severity:    RiskHigh,
		},
		{
			ID:          "BP003",
			Name:        "Use Namespaced Storage",
			Description: "Implement ERC-7201 namespaced storage",
			Category:    "Contract Design",
			Severity:    RiskHigh,
		},
		{
			ID:          "BP004",
			Name:        "Protected Initialization",
			Description: "Use signature verification in initialization",
			Category:    "Contract Design",
			Severity:    RiskHigh,
		},
		{
			ID:          "BP005",
			Name:        "Add Delegation Detection",
			Description: "Detect and handle delegated accounts in protocols",
			Category:    "Protocol Integration",
			Severity:    RiskMedium,
		},
		{
			ID:          "BP006",
			Name:        "External Nonce Tracking",
			Description: "Use external singleton for nonce tracking",
			Category:    "Contract Design",
			Severity:    RiskMedium,
		},
		{
			ID:          "BP007",
			Name:        "Clear Storage on Re-delegation",
			Description: "Clear critical storage before re-delegation",
			Category:    "Contract Design",
			Severity:    RiskMedium,
		},
		{
			ID:          "BP008",
			Name:        "Wallet Separation",
			Description: "Use separate wallets for high-value assets",
			Category:    "User Practice",
			Severity:    RiskMedium,
		},
		{
			ID:          "BP009",
			Name:        "Revoke After Use",
			Description: "Revoke delegation when no longer needed",
			Category:    "User Practice",
			Severity:    RiskLow,
		},
		{
			ID:          "BP010",
			Name:        "Monitor Delegations",
			Description: "Regularly monitor for unexpected delegations",
			Category:    "User Practice",
			Severity:    RiskLow,
		},
	}
}

// CheckAuthorizationBestPractices checks authorization against best practices
func (bpc *BestPracticeChecker) CheckAuthorizationBestPractices(auth *SetCodeAuthorization) []ValidationResult {
	results := make([]ValidationResult, 0)

	// BP001: ChainID check
	if auth.ChainID.IsZero() {
		results = append(results, ValidationResult{
			Passed:      false,
			CheckName:   "BP001: Use Specific ChainID",
			Category:    "Best Practice",
			Description: "Authorization uses chainId=0",
			Severity:    RiskCritical,
			Suggestion:  "Use the specific chainId for your target network",
		})
	} else {
		results = append(results, ValidationResult{
			Passed:      true,
			CheckName:   "BP001: Use Specific ChainID",
			Category:    "Best Practice",
			Description: "ChainID is properly specified",
			Severity:    RiskInfo,
		})
	}

	// BP002 would require external contract verification

	return results
}

// FormatValidationResults formats validation results for display
func FormatValidationResults(results []ValidationResult) string {
	var sb strings.Builder

	passed := 0
	failed := 0

	for _, r := range results {
		if r.Passed {
			passed++
		} else {
			failed++
		}
	}

	sb.WriteString("\n--- Validation Results ---\n\n")
	sb.WriteString(fmt.Sprintf("Passed: %d  Failed: %d\n\n", passed, failed))

	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] [%s] %s\n", status, r.Severity, r.CheckName))
		sb.WriteString(fmt.Sprintf("       Category: %s\n", r.Category))
		sb.WriteString(fmt.Sprintf("       %s\n", r.Description))
		if r.Suggestion != "" {
			sb.WriteString(fmt.Sprintf("       Suggestion: %s\n", r.Suggestion))
		}
		sb.WriteString("\n")
	}

	return sb.String()
}

// FormatContractValidation formats contract validation for display
func FormatContractValidation(cv *ContractValidation) string {
	var sb strings.Builder

	sb.WriteString("\n--- Contract EIP-7702 Validation ---\n\n")
	sb.WriteString(fmt.Sprintf("Address: %s\n", cv.Address.Hex()))
	sb.WriteString(fmt.Sprintf("EIP-7702 Safe: %v\n", cv.IsEIP7702Safe))
	sb.WriteString(fmt.Sprintf("Overall Score: %d/100\n\n", cv.OverallScore))

	sb.WriteString("Feature Checks:\n")
	sb.WriteString(fmt.Sprintf("  Namespaced Storage (ERC-7201): %v\n", cv.HasNamespacedStorage))
	sb.WriteString(fmt.Sprintf("  Protected Initialization: %v\n", cv.HasProtectedInit))
	sb.WriteString(fmt.Sprintf("  Delegation Detection: %v\n", cv.HasDelegationCheck))

	if len(cv.Findings) > 0 {
		sb.WriteString("\nFindings:\n")
		sb.WriteString(FormatValidationResults(cv.Findings))
	}

	return sb.String()
}
