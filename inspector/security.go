// Package inspector provides EIP-7702 security analysis and vulnerability detection.
package inspector

import (
	"bytes"
	"fmt"
	"math/big"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// SecurityRisk represents a security risk level
type SecurityRisk string

const (
	RiskCritical SecurityRisk = "CRITICAL"
	RiskHigh     SecurityRisk = "HIGH"
	RiskMedium   SecurityRisk = "MEDIUM"
	RiskLow      SecurityRisk = "LOW"
	RiskInfo     SecurityRisk = "INFO"
)

// VulnerabilityType represents the type of vulnerability
type VulnerabilityType string

const (
	VulnPhishing             VulnerabilityType = "PHISHING_DELEGATION"
	VulnCrossChainReplay     VulnerabilityType = "CROSS_CHAIN_REPLAY"
	VulnFrontRunning         VulnerabilityType = "FRONT_RUNNING_INIT"
	VulnStorageCollision     VulnerabilityType = "STORAGE_COLLISION"
	VulnWhitelistBypass      VulnerabilityType = "WHITELIST_BYPASS"
	VulnMsgSenderAssumption  VulnerabilityType = "MSG_SENDER_ASSUMPTION"
	VulnMaliciousContract    VulnerabilityType = "MALICIOUS_CONTRACT"
	VulnUnauditedContract    VulnerabilityType = "UNAUDITED_CONTRACT"
	VulnSuspiciousPattern    VulnerabilityType = "SUSPICIOUS_PATTERN"
)

// SecurityFinding represents a security finding
type SecurityFinding struct {
	Type        VulnerabilityType
	Risk        SecurityRisk
	Title       string
	Description string
	Location    string
	Mitigation  string
	Details     map[string]interface{}
}

// SecurityAnalysisResult contains the result of security analysis
type SecurityAnalysisResult struct {
	Address          common.Address
	IsDelegated      bool
	DelegationTarget *common.Address
	Findings         []SecurityFinding
	RiskScore        float64
	HighestRisk      SecurityRisk
	Recommendations  []string
	Details          map[string]interface{}
}

// AuthorizationSecurityCheck contains security check results for an authorization
type AuthorizationSecurityCheck struct {
	Authorization     *SetCodeAuthorization
	Findings          []SecurityFinding
	IsSafe            bool
	Warnings          []string
	BlockRecommended  bool
}

// KnownMaliciousContracts contains addresses of known malicious contracts
// In production, this should be loaded from an external database
var KnownMaliciousContracts = map[common.Address]string{
	// Example entries - in production, load from external source
	common.HexToAddress("0x0000000000000000000000000000000000000bad"): "Known sweeper contract",
}

// AuditedContracts contains addresses of audited and trusted contracts
var AuditedContracts = map[common.Address]string{
	// Example entries - in production, load from external source
	common.HexToAddress("0x0000000000000000000000000000000000000042"): "Example trusted contract",
}

// SuspiciousPatterns contains bytecode patterns that indicate malicious intent
var SuspiciousPatterns = []struct {
	Pattern     []byte
	Description string
}{
	// selfdestruct opcode
	{[]byte{0xff}, "Contains SELFDESTRUCT opcode"},
	// delegatecall to unknown
	{[]byte{0xf4}, "Contains DELEGATECALL opcode"},
}

// SecurityAnalyzer provides security analysis for EIP-7702
type SecurityAnalyzer struct {
	knownMalicious map[common.Address]string
	auditedContracts map[common.Address]string
	networkTester  *NetworkTester
}

// NewSecurityAnalyzer creates a new security analyzer
func NewSecurityAnalyzer() *SecurityAnalyzer {
	return &SecurityAnalyzer{
		knownMalicious:   KnownMaliciousContracts,
		auditedContracts: AuditedContracts,
	}
}

// NewSecurityAnalyzerWithNetwork creates a security analyzer with network capabilities
func NewSecurityAnalyzerWithNetwork(rpcURL, privateKeyHex string) (*SecurityAnalyzer, error) {
	tester, err := NewNetworkTester(rpcURL, privateKeyHex)
	if err != nil {
		return nil, err
	}

	return &SecurityAnalyzer{
		knownMalicious:   KnownMaliciousContracts,
		auditedContracts: AuditedContracts,
		networkTester:    tester,
	}, nil
}

// AnalyzeAddress analyzes an address for EIP-7702 security risks
func (sa *SecurityAnalyzer) AnalyzeAddress(addr common.Address, code []byte) *SecurityAnalysisResult {
	result := &SecurityAnalysisResult{
		Address:  addr,
		Findings: make([]SecurityFinding, 0),
		Details:  make(map[string]interface{}),
	}

	// Check if delegated
	if IsDelegation(code) {
		result.IsDelegated = true
		target, _ := ParseDelegation(code)
		result.DelegationTarget = &target

		// Check for known malicious
		sa.checkMaliciousTarget(result, target)

		// Check for unaudited
		sa.checkUnauditedTarget(result, target)
	}

	// Calculate risk score
	sa.calculateRiskScore(result)

	// Generate recommendations
	sa.generateRecommendations(result)

	return result
}

// AnalyzeAuthorization analyzes an authorization for security risks
func (sa *SecurityAnalyzer) AnalyzeAuthorization(auth *SetCodeAuthorization, currentChainID *big.Int) *AuthorizationSecurityCheck {
	check := &AuthorizationSecurityCheck{
		Authorization: auth,
		Findings:      make([]SecurityFinding, 0),
		Warnings:      make([]string, 0),
		IsSafe:        true,
	}

	// Check 1: Cross-chain replay risk (chainId = 0)
	if auth.ChainID.IsZero() {
		check.Findings = append(check.Findings, SecurityFinding{
			Type:        VulnCrossChainReplay,
			Risk:        RiskCritical,
			Title:       "Cross-Chain Replay Attack Risk",
			Description: "Authorization with chainId=0 can be replayed on ANY EVM chain",
			Mitigation:  "Use specific chainId matching the target network",
			Details: map[string]interface{}{
				"chainId":      "0",
				"affectedChains": "ALL EVM chains",
			},
		})
		check.IsSafe = false
		check.BlockRecommended = true
		check.Warnings = append(check.Warnings, "CRITICAL: This authorization can be used on any blockchain!")
	}

	// Check 2: Chain ID mismatch
	if currentChainID != nil && !auth.ChainID.IsZero() {
		if auth.ChainID.ToBig().Cmp(currentChainID) != 0 {
			check.Findings = append(check.Findings, SecurityFinding{
				Type:        VulnSuspiciousPattern,
				Risk:        RiskHigh,
				Title:       "Chain ID Mismatch",
				Description: "Authorization chainId does not match current network",
				Mitigation:  "Verify the target network before signing",
				Details: map[string]interface{}{
					"authChainId":    auth.ChainID.ToBig().String(),
					"currentChainId": currentChainID.String(),
				},
			})
			check.Warnings = append(check.Warnings, "Authorization is for a different network")
		}
	}

	// Check 3: Known malicious target
	if reason, isMalicious := sa.knownMalicious[auth.Address]; isMalicious {
		check.Findings = append(check.Findings, SecurityFinding{
			Type:        VulnMaliciousContract,
			Risk:        RiskCritical,
			Title:       "Known Malicious Contract",
			Description: fmt.Sprintf("Target contract is flagged as malicious: %s", reason),
			Mitigation:  "Do not sign this authorization",
			Details: map[string]interface{}{
				"target": auth.Address.Hex(),
				"reason": reason,
			},
		})
		check.IsSafe = false
		check.BlockRecommended = true
	}

	// Check 4: Unaudited target
	if _, isAudited := sa.auditedContracts[auth.Address]; !isAudited {
		check.Findings = append(check.Findings, SecurityFinding{
			Type:        VulnUnauditedContract,
			Risk:        RiskMedium,
			Title:       "Unaudited Contract",
			Description: "Target contract is not in the list of audited contracts",
			Mitigation:  "Only delegate to audited and trusted contracts",
			Details: map[string]interface{}{
				"target": auth.Address.Hex(),
			},
		})
		check.Warnings = append(check.Warnings, "Target contract has not been verified as safe")
	}

	// Check 5: Zero address delegation (revocation)
	if auth.Address == (common.Address{}) {
		check.Findings = append(check.Findings, SecurityFinding{
			Type:        VulnSuspiciousPattern,
			Risk:        RiskInfo,
			Title:       "Delegation Revocation",
			Description: "This authorization will remove any existing delegation",
			Mitigation:  "Ensure this is intentional",
			Details: map[string]interface{}{
				"action": "revoke_delegation",
			},
		})
	}

	return check
}

// AnalyzeDelegationCode analyzes bytecode for suspicious patterns
func (sa *SecurityAnalyzer) AnalyzeDelegationCode(code []byte) []SecurityFinding {
	findings := make([]SecurityFinding, 0)

	if !IsDelegation(code) {
		return findings
	}

	target, _ := ParseDelegation(code)

	// Check known malicious
	if reason, isMalicious := sa.knownMalicious[target]; isMalicious {
		findings = append(findings, SecurityFinding{
			Type:        VulnMaliciousContract,
			Risk:        RiskCritical,
			Title:       "Delegation to Known Malicious Contract",
			Description: reason,
			Location:    target.Hex(),
			Mitigation:  "Immediately revoke delegation by setting to zero address",
		})
	}

	return findings
}

// AnalyzeContractCode analyzes contract bytecode for suspicious patterns
func (sa *SecurityAnalyzer) AnalyzeContractCode(code []byte) []SecurityFinding {
	findings := make([]SecurityFinding, 0)

	for _, pattern := range SuspiciousPatterns {
		if bytes.Contains(code, pattern.Pattern) {
			findings = append(findings, SecurityFinding{
				Type:        VulnSuspiciousPattern,
				Risk:        RiskMedium,
				Title:       "Suspicious Bytecode Pattern",
				Description: pattern.Description,
				Mitigation:  "Review contract source code for malicious behavior",
			})
		}
	}

	// Check for common sweeper patterns
	// Function selector for transfer(address,uint256): 0xa9059cbb
	transferSelector := []byte{0xa9, 0x05, 0x9c, 0xbb}
	transferCount := bytes.Count(code, transferSelector)
	if transferCount > 5 {
		findings = append(findings, SecurityFinding{
			Type:        VulnSuspiciousPattern,
			Risk:        RiskHigh,
			Title:       "Potential Sweeper Contract",
			Description: fmt.Sprintf("Contract contains %d transfer function calls", transferCount),
			Mitigation:  "This could be a sweeper contract designed to drain tokens",
		})
	}

	return findings
}

// CheckWhitelistBypassRisk checks if an address could be used for whitelist bypass
func (sa *SecurityAnalyzer) CheckWhitelistBypassRisk(code []byte) *SecurityFinding {
	if !IsDelegation(code) {
		return nil
	}

	return &SecurityFinding{
		Type:        VulnWhitelistBypass,
		Risk:        RiskMedium,
		Title:       "Potential Whitelist Bypass Risk",
		Description: "This address has delegation set, which could be used to bypass whitelist checks in protocols that use msg.sender for access control",
		Mitigation:  "Protocols should add delegation detection to their whitelist logic",
		Details: map[string]interface{}{
			"hasDelegation": true,
		},
	}
}

// ValidateStorageLayout validates storage layout compatibility between contracts
func (sa *SecurityAnalyzer) ValidateStorageLayout(currentLayout, newLayout map[uint64]string) []SecurityFinding {
	findings := make([]SecurityFinding, 0)

	for slot, currentType := range currentLayout {
		if newType, exists := newLayout[slot]; exists && currentType != newType {
			findings = append(findings, SecurityFinding{
				Type:        VulnStorageCollision,
				Risk:        RiskHigh,
				Title:       "Storage Slot Collision",
				Description: fmt.Sprintf("Storage slot %d has incompatible types: %s vs %s", slot, currentType, newType),
				Mitigation:  "Use ERC-7201 namespaced storage to prevent collisions",
				Details: map[string]interface{}{
					"slot":        slot,
					"currentType": currentType,
					"newType":     newType,
				},
			})
		}
	}

	return findings
}

// checkMaliciousTarget checks if delegation target is known malicious
func (sa *SecurityAnalyzer) checkMaliciousTarget(result *SecurityAnalysisResult, target common.Address) {
	if reason, isMalicious := sa.knownMalicious[target]; isMalicious {
		result.Findings = append(result.Findings, SecurityFinding{
			Type:        VulnMaliciousContract,
			Risk:        RiskCritical,
			Title:       "Delegation to Known Malicious Contract",
			Description: reason,
			Location:    target.Hex(),
			Mitigation:  "Immediately revoke delegation",
		})
	}
}

// checkUnauditedTarget checks if delegation target is unaudited
func (sa *SecurityAnalyzer) checkUnauditedTarget(result *SecurityAnalysisResult, target common.Address) {
	if _, isAudited := sa.auditedContracts[target]; !isAudited {
		result.Findings = append(result.Findings, SecurityFinding{
			Type:        VulnUnauditedContract,
			Risk:        RiskMedium,
			Title:       "Delegation to Unaudited Contract",
			Description: "The delegation target has not been audited",
			Location:    target.Hex(),
			Mitigation:  "Only delegate to audited and trusted contracts",
		})
	}
}

// calculateRiskScore calculates overall risk score
func (sa *SecurityAnalyzer) calculateRiskScore(result *SecurityAnalysisResult) {
	score := 0.0
	highest := RiskInfo

	riskWeights := map[SecurityRisk]float64{
		RiskCritical: 1.0,
		RiskHigh:     0.7,
		RiskMedium:   0.4,
		RiskLow:      0.2,
		RiskInfo:     0.0,
	}

	riskOrder := map[SecurityRisk]int{
		RiskCritical: 4,
		RiskHigh:     3,
		RiskMedium:   2,
		RiskLow:      1,
		RiskInfo:     0,
	}

	for _, finding := range result.Findings {
		score += riskWeights[finding.Risk]
		if riskOrder[finding.Risk] > riskOrder[highest] {
			highest = finding.Risk
		}
	}

	// Normalize score (0-10)
	if len(result.Findings) > 0 {
		score = (score / float64(len(result.Findings))) * 10
	}

	result.RiskScore = score
	result.HighestRisk = highest
}

// generateRecommendations generates security recommendations
func (sa *SecurityAnalyzer) generateRecommendations(result *SecurityAnalysisResult) {
	result.Recommendations = make([]string, 0)

	hasCritical := false
	hasHigh := false

	for _, finding := range result.Findings {
		if finding.Risk == RiskCritical {
			hasCritical = true
		}
		if finding.Risk == RiskHigh {
			hasHigh = true
		}
	}

	if hasCritical {
		result.Recommendations = append(result.Recommendations,
			"URGENT: Critical security issues detected. Immediate action required.",
			"Consider revoking delegation by setting to zero address.",
			"Do not send any funds to this address until issues are resolved.",
		)
	}

	if hasHigh {
		result.Recommendations = append(result.Recommendations,
			"High-risk issues detected. Review and address before proceeding.",
			"Verify the delegation target contract is legitimate.",
		)
	}

	if result.IsDelegated {
		result.Recommendations = append(result.Recommendations,
			"Monitor this address for suspicious activity.",
			"Consider using a separate wallet for high-value assets.",
		)
	}
}

// CreateAuthorizationHash creates the hash used for signing an authorization
func CreateAuthorizationHash(chainID *big.Int, target common.Address, nonce uint64) common.Hash {
	// This replicates the EIP-7702 signing hash calculation
	auth := SetCodeAuthorization{
		Address: target,
		Nonce:   nonce,
	}
	if chainID != nil {
		auth.ChainID = *uint256.MustFromBig(chainID)
	}
	return auth.SigHash()
}

// VerifyAuthorizationSignature verifies an authorization signature
func VerifyAuthorizationSignature(auth *SetCodeAuthorization) (common.Address, error) {
	return auth.Authority()
}

// FormatSecurityReport formats a security analysis result for display
func FormatSecurityReport(result *SecurityAnalysisResult) string {
	var sb strings.Builder

	sb.WriteString("\n================================================================================\n")
	sb.WriteString("  EIP-7702 Security Analysis Report\n")
	sb.WriteString("================================================================================\n\n")

	sb.WriteString(fmt.Sprintf("Address: %s\n", result.Address.Hex()))
	sb.WriteString(fmt.Sprintf("Is Delegated: %v\n", result.IsDelegated))
	if result.DelegationTarget != nil {
		sb.WriteString(fmt.Sprintf("Delegation Target: %s\n", result.DelegationTarget.Hex()))
	}
	sb.WriteString(fmt.Sprintf("Risk Score: %.1f/10\n", result.RiskScore))
	sb.WriteString(fmt.Sprintf("Highest Risk: %s\n", result.HighestRisk))

	if len(result.Findings) > 0 {
		sb.WriteString("\n--- Findings ---\n\n")
		for i, finding := range result.Findings {
			sb.WriteString(fmt.Sprintf("[%d] [%s] %s\n", i+1, finding.Risk, finding.Title))
			sb.WriteString(fmt.Sprintf("    Type: %s\n", finding.Type))
			sb.WriteString(fmt.Sprintf("    Description: %s\n", finding.Description))
			if finding.Location != "" {
				sb.WriteString(fmt.Sprintf("    Location: %s\n", finding.Location))
			}
			sb.WriteString(fmt.Sprintf("    Mitigation: %s\n", finding.Mitigation))
			sb.WriteString("\n")
		}
	}

	if len(result.Recommendations) > 0 {
		sb.WriteString("--- Recommendations ---\n\n")
		for _, rec := range result.Recommendations {
			sb.WriteString(fmt.Sprintf("  - %s\n", rec))
		}
	}

	sb.WriteString("\n================================================================================\n")

	return sb.String()
}

// FormatAuthorizationCheck formats an authorization check result for display
func FormatAuthorizationCheck(check *AuthorizationSecurityCheck) string {
	var sb strings.Builder

	sb.WriteString("\n--- Authorization Security Check ---\n\n")

	if check.Authorization != nil {
		sb.WriteString(fmt.Sprintf("Target: %s\n", check.Authorization.Address.Hex()))
		sb.WriteString(fmt.Sprintf("ChainID: %s\n", check.Authorization.ChainID.ToBig().String()))
		sb.WriteString(fmt.Sprintf("Nonce: %d\n", check.Authorization.Nonce))
	}

	sb.WriteString(fmt.Sprintf("Is Safe: %v\n", check.IsSafe))
	sb.WriteString(fmt.Sprintf("Block Recommended: %v\n", check.BlockRecommended))

	if len(check.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range check.Warnings {
			sb.WriteString(fmt.Sprintf("  ! %s\n", w))
		}
	}

	if len(check.Findings) > 0 {
		sb.WriteString("\nFindings:\n")
		for _, f := range check.Findings {
			sb.WriteString(fmt.Sprintf("  [%s] %s\n", f.Risk, f.Title))
		}
	}

	return sb.String()
}

