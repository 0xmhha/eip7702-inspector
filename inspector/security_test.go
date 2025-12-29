package inspector

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

func TestSecurityAnalyzer_AnalyzeAddress(t *testing.T) {
	analyzer := NewSecurityAnalyzer()

	t.Run("non-delegated address", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		code := []byte{} // Empty code

		result := analyzer.AnalyzeAddress(addr, code)

		if result.IsDelegated {
			t.Error("Expected non-delegated address")
		}
		if result.DelegationTarget != nil {
			t.Error("Expected nil delegation target")
		}
	})

	t.Run("delegated address", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		target := common.HexToAddress("0x0000000000000000000000000000000000000042")
		code := AddressToDelegation(target)

		result := analyzer.AnalyzeAddress(addr, code)

		if !result.IsDelegated {
			t.Error("Expected delegated address")
		}
		if result.DelegationTarget == nil {
			t.Fatal("Expected delegation target")
		}
		if *result.DelegationTarget != target {
			t.Errorf("Expected target %s, got %s", target.Hex(), result.DelegationTarget.Hex())
		}
	})

	t.Run("delegation to known malicious", func(t *testing.T) {
		addr := common.HexToAddress("0x1234567890123456789012345678901234567890")
		malicious := common.HexToAddress("0x0000000000000000000000000000000000000bad")
		code := AddressToDelegation(malicious)

		result := analyzer.AnalyzeAddress(addr, code)

		hasCriticalFinding := false
		for _, f := range result.Findings {
			if f.Risk == RiskCritical && f.Type == VulnMaliciousContract {
				hasCriticalFinding = true
				break
			}
		}

		if !hasCriticalFinding {
			t.Error("Expected critical finding for malicious contract")
		}
	})
}

func TestSecurityAnalyzer_AnalyzeAuthorization(t *testing.T) {
	analyzer := NewSecurityAnalyzer()
	chainID := big.NewInt(1)

	t.Run("chainId zero - cross-chain replay risk", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.NewInt(0),
			Address: common.HexToAddress("0x0000000000000000000000000000000000000042"),
			Nonce:   0,
		}

		check := analyzer.AnalyzeAuthorization(auth, chainID)

		if check.IsSafe {
			t.Error("Expected unsafe authorization")
		}
		if !check.BlockRecommended {
			t.Error("Expected block recommendation")
		}

		hasCrossChainFinding := false
		for _, f := range check.Findings {
			if f.Type == VulnCrossChainReplay {
				hasCrossChainFinding = true
				break
			}
		}
		if !hasCrossChainFinding {
			t.Error("Expected cross-chain replay finding")
		}
	})

	t.Run("specific chainId - safe", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: common.HexToAddress("0x0000000000000000000000000000000000000042"),
			Nonce:   0,
		}

		check := analyzer.AnalyzeAuthorization(auth, chainID)

		// Should not have cross-chain replay finding
		for _, f := range check.Findings {
			if f.Type == VulnCrossChainReplay {
				t.Error("Should not have cross-chain replay finding for specific chainId")
			}
		}
	})

	t.Run("known malicious target", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: common.HexToAddress("0x0000000000000000000000000000000000000bad"),
			Nonce:   0,
		}

		check := analyzer.AnalyzeAuthorization(auth, chainID)

		if check.IsSafe {
			t.Error("Expected unsafe authorization for malicious target")
		}
		if !check.BlockRecommended {
			t.Error("Expected block recommendation for malicious target")
		}
	})

	t.Run("zero address - revocation", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: common.Address{},
			Nonce:   0,
		}

		check := analyzer.AnalyzeAuthorization(auth, chainID)

		hasRevocationInfo := false
		for _, f := range check.Findings {
			if f.Details != nil && f.Details["action"] == "revoke_delegation" {
				hasRevocationInfo = true
				break
			}
		}
		if !hasRevocationInfo {
			t.Error("Expected revocation info in findings")
		}
	})
}

func TestAttackSimulator(t *testing.T) {
	chainID := big.NewInt(1)
	keyHex := TestPrivateKeys[0]
	targetContract := common.HexToAddress("0x0000000000000000000000000000000000000042")

	simulator, err := NewAttackSimulator(chainID, keyHex)
	if err != nil {
		t.Fatalf("Failed to create simulator: %v", err)
	}

	t.Run("cross-chain replay simulation", func(t *testing.T) {
		result := simulator.SimulateCrossChainReplay(targetContract)

		if !result.Vulnerable {
			t.Error("Expected vulnerable result for cross-chain replay")
		}
		if result.Attack.Type != AttackCrossChainReplay {
			t.Errorf("Expected attack type %s, got %s", AttackCrossChainReplay, result.Attack.Type)
		}
		if len(result.Recommendations) == 0 {
			t.Error("Expected recommendations")
		}
	})

	t.Run("front-running simulation", func(t *testing.T) {
		result := simulator.SimulateFrontRunning(targetContract)

		if !result.Vulnerable {
			t.Error("Expected vulnerable result for front-running")
		}
		if result.Attack.Type != AttackFrontRunning {
			t.Errorf("Expected attack type %s, got %s", AttackFrontRunning, result.Attack.Type)
		}
	})

	t.Run("whitelist bypass simulation", func(t *testing.T) {
		whitelistedAddr := common.HexToAddress("0x1111111111111111111111111111111111111111")
		result := simulator.SimulateWhitelistBypass(whitelistedAddr, targetContract)

		if !result.Vulnerable {
			t.Error("Expected vulnerable result for whitelist bypass")
		}
		if result.Attack.Type != AttackWhitelistBypass {
			t.Errorf("Expected attack type %s, got %s", AttackWhitelistBypass, result.Attack.Type)
		}
	})

	t.Run("storage collision simulation", func(t *testing.T) {
		result := simulator.SimulateStorageCollision()

		if !result.Vulnerable {
			t.Error("Expected vulnerable result for storage collision")
		}
		if result.Attack.Type != AttackStorageCollision {
			t.Errorf("Expected attack type %s, got %s", AttackStorageCollision, result.Attack.Type)
		}
	})

	t.Run("run all simulations", func(t *testing.T) {
		results := simulator.RunAllAttackSimulations(targetContract)

		if len(results) != 5 {
			t.Errorf("Expected 5 attack simulations, got %d", len(results))
		}

		// All should be vulnerable in simulation
		for _, r := range results {
			if !r.Vulnerable {
				t.Errorf("Expected vulnerable result for %s", r.Attack.Type)
			}
		}
	})
}

func TestValidator(t *testing.T) {
	chainID := big.NewInt(1)
	validator := NewValidator(chainID)

	// Add trusted contract
	trustedContract := common.HexToAddress("0x0000000000000000000000000000000000000042")
	validator.AddTrustedContract(trustedContract)

	// Add blocked contract
	blockedContract := common.HexToAddress("0x0000000000000000000000000000000000000bad")
	validator.AddBlockedContract(blockedContract, "Known malicious")

	t.Run("validate trusted contract authorization", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: trustedContract,
			Nonce:   0,
		}

		result := validator.ValidateAuthorization(auth)

		if !result.IsValid {
			t.Error("Expected valid authorization")
		}
		if result.ShouldBlock {
			t.Error("Should not block trusted contract")
		}
	})

	t.Run("validate blocked contract authorization", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: blockedContract,
			Nonce:   0,
		}

		result := validator.ValidateAuthorization(auth)

		if !result.ShouldBlock {
			t.Error("Expected block recommendation for blocked contract")
		}
	})

	t.Run("validate untrusted contract authorization", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: common.HexToAddress("0x9999999999999999999999999999999999999999"),
			Nonce:   0,
		}

		result := validator.ValidateAuthorization(auth)

		hasTrustWarning := false
		for _, f := range result.Findings {
			if f.CheckName == "Trusted Contract Check" && !f.Passed {
				hasTrustWarning = true
				break
			}
		}
		if !hasTrustWarning {
			t.Error("Expected trust warning for untrusted contract")
		}
	})

	t.Run("validate chainId zero", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.NewInt(0),
			Address: trustedContract,
			Nonce:   0,
		}

		result := validator.ValidateAuthorization(auth)

		hasChainIdFinding := false
		for _, f := range result.Findings {
			if f.CheckName == "ChainID Zero Check" && !f.Passed {
				hasChainIdFinding = true
				break
			}
		}
		if !hasChainIdFinding {
			t.Error("Expected chainId zero finding")
		}
	})
}

func TestBestPracticeChecker(t *testing.T) {
	bpc := NewBestPracticeChecker()
	chainID := big.NewInt(1)

	t.Run("check chainId zero violation", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.NewInt(0),
			Address: common.HexToAddress("0x0000000000000000000000000000000000000042"),
			Nonce:   0,
		}

		results := bpc.CheckAuthorizationBestPractices(auth)

		hasBP001Violation := false
		for _, r := range results {
			if r.CheckName == "BP001: Use Specific ChainID" && !r.Passed {
				hasBP001Violation = true
				break
			}
		}
		if !hasBP001Violation {
			t.Error("Expected BP001 violation for chainId=0")
		}
	})

	t.Run("check specific chainId compliance", func(t *testing.T) {
		auth := &SetCodeAuthorization{
			ChainID: *uint256.MustFromBig(chainID),
			Address: common.HexToAddress("0x0000000000000000000000000000000000000042"),
			Nonce:   0,
		}

		results := bpc.CheckAuthorizationBestPractices(auth)

		hasBP001Pass := false
		for _, r := range results {
			if r.CheckName == "BP001: Use Specific ChainID" && r.Passed {
				hasBP001Pass = true
				break
			}
		}
		if !hasBP001Pass {
			t.Error("Expected BP001 pass for specific chainId")
		}
	})
}

func TestValidateDelegationCode(t *testing.T) {
	validator := NewValidator(big.NewInt(1))

	t.Run("valid delegation code", func(t *testing.T) {
		target := common.HexToAddress("0x0000000000000000000000000000000000000042")
		code := AddressToDelegation(target)

		results := validator.ValidateDelegationCode(code)

		hasValidResult := false
		for _, r := range results {
			if r.CheckName == "Delegation Format Check" && r.Passed {
				hasValidResult = true
				break
			}
		}
		if !hasValidResult {
			t.Error("Expected valid delegation format check")
		}
	})

	t.Run("invalid delegation code", func(t *testing.T) {
		code := []byte{0x60, 0x80, 0x60, 0x40} // Random bytecode

		results := validator.ValidateDelegationCode(code)

		hasInvalidResult := false
		for _, r := range results {
			if r.CheckName == "Delegation Format Check" && !r.Passed {
				hasInvalidResult = true
				break
			}
		}
		if !hasInvalidResult {
			t.Error("Expected invalid delegation format check")
		}
	})

	t.Run("blocked delegation target", func(t *testing.T) {
		blockedAddr := common.HexToAddress("0x0000000000000000000000000000000000000bad")
		validator.AddBlockedContract(blockedAddr, "Test blocked")
		code := AddressToDelegation(blockedAddr)

		results := validator.ValidateDelegationCode(code)

		hasCriticalFinding := false
		for _, r := range results {
			if r.Severity == RiskCritical {
				hasCriticalFinding = true
				break
			}
		}
		if !hasCriticalFinding {
			t.Error("Expected critical finding for blocked delegation target")
		}
	})
}

func TestSecurityReport(t *testing.T) {
	result := &SecurityAnalysisResult{
		Address:     common.HexToAddress("0x1234567890123456789012345678901234567890"),
		IsDelegated: true,
		RiskScore:   7.5,
		HighestRisk: RiskHigh,
		Findings: []SecurityFinding{
			{
				Type:        VulnUnauditedContract,
				Risk:        RiskHigh,
				Title:       "Test Finding",
				Description: "Test description",
				Mitigation:  "Test mitigation",
			},
		},
		Recommendations: []string{"Test recommendation"},
	}

	target := common.HexToAddress("0x0000000000000000000000000000000000000042")
	result.DelegationTarget = &target

	report := FormatSecurityReport(result)

	// Check report contains expected sections
	if len(report) == 0 {
		t.Error("Expected non-empty report")
	}

	// Check for key elements
	expectedStrings := []string{
		"Security Analysis Report",
		"Address:",
		"Is Delegated: true",
		"Delegation Target:",
		"Risk Score:",
		"Findings",
		"Recommendations",
	}

	for _, expected := range expectedStrings {
		if !containsString(report, expected) {
			t.Errorf("Report missing expected string: %s", expected)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
