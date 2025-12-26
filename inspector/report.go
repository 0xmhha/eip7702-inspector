package inspector

import (
	"fmt"
	"math/big"
	"strings"
)

// InspectionReport contains the complete EIP-7702 inspection report
type InspectionReport struct {
	Title                    string
	ChainID                  *big.Int
	DelegationResults        []DelegationTestResult
	AuthorizationResults     []AuthorizationTestResult
	SetCodeTxResults         []SetCodeTxTestResult
	GasResults               []GasTestResult
	Summary                  ReportSummary
}

// ReportSummary contains summary statistics
type ReportSummary struct {
	TotalTests     int
	PassedTests    int
	FailedTests    int
	PassRate       float64
	DelegationPass bool
	AuthPass       bool
	TxPass         bool
	GasPass        bool
}

// Inspector is the main EIP-7702 inspector
type Inspector struct {
	ChainID    *big.Int
	PrivateKey string
}

// NewInspector creates a new EIP-7702 inspector
func NewInspector(chainID *big.Int, privateKey string) *Inspector {
	return &Inspector{
		ChainID:    chainID,
		PrivateKey: privateKey,
	}
}

// RunFullInspection runs a complete EIP-7702 inspection
func (i *Inspector) RunFullInspection() (*InspectionReport, error) {
	report := &InspectionReport{
		Title:   "EIP-7702 Implementation Inspection Report",
		ChainID: i.ChainID,
	}

	// Run delegation tests
	report.DelegationResults = RunDelegationTests()

	// Run authorization tests
	authResults, err := RunAuthorizationTests(i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("authorization tests failed: %w", err)
	}
	report.AuthorizationResults = authResults

	// Run SetCode transaction tests
	txResults, err := RunSetCodeTxTests(i.ChainID, i.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("SetCode transaction tests failed: %w", err)
	}
	report.SetCodeTxResults = txResults

	// Run gas calculation tests
	report.GasResults = RunGasTests()

	// Calculate summary
	report.Summary = i.calculateSummary(report)

	return report, nil
}

// calculateSummary calculates the report summary
func (i *Inspector) calculateSummary(report *InspectionReport) ReportSummary {
	summary := ReportSummary{}

	// Count delegation tests
	delegationPassed := 0
	for _, r := range report.DelegationResults {
		summary.TotalTests++
		if r.Passed {
			summary.PassedTests++
			delegationPassed++
		} else {
			summary.FailedTests++
		}
	}
	summary.DelegationPass = delegationPassed == len(report.DelegationResults)

	// Count authorization tests
	authPassed := 0
	for _, r := range report.AuthorizationResults {
		summary.TotalTests++
		if r.Passed {
			summary.PassedTests++
			authPassed++
		} else {
			summary.FailedTests++
		}
	}
	summary.AuthPass = authPassed == len(report.AuthorizationResults)

	// Count SetCode transaction tests
	txPassed := 0
	for _, r := range report.SetCodeTxResults {
		summary.TotalTests++
		if r.Passed {
			summary.PassedTests++
			txPassed++
		} else {
			summary.FailedTests++
		}
	}
	summary.TxPass = txPassed == len(report.SetCodeTxResults)

	// Count gas tests
	gasPassed := 0
	for _, r := range report.GasResults {
		summary.TotalTests++
		if r.Passed {
			summary.PassedTests++
			gasPassed++
		} else {
			summary.FailedTests++
		}
	}
	summary.GasPass = gasPassed == len(report.GasResults)

	// Calculate pass rate
	if summary.TotalTests > 0 {
		summary.PassRate = float64(summary.PassedTests) / float64(summary.TotalTests) * 100
	}

	return summary
}

// FormatReport formats the inspection report as a string
func FormatReport(report *InspectionReport) string {
	var sb strings.Builder

	sb.WriteString("=" + strings.Repeat("=", 79) + "\n")
	sb.WriteString(fmt.Sprintf("  %s\n", report.Title))
	sb.WriteString(fmt.Sprintf("  Chain ID: %s\n", report.ChainID.String()))
	sb.WriteString("=" + strings.Repeat("=", 79) + "\n\n")

	// Summary
	sb.WriteString("SUMMARY\n")
	sb.WriteString("-" + strings.Repeat("-", 39) + "\n")
	sb.WriteString(fmt.Sprintf("Total Tests:  %d\n", report.Summary.TotalTests))
	sb.WriteString(fmt.Sprintf("Passed:       %d\n", report.Summary.PassedTests))
	sb.WriteString(fmt.Sprintf("Failed:       %d\n", report.Summary.FailedTests))
	sb.WriteString(fmt.Sprintf("Pass Rate:    %.1f%%\n\n", report.Summary.PassRate))

	// Component status
	sb.WriteString("Component Status:\n")
	sb.WriteString(fmt.Sprintf("  Delegation:      %s\n", statusIcon(report.Summary.DelegationPass)))
	sb.WriteString(fmt.Sprintf("  Authorization:   %s\n", statusIcon(report.Summary.AuthPass)))
	sb.WriteString(fmt.Sprintf("  Transaction:     %s\n", statusIcon(report.Summary.TxPass)))
	sb.WriteString(fmt.Sprintf("  Gas Calculation: %s\n\n", statusIcon(report.Summary.GasPass)))

	// Delegation Tests
	sb.WriteString("\nDELEGATION TESTS\n")
	sb.WriteString("-" + strings.Repeat("-", 39) + "\n")
	for _, r := range report.DelegationResults {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n", status, r.TestCase.Name))
		if !r.Passed {
			sb.WriteString(fmt.Sprintf("       Description: %s\n", r.TestCase.Description))
			sb.WriteString(fmt.Sprintf("       Expected valid: %v, Got valid: %v\n", r.TestCase.ExpectValid, r.GotValid))
		}
	}

	// Authorization Tests
	sb.WriteString("\nAUTHORIZATION TESTS\n")
	sb.WriteString("-" + strings.Repeat("-", 39) + "\n")
	for _, r := range report.AuthorizationResults {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n", status, r.TestCase.Name))
		if !r.Passed {
			sb.WriteString(fmt.Sprintf("       Description: %s\n", r.TestCase.Description))
			if r.Error != nil {
				sb.WriteString(fmt.Sprintf("       Error: %v\n", r.Error))
			}
		}
	}

	// Transaction Tests
	sb.WriteString("\nSETCODE TRANSACTION TESTS\n")
	sb.WriteString("-" + strings.Repeat("-", 39) + "\n")
	for _, r := range report.SetCodeTxResults {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n", status, r.TestCase.Name))
		if !r.Passed {
			sb.WriteString(fmt.Sprintf("       Description: %s\n", r.TestCase.Description))
			if r.Verification != nil && r.Verification.ErrorMessage != "" {
				sb.WriteString(fmt.Sprintf("       Error: %s\n", r.Verification.ErrorMessage))
			}
		}
	}

	// Gas Tests
	sb.WriteString("\nGAS CALCULATION TESTS\n")
	sb.WriteString("-" + strings.Repeat("-", 39) + "\n")
	for _, r := range report.GasResults {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
		}
		sb.WriteString(fmt.Sprintf("[%s] %s\n", status, r.TestCase.Name))
		if !r.Passed {
			sb.WriteString(fmt.Sprintf("       Description: %s\n", r.TestCase.Description))
			sb.WriteString(fmt.Sprintf("       Expected: %d, Got: %d (diff: %d)\n",
				r.TestCase.ExpectedGas, r.Calculation.TotalGas, r.Difference))
		}
	}

	sb.WriteString("\n" + "=" + strings.Repeat("=", 79) + "\n")
	if report.Summary.PassedTests == report.Summary.TotalTests {
		sb.WriteString("  ALL TESTS PASSED\n")
	} else {
		sb.WriteString(fmt.Sprintf("  %d TESTS FAILED\n", report.Summary.FailedTests))
	}
	sb.WriteString("=" + strings.Repeat("=", 79) + "\n")

	return sb.String()
}

func statusIcon(passed bool) string {
	if passed {
		return "PASS"
	}
	return "FAIL"
}

// VerificationResult is a generic verification result
type VerificationResult struct {
	Component   string
	Name        string
	Passed      bool
	Message     string
	Details     map[string]interface{}
}

// QuickVerify performs a quick verification of essential EIP-7702 components
func QuickVerify() []VerificationResult {
	results := make([]VerificationResult, 0)

	// Verify delegation prefix constant
	results = append(results, VerificationResult{
		Component: "Constants",
		Name:      "DelegationPrefix",
		Passed:    len(DelegationPrefix) == 3 && DelegationPrefix[0] == 0xef && DelegationPrefix[1] == 0x01 && DelegationPrefix[2] == 0x00,
		Message:   fmt.Sprintf("DelegationPrefix = 0x%x", DelegationPrefix),
		Details:   map[string]interface{}{"expected": "0xef0100", "actual": fmt.Sprintf("0x%x", DelegationPrefix)},
	})

	// Verify gas constants
	results = append(results, VerificationResult{
		Component: "Constants",
		Name:      "AuthorizationGas",
		Passed:    CallNewAccountGas == 25000 && TxAuthTupleGas == 12500,
		Message:   fmt.Sprintf("CallNewAccountGas=%d, TxAuthTupleGas=%d", CallNewAccountGas, TxAuthTupleGas),
		Details: map[string]interface{}{
			"CallNewAccountGas": CallNewAccountGas,
			"TxAuthTupleGas":    TxAuthTupleGas,
		},
	})

	// Verify signing prefix
	results = append(results, VerificationResult{
		Component: "Constants",
		Name:      "AuthorizationSigningPrefix",
		Passed:    AuthorizationSigningPrefix == 0x05,
		Message:   fmt.Sprintf("AuthorizationSigningPrefix = 0x%02x", AuthorizationSigningPrefix),
		Details:   map[string]interface{}{"expected": "0x05", "actual": fmt.Sprintf("0x%02x", AuthorizationSigningPrefix)},
	})

	// Verify tx type
	results = append(results, VerificationResult{
		Component: "Constants",
		Name:      "SetCodeTxType",
		Passed:    SetCodeTxType == 0x04,
		Message:   fmt.Sprintf("SetCodeTxType = 0x%02x", SetCodeTxType),
		Details:   map[string]interface{}{"expected": "0x04", "actual": fmt.Sprintf("0x%02x", SetCodeTxType)},
	})

	// Verify delegation code length
	results = append(results, VerificationResult{
		Component: "Constants",
		Name:      "DelegationCodeLength",
		Passed:    DelegationCodeLength == 23,
		Message:   fmt.Sprintf("DelegationCodeLength = %d", DelegationCodeLength),
		Details:   map[string]interface{}{"expected": 23, "actual": DelegationCodeLength},
	})

	// Verify AddressToDelegation / ParseDelegation roundtrip
	testAddr := TestAddresses.Simple
	delegationCode := AddressToDelegation(testAddr)
	parsedAddr, ok := ParseDelegation(delegationCode)
	results = append(results, VerificationResult{
		Component: "Functions",
		Name:      "DelegationRoundtrip",
		Passed:    ok && parsedAddr == testAddr,
		Message:   fmt.Sprintf("AddressToDelegation -> ParseDelegation roundtrip"),
		Details: map[string]interface{}{
			"input":  testAddr.Hex(),
			"parsed": parsedAddr.Hex(),
			"ok":     ok,
		},
	})

	return results
}
