// EIP-7702 Inspector - A comprehensive verification and security analysis tool for EIP-7702 implementations
//
// This tool provides verification of EIP-7702 (EOA Code Delegation) implementations
// based on test patterns from go-ethereum and reth, plus security analysis capabilities.
//
// Usage:
//
//	eip7702-inspector [options]
//
// Options:
//
//	-chain-id      Chain ID to use for testing (default: 1, or from env/preset)
//	-key           Private key hex for signing tests (uses test key if not provided)
//	-quick         Run quick verification only
//	-verbose       Show detailed output
//	-network       Run network tests against a live Ethereum node
//	-rpc           RPC URL for network testing (default: http://localhost:8545)
//	-mnemonic      BIP39 mnemonic for deriving the test account
//	-target        Target address for delegation (for network tests)
//	-preset        Chain preset (local, mainnet, sepolia, holesky, goerli)
//	-env           Path to .env file (default: .env in current directory)
//	-list-presets  List available chain presets
//
// Security Commands:
//
//	-security    Run security analysis on an address
//	-attack      Run attack simulations
//	-validate    Validate an authorization or contract
//	-delegate    Send SetCode transaction to delegate EOA to target address
//
// Environment Variables:
//
//	CHAIN_ID        Chain ID (overrides default, overridden by -chain-id flag)
//	RPC_URL         RPC endpoint URL (overrides default, overridden by -rpc flag)
//	PRIVATE_KEY     Test account private key (no 0x prefix)
//	TARGET_ADDRESS  Delegation target contract address
//	CHAIN_PRESET    Chain preset name (e.g., sepolia)
package main

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
	"github.com/stable-net/eip7702-inspector/config"
	"github.com/stable-net/eip7702-inspector/inspector"
	"golang.org/x/crypto/pbkdf2"
)

func main() {
	// Pre-parse to get env path for early loading
	// We need to load .env before defining other flags so defaults work
	envLoaded := false
	for i, arg := range os.Args[1:] {
		if arg == "-env" && i+1 < len(os.Args)-1 {
			_ = config.LoadConfig(os.Args[i+2])
			envLoaded = true
			break
		} else if strings.HasPrefix(arg, "-env=") {
			_ = config.LoadConfig(strings.TrimPrefix(arg, "-env="))
			envLoaded = true
			break
		}
	}
	// Try default .env if not explicitly specified
	if !envLoaded {
		_ = config.LoadConfig("")
	}

	// Define flags
	_ = flag.String("env", "", "Path to .env file (default: .env in current directory)")
	preset := flag.String("preset", "", "Chain preset (local, mainnet, sepolia, holesky, goerli)")
	listPresets := flag.Bool("list-presets", false, "List available chain presets")

	// Define flags with environment-aware defaults
	chainID := flag.Int64("chain-id", config.GetChainID().Int64(), "Chain ID for testing")
	keyHex := flag.String("key", config.GetPrivateKey(), "Private key hex for signing tests")
	quick := flag.Bool("quick", false, "Run quick verification only")
	verbose := flag.Bool("verbose", false, "Show detailed output")
	network := flag.Bool("network", false, "Run network tests against a live Ethereum node")
	rpcURL := flag.String("rpc", config.GetRPCURL(), "RPC URL for network testing")
	mnemonic := flag.String("mnemonic", "", "BIP39 mnemonic for deriving the test account")
	targetAddr := flag.String("target", config.GetTargetAddress(), "Target address for delegation (for network tests)")

	// Security commands
	security := flag.Bool("security", false, "Run security analysis on target address")
	attack := flag.Bool("attack", false, "Run attack simulations")
	validate := flag.Bool("validate", false, "Validate authorization or contract security")

	// Delegation command
	delegate := flag.Bool("delegate", false, "Send SetCode transaction to delegate EOA to target address")

	flag.Parse()

	// Handle list-presets command
	if *listPresets {
		config.PrintPresets()
		return
	}

	// Apply preset if specified (preset values are overridden by explicit flags)
	if *preset != "" {
		presetConfig, err := config.ApplyPreset(*preset)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
		// Only apply preset values if not explicitly set via flags
		if !isFlagSet("chain-id") {
			*chainID = presetConfig.ChainID.Int64()
		}
		if !isFlagSet("rpc") {
			*rpcURL = presetConfig.RPCURL
		}
	}

	fmt.Println("EIP-7702 Inspector")
	fmt.Println("==================")

	// Derive private key from mnemonic if provided
	if *mnemonic != "" {
		derivedKey, err := deriveKeyFromMnemonic(*mnemonic, 0)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error deriving key from mnemonic: %v\n", err)
			os.Exit(1)
		}
		*keyHex = derivedKey
		fmt.Printf("Derived key from mnemonic\n")
	} else if *keyHex == "" {
		*keyHex = inspector.TestPrivateKeys[0]
	}

	if *quick {
		runQuickVerification(*verbose)
		return
	}

	if *security {
		runSecurityAnalysis(*rpcURL, *targetAddr)
		return
	}

	if *attack {
		runAttackSimulations(big.NewInt(*chainID), *keyHex, *targetAddr)
		return
	}

	if *validate {
		runValidation(big.NewInt(*chainID), *keyHex, *targetAddr)
		return
	}

	if *delegate {
		runDelegation(*rpcURL, *keyHex, *targetAddr)
		return
	}

	if *network {
		runNetworkTests(*rpcURL, *keyHex, *targetAddr)
		return
	}

	runFullInspection(big.NewInt(*chainID), *keyHex, *verbose)
}

// isFlagSet checks if a flag was explicitly set on the command line
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

// deriveKeyFromMnemonic derives a private key from a BIP39 mnemonic using BIP44 path
// Path: m/44'/60'/0'/0/accountIndex (Ethereum standard)
func deriveKeyFromMnemonic(mnemonic string, accountIndex uint32) (string, error) {
	// Normalize mnemonic
	words := strings.Fields(strings.ToLower(mnemonic))
	normalizedMnemonic := strings.Join(words, " ")

	// BIP39: Generate seed using PBKDF2-HMAC-SHA512
	// salt = "mnemonic" + passphrase (empty passphrase)
	salt := []byte("mnemonic")
	seed := pbkdf2.Key([]byte(normalizedMnemonic), salt, 2048, 64, sha512.New)

	// BIP32: Generate master key from seed
	masterKey, chainCode := generateMasterKey(seed)

	// BIP44: Derive path m/44'/60'/0'/0/accountIndex
	// 44' = 0x8000002C (purpose)
	// 60' = 0x8000003C (Ethereum coin type)
	// 0'  = 0x80000000 (account)
	// 0   = 0x00000000 (change)
	// idx = accountIndex (address index)
	path := []uint32{
		0x8000002C, // 44' (hardened)
		0x8000003C, // 60' (hardened)
		0x80000000, // 0' (hardened)
		0x00000000, // 0 (external chain)
		accountIndex,
	}

	key := masterKey
	code := chainCode
	var err error

	for _, index := range path {
		key, code, err = deriveChildKey(key, code, index)
		if err != nil {
			return "", fmt.Errorf("failed to derive child key: %w", err)
		}
	}

	return hex.EncodeToString(key), nil
}

// generateMasterKey generates the master private key and chain code from seed
func generateMasterKey(seed []byte) ([]byte, []byte) {
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	mac.Write(seed)
	result := mac.Sum(nil)
	return result[:32], result[32:]
}

// deriveChildKey derives a child key from parent key and chain code
func deriveChildKey(parentKey, chainCode []byte, index uint32) ([]byte, []byte, error) {
	var data []byte

	if index >= 0x80000000 {
		// Hardened child: 0x00 || parentKey || index
		data = make([]byte, 37)
		data[0] = 0x00
		copy(data[1:33], parentKey)
		binary.BigEndian.PutUint32(data[33:], index)
	} else {
		// Normal child: parentPubKey || index
		// For simplicity, we compute the public key point
		pubKey := computePublicKey(parentKey)
		data = make([]byte, 37)
		copy(data[:33], pubKey)
		binary.BigEndian.PutUint32(data[33:], index)
	}

	mac := hmac.New(sha512.New, chainCode)
	mac.Write(data)
	result := mac.Sum(nil)

	// Child key = (IL + parentKey) mod n
	il := new(big.Int).SetBytes(result[:32])
	pk := new(big.Int).SetBytes(parentKey)

	// secp256k1 curve order
	n, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

	childKey := new(big.Int).Add(il, pk)
	childKey.Mod(childKey, n)

	// Pad to 32 bytes
	keyBytes := childKey.Bytes()
	if len(keyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(keyBytes):], keyBytes)
		keyBytes = padded
	}

	return keyBytes, result[32:], nil
}

// computePublicKey computes the compressed public key from private key
func computePublicKey(privateKey []byte) []byte {
	// secp256k1 curve parameters
	p, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	gx, _ := new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	gy, _ := new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)

	k := new(big.Int).SetBytes(privateKey)

	// Point multiplication: k * G
	x, y := scalarMult(gx, gy, k, p)

	// Compressed public key format
	pubKey := make([]byte, 33)
	if y.Bit(0) == 0 {
		pubKey[0] = 0x02
	} else {
		pubKey[0] = 0x03
	}
	xBytes := x.Bytes()
	copy(pubKey[33-len(xBytes):], xBytes)

	return pubKey
}

// scalarMult performs elliptic curve point multiplication
func scalarMult(gx, gy, k, p *big.Int) (*big.Int, *big.Int) {
	rx, ry := new(big.Int), new(big.Int)
	tx, ty := new(big.Int).Set(gx), new(big.Int).Set(gy)

	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			rx, ry = pointAdd(rx, ry, tx, ty, p)
		}
		tx, ty = pointDouble(tx, ty, p)
	}

	return rx, ry
}

// pointAdd adds two points on the curve
func pointAdd(x1, y1, x2, y2, p *big.Int) (*big.Int, *big.Int) {
	if x1.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int).Set(x2), new(big.Int).Set(y2)
	}
	if x2.Sign() == 0 && y2.Sign() == 0 {
		return new(big.Int).Set(x1), new(big.Int).Set(y1)
	}

	// s = (y2 - y1) / (x2 - x1) mod p
	dy := new(big.Int).Sub(y2, y1)
	dx := new(big.Int).Sub(x2, x1)
	dx.Mod(dx, p)
	if dx.Sign() < 0 {
		dx.Add(dx, p)
	}
	dxInv := new(big.Int).ModInverse(dx, p)
	s := new(big.Int).Mul(dy, dxInv)
	s.Mod(s, p)

	// x3 = s^2 - x1 - x2 mod p
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, x1)
	x3.Sub(x3, x2)
	x3.Mod(x3, p)
	if x3.Sign() < 0 {
		x3.Add(x3, p)
	}

	// y3 = s(x1 - x3) - y1 mod p
	y3 := new(big.Int).Sub(x1, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, y1)
	y3.Mod(y3, p)
	if y3.Sign() < 0 {
		y3.Add(y3, p)
	}

	return x3, y3
}

// pointDouble doubles a point on the curve
func pointDouble(x, y, p *big.Int) (*big.Int, *big.Int) {
	if y.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// s = (3 * x^2) / (2 * y) mod p
	x2 := new(big.Int).Mul(x, x)
	x2.Mul(x2, big.NewInt(3))
	y2 := new(big.Int).Mul(y, big.NewInt(2))
	y2Inv := new(big.Int).ModInverse(y2, p)
	s := new(big.Int).Mul(x2, y2Inv)
	s.Mod(s, p)

	// x3 = s^2 - 2*x mod p
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, new(big.Int).Mul(x, big.NewInt(2)))
	x3.Mod(x3, p)
	if x3.Sign() < 0 {
		x3.Add(x3, p)
	}

	// y3 = s(x - x3) - y mod p
	y3 := new(big.Int).Sub(x, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, y)
	y3.Mod(y3, p)
	if y3.Sign() < 0 {
		y3.Add(y3, p)
	}

	return x3, y3
}

func runNetworkTests(rpcURL, keyHex, targetAddrHex string) {
	fmt.Println("Running Network Tests...")
	fmt.Println("------------------------")
	fmt.Printf("RPC URL: %s\n", rpcURL)

	// Create network tester
	tester, err := inspector.NewNetworkTester(rpcURL, keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating network tester: %v\n", err)
		os.Exit(1)
	}
	defer tester.Close()

	fmt.Printf("Account Address: %s\n", tester.GetAddress().Hex())
	fmt.Printf("Chain ID: %s\n", tester.GetChainID().String())

	// Get balance
	balance, err := tester.GetBalance()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting balance: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Balance: %s wei\n", balance.String())
	fmt.Println()

	// Parse target address
	var targetAddr common.Address
	if targetAddrHex != "" {
		targetAddr = common.HexToAddress(targetAddrHex)
	} else {
		// Use a sample contract address for testing
		targetAddr = common.HexToAddress("0x0000000000000000000000000000000000000042")
	}

	// Run network tests
	results, err := tester.RunNetworkTests(targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running network tests: %v\n", err)
		os.Exit(1)
	}

	// Format and print results
	fmt.Print(inspector.FormatNetworkResults(results))

	// Check for failures
	for _, r := range results {
		if !r.Passed {
			os.Exit(1)
		}
	}
}

func runQuickVerification(verbose bool) {
	fmt.Println("Running Quick Verification...")
	fmt.Println("-----------------------------")

	results := inspector.QuickVerify()

	allPassed := true
	for _, r := range results {
		status := "PASS"
		if !r.Passed {
			status = "FAIL"
			allPassed = false
		}
		fmt.Printf("[%s] %s/%s\n", status, r.Component, r.Name)
		if verbose || !r.Passed {
			fmt.Printf("       %s\n", r.Message)
		}
	}

	fmt.Println()
	if allPassed {
		fmt.Println("All quick verifications PASSED")
		os.Exit(0)
	} else {
		fmt.Println("Some quick verifications FAILED")
		os.Exit(1)
	}
}

func runFullInspection(chainID *big.Int, keyHex string, verbose bool) {
	insp := inspector.NewInspector(chainID, keyHex)

	report, err := insp.RunFullInspection()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error running inspection: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Print(inspector.FormatReport(report))
	} else {
		printSummary(report)
	}

	if report.Summary.FailedTests > 0 {
		os.Exit(1)
	}
}

func printSummary(report *inspector.InspectionReport) {
	fmt.Println("Inspection Summary")
	fmt.Println("------------------")
	fmt.Printf("Total Tests:  %d\n", report.Summary.TotalTests)
	fmt.Printf("Passed:       %d\n", report.Summary.PassedTests)
	fmt.Printf("Failed:       %d\n", report.Summary.FailedTests)
	fmt.Printf("Pass Rate:    %.1f%%\n", report.Summary.PassRate)
	fmt.Println()
	fmt.Println("Components:")
	printComponentStatus("Delegation", report.Summary.DelegationPass, len(report.DelegationResults))
	printComponentStatus("Authorization", report.Summary.AuthPass, len(report.AuthorizationResults))
	printComponentStatus("Transaction", report.Summary.TxPass, len(report.SetCodeTxResults))
	printComponentStatus("Gas Calculation", report.Summary.GasPass, len(report.GasResults))

	fmt.Println()
	if report.Summary.FailedTests == 0 {
		fmt.Println("All tests PASSED")
	} else {
		fmt.Printf("%d tests FAILED - run with -verbose for details\n", report.Summary.FailedTests)
	}
}

func printComponentStatus(name string, passed bool, count int) {
	status := "PASS"
	if !passed {
		status = "FAIL"
	}
	fmt.Printf("  %-16s [%s] (%d tests)\n", name, status, count)
}

// runSecurityAnalysis performs security analysis on a target address
func runSecurityAnalysis(rpcURL, targetAddrHex string) {
	fmt.Println("Running Security Analysis...")
	fmt.Println("----------------------------")

	if targetAddrHex == "" {
		fmt.Fprintf(os.Stderr, "Error: -target address required for security analysis\n")
		os.Exit(1)
	}

	targetAddr := common.HexToAddress(targetAddrHex)
	fmt.Printf("Target Address: %s\n\n", targetAddr.Hex())

	// Create security analyzer
	analyzer := inspector.NewSecurityAnalyzer()

	// If RPC is provided, try to get code from network
	var code []byte
	if rpcURL != "" {
		tester, err := inspector.NewNetworkTester(rpcURL, inspector.TestPrivateKeys[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Could not connect to RPC: %v\n", err)
		} else {
			defer tester.Close()
			code, err = tester.GetCode(targetAddr)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: Could not get code: %v\n", err)
			}
		}
	}

	// Analyze the address
	result := analyzer.AnalyzeAddress(targetAddr, code)

	// Print the report
	fmt.Print(inspector.FormatSecurityReport(result))

	// Exit with error if critical issues found
	if result.HighestRisk == inspector.RiskCritical {
		os.Exit(1)
	}
}

// runAttackSimulations runs attack simulations
func runAttackSimulations(chainID *big.Int, keyHex, targetAddrHex string) {
	fmt.Println("Running Attack Simulations...")
	fmt.Println("-----------------------------")

	var targetAddr common.Address
	if targetAddrHex != "" {
		targetAddr = common.HexToAddress(targetAddrHex)
	} else {
		targetAddr = common.HexToAddress("0x0000000000000000000000000000000000000042")
	}

	fmt.Printf("Target Contract: %s\n", targetAddr.Hex())
	fmt.Printf("Chain ID: %s\n\n", chainID.String())

	// Create attack simulator
	simulator, err := inspector.NewAttackSimulator(chainID, keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating attack simulator: %v\n", err)
		os.Exit(1)
	}

	// Run all attack simulations
	results := simulator.RunAllAttackSimulations(targetAddr)

	// Print results
	fmt.Print(inspector.FormatAllAttackResults(results))

	// Count vulnerabilities
	vulnCount := 0
	for _, r := range results {
		if r.Vulnerable {
			vulnCount++
		}
	}

	if vulnCount > 0 {
		fmt.Printf("\nWARNING: %d potential vulnerabilities identified!\n", vulnCount)
		fmt.Println("Review the recommendations above to mitigate these risks.")
	}
}

// runValidation runs validation checks
func runValidation(chainID *big.Int, keyHex, targetAddrHex string) {
	fmt.Println("Running Validation Checks...")
	fmt.Println("----------------------------")

	validator := inspector.NewValidator(chainID)

	// Add some trusted contracts for testing
	validator.AddTrustedContract(common.HexToAddress("0x0000000000000000000000000000000000000042"))

	var targetAddr common.Address
	if targetAddrHex != "" {
		targetAddr = common.HexToAddress(targetAddrHex)
	} else {
		targetAddr = common.HexToAddress("0x0000000000000000000000000000000000000042")
	}

	fmt.Printf("Validating authorization for target: %s\n\n", targetAddr.Hex())

	// Create a sample authorization for validation
	auth := inspector.SetCodeAuthorization{
		ChainID: *uint256.MustFromBig(chainID),
		Address: targetAddr,
		Nonce:   0,
	}

	// Validate the authorization
	result := validator.ValidateAuthorization(&auth)

	// Print results
	fmt.Printf("Authorization Valid: %v\n", result.IsValid)
	fmt.Printf("Authorization Safe: %v\n", result.IsSafe)
	fmt.Printf("Should Block: %v\n", result.ShouldBlock)
	if result.BlockReason != "" {
		fmt.Printf("Block Reason: %s\n", result.BlockReason)
	}

	fmt.Print(inspector.FormatValidationResults(result.Findings))

	// Run best practice checks
	bpc := inspector.NewBestPracticeChecker()
	bpResults := bpc.CheckAuthorizationBestPractices(&auth)

	fmt.Println("\n--- Best Practice Checks ---")
	fmt.Print(inspector.FormatValidationResults(bpResults))

	// Exit with error if should block
	if result.ShouldBlock {
		os.Exit(1)
	}
}

// runDelegation sends a SetCode transaction to delegate the EOA to the target address
func runDelegation(rpcURL, keyHex, targetAddrHex string) {
	fmt.Println("Sending SetCode Transaction for Delegation...")
	fmt.Println("---------------------------------------------")

	if targetAddrHex == "" {
		fmt.Fprintf(os.Stderr, "Error: -target address required for delegation\n")
		os.Exit(1)
	}

	targetAddr := common.HexToAddress(targetAddrHex)
	fmt.Printf("Target Contract: %s\n", targetAddr.Hex())
	fmt.Printf("RPC URL: %s\n", rpcURL)

	// Create network tester
	tester, err := inspector.NewNetworkTester(rpcURL, keyHex)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating network tester: %v\n", err)
		os.Exit(1)
	}
	defer tester.Close()

	fmt.Printf("Account Address: %s\n", tester.GetAddress().Hex())
	fmt.Printf("Chain ID: %s\n", tester.GetChainID().String())

	// Get balance
	balance, err := tester.GetBalance()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting balance: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Balance: %s wei\n\n", balance.String())

	// Send SetCode transaction
	result, err := tester.TestSetCodeTransaction(targetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error sending SetCode transaction: %v\n", err)
		os.Exit(1)
	}

	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "SetCode transaction failed: %v\n", result.Error)
		if details, ok := result.Details["errorMessage"]; ok {
			fmt.Fprintf(os.Stderr, "Error details: %v\n", details)
		}
		os.Exit(1)
	}

	fmt.Println("=== SetCode Transaction Result ===")
	fmt.Printf("Status: %s\n", result.Details["status"])
	fmt.Printf("TX Hash: %s\n", result.TxHash)
	fmt.Printf("Authority: %s\n", result.Details["authority"])
	fmt.Printf("Target Address: %s\n", result.Details["targetAddress"])
	fmt.Printf("TX Nonce: %v\n", result.Details["txNonce"])
	fmt.Printf("Auth Nonce: %v\n", result.Details["authNonce"])
	fmt.Println()
	fmt.Println("SetCode transaction submitted successfully!")
	fmt.Println("Note: Wait for transaction confirmation before using the delegated account.")
}
