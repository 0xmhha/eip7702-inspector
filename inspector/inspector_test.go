package inspector

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

func TestDelegationPrefix(t *testing.T) {
	if len(DelegationPrefix) != 3 {
		t.Errorf("DelegationPrefix length = %d, want 3", len(DelegationPrefix))
	}
	if DelegationPrefix[0] != 0xef || DelegationPrefix[1] != 0x01 || DelegationPrefix[2] != 0x00 {
		t.Errorf("DelegationPrefix = %x, want ef0100", DelegationPrefix)
	}
}

func TestParseDelegation(t *testing.T) {
	testCases := GetDelegationTestCases()

	for _, tc := range testCases {
		t.Run(tc.Name, func(t *testing.T) {
			addr, ok := ParseDelegation(tc.Input)

			if ok != tc.ExpectValid {
				t.Errorf("ParseDelegation() valid = %v, want %v", ok, tc.ExpectValid)
			}

			if tc.ExpectValid && tc.ExpectedAddr != nil {
				if addr != *tc.ExpectedAddr {
					t.Errorf("ParseDelegation() addr = %s, want %s", addr.Hex(), tc.ExpectedAddr.Hex())
				}
			}
		})
	}
}

func TestAddressToDelegation(t *testing.T) {
	addr := common.HexToAddress("0x0000000000000000000000000000000000000042")
	delegation := AddressToDelegation(addr)

	if len(delegation) != DelegationCodeLength {
		t.Errorf("AddressToDelegation() length = %d, want %d", len(delegation), DelegationCodeLength)
	}

	// Verify roundtrip
	parsedAddr, ok := ParseDelegation(delegation)
	if !ok {
		t.Error("ParseDelegation() failed on AddressToDelegation result")
	}
	if parsedAddr != addr {
		t.Errorf("Roundtrip failed: got %s, want %s", parsedAddr.Hex(), addr.Hex())
	}
}

func TestVerifyDelegation(t *testing.T) {
	addr := common.HexToAddress("0x000000000000000000000000000000000000aaaa")
	validDelegation := AddressToDelegation(addr)

	result := VerifyDelegation(validDelegation)

	if !result.Valid {
		t.Errorf("VerifyDelegation() valid = false for valid delegation, error: %s", result.ErrorMessage)
	}
	if !result.PrefixCorrect {
		t.Error("VerifyDelegation() prefix incorrect for valid delegation")
	}
	if !result.LengthCorrect {
		t.Error("VerifyDelegation() length incorrect for valid delegation")
	}
	if result.Address == nil || *result.Address != addr {
		t.Errorf("VerifyDelegation() address = %v, want %s", result.Address, addr.Hex())
	}
}

func TestSignSetCode(t *testing.T) {
	key, err := crypto.HexToECDSA(TestPrivateKeys[0])
	if err != nil {
		t.Fatalf("Failed to parse private key: %v", err)
	}

	expectedAuthority := crypto.PubkeyToAddress(key.PublicKey)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}

	signedAuth, err := SignSetCode(key, auth)
	if err != nil {
		t.Fatalf("SignSetCode() error = %v", err)
	}

	// Verify signature is set
	if signedAuth.R.IsZero() || signedAuth.S.IsZero() {
		t.Error("SignSetCode() did not set R and S values")
	}

	// Recover authority
	recoveredAuthority, err := signedAuth.Authority()
	if err != nil {
		t.Fatalf("Authority() error = %v", err)
	}

	if recoveredAuthority != expectedAuthority {
		t.Errorf("Authority() = %s, want %s", recoveredAuthority.Hex(), expectedAuthority.Hex())
	}
}

func TestVerifyAuthorization(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}

	signedAuth, _ := SignSetCode(key, auth)
	result := VerifyAuthorization(&signedAuth, chainID)

	if !result.Valid {
		t.Errorf("VerifyAuthorization() valid = false, error: %s", result.ErrorMessage)
	}
	if !result.SignatureValid {
		t.Error("VerifyAuthorization() signature invalid")
	}
}

func TestVerifySetCodeTx_EmptyAuthList(t *testing.T) {
	tx := &SetCodeTx{
		Nonce:    0,
		Gas:      50000,
		To:       TestAddresses.Simple,
		AuthList: []SetCodeAuthorization{}, // Empty
	}

	result := VerifySetCodeTx(tx, big.NewInt(1))

	if result.Valid {
		t.Error("VerifySetCodeTx() should fail for empty auth list")
	}
	if result.HasAuthList {
		t.Error("VerifySetCodeTx() HasAuthList should be false for empty list")
	}
	if result.ErrorMessage != "EIP-7702 transaction with empty auth list" {
		t.Errorf("VerifySetCodeTx() wrong error: %s", result.ErrorMessage)
	}
}

func TestVerifySetCodeTx_ValidTx(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}
	signedAuth, _ := SignSetCode(key, auth)

	tx := &SetCodeTx{
		ChainID:  *uint256.MustFromBig(chainID),
		Nonce:    0,
		Gas:      500000,
		To:       TestAddresses.Simple,
		AuthList: []SetCodeAuthorization{signedAuth},
	}

	result := VerifySetCodeTx(tx, chainID)

	if !result.Valid {
		t.Errorf("VerifySetCodeTx() valid = false, error: %s", result.ErrorMessage)
	}
	if !result.HasAuthList {
		t.Error("VerifySetCodeTx() HasAuthList should be true")
	}
	if result.AuthListLength != 1 {
		t.Errorf("VerifySetCodeTx() AuthListLength = %d, want 1", result.AuthListLength)
	}
}

func TestCalculateDetailedGas(t *testing.T) {
	testCases := []struct {
		name            string
		tx              *SetCodeTx
		existingAccounts []bool
		expectedGas     uint64
	}{
		{
			name: "base_tx_no_auth",
			tx: &SetCodeTx{
				AuthList: []SetCodeAuthorization{},
			},
			expectedGas: 21000, // Just base gas
		},
		{
			name: "single_new_account_auth",
			tx: &SetCodeTx{
				AuthList: []SetCodeAuthorization{{}},
			},
			existingAccounts: []bool{false},
			expectedGas:      21000 + 25000, // base + new account
		},
		{
			name: "single_existing_account_auth",
			tx: &SetCodeTx{
				AuthList: []SetCodeAuthorization{{}},
			},
			existingAccounts: []bool{true},
			expectedGas:      21000 + 25000 - 12500, // base + new - refund
		},
		{
			name: "with_calldata",
			tx: &SetCodeTx{
				Data:     []byte{0x00, 0x01, 0x02}, // 1 zero, 2 non-zero
				AuthList: []SetCodeAuthorization{{}},
			},
			existingAccounts: []bool{false},
			expectedGas:      21000 + 25000 + 4 + 32, // base + auth + data
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := CalculateDetailedGas(tc.tx, tc.existingAccounts)
			if result.TotalGas != tc.expectedGas {
				t.Errorf("CalculateDetailedGas() = %d, want %d", result.TotalGas, tc.expectedGas)
			}
		})
	}
}

func TestQuickVerify(t *testing.T) {
	results := QuickVerify()

	for _, r := range results {
		if !r.Passed {
			t.Errorf("QuickVerify %s/%s failed: %s", r.Component, r.Name, r.Message)
		}
	}
}

func TestFullInspection(t *testing.T) {
	inspector := NewInspector(big.NewInt(1), TestPrivateKeys[0])
	report, err := inspector.RunFullInspection()
	if err != nil {
		t.Fatalf("RunFullInspection() error = %v", err)
	}

	if report.Summary.TotalTests == 0 {
		t.Error("RunFullInspection() produced no tests")
	}

	// Log the report for visibility
	t.Logf("Total: %d, Passed: %d, Failed: %d, Rate: %.1f%%",
		report.Summary.TotalTests,
		report.Summary.PassedTests,
		report.Summary.FailedTests,
		report.Summary.PassRate)
}
