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

// TestValidateTxType tests transaction type validation functions
func TestValidateTxType(t *testing.T) {
	testCases := []struct {
		name       string
		txType     uint8
		wantValid  bool
		wantName   string
	}{
		{"valid_setcode_type", SetCodeTxType, true, "SetCode (EIP-7702)"},
		{"invalid_legacy_type", LegacyTxType, false, "Legacy"},
		{"invalid_accesslist_type", AccessListTxType, false, "AccessList (EIP-2930)"},
		{"invalid_dynamicfee_type", DynamicFeeTxType, false, "DynamicFee (EIP-1559)"},
		{"invalid_blob_type", BlobTxType, false, "Blob (EIP-4844)"},
		{"invalid_unknown_type", 0x05, false, "Unknown (0x05)"},
		{"invalid_high_type", 0xff, false, "Unknown (0xff)"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Test ValidateTxType
			if got := ValidateTxType(tc.txType); got != tc.wantValid {
				t.Errorf("ValidateTxType(0x%02x) = %v, want %v", tc.txType, got, tc.wantValid)
			}

			// Test ValidateTxTypeValue
			errMsg := ValidateTxTypeValue(tc.txType)
			if tc.wantValid && errMsg != "" {
				t.Errorf("ValidateTxTypeValue(0x%02x) = %q, want empty", tc.txType, errMsg)
			}
			if !tc.wantValid && errMsg == "" {
				t.Errorf("ValidateTxTypeValue(0x%02x) = empty, want error", tc.txType)
			}

			// Test GetTxTypeName
			if got := GetTxTypeName(tc.txType); got != tc.wantName {
				t.Errorf("GetTxTypeName(0x%02x) = %q, want %q", tc.txType, got, tc.wantName)
			}
		})
	}
}

// TestVerifySetCodeTx_TxType tests EIP-7702 transaction type validation
func TestVerifySetCodeTx_TxType(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)
	chainIDUint := uint256.MustFromBig(chainID)

	// Create a valid authorization
	auth := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}
	signedAuth, _ := SignSetCode(key, auth)

	t.Run("valid_setcode_type", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType, // 0x04
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if !result.TxTypeValid {
			t.Error("TxTypeValid should be true for SetCodeTxType")
		}
		if result.TxType != SetCodeTxType {
			t.Errorf("TxType = 0x%02x, want 0x%02x", result.TxType, SetCodeTxType)
		}
	})

	t.Run("invalid_legacy_type", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     LegacyTxType, // 0x00
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if result.Valid {
			t.Error("VerifySetCodeTx() should reject legacy transaction type")
		}
		if result.TxTypeValid {
			t.Error("TxTypeValid should be false for LegacyTxType")
		}
		if result.TxType != LegacyTxType {
			t.Errorf("TxType = 0x%02x, want 0x%02x", result.TxType, LegacyTxType)
		}
		t.Logf("Correctly rejected invalid type: %s", result.ErrorMessage)
	})

	t.Run("invalid_eip1559_type", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     DynamicFeeTxType, // 0x02
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if result.Valid {
			t.Error("VerifySetCodeTx() should reject EIP-1559 transaction type")
		}
		if result.TxTypeValid {
			t.Error("TxTypeValid should be false for DynamicFeeTxType")
		}
		t.Logf("Correctly rejected EIP-1559 type: %s", result.ErrorMessage)
	})

	t.Run("invalid_blob_type", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     BlobTxType, // 0x03
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if result.Valid {
			t.Error("VerifySetCodeTx() should reject blob transaction type")
		}
		if result.TxTypeValid {
			t.Error("TxTypeValid should be false for BlobTxType")
		}
		t.Logf("Correctly rejected blob type: %s", result.ErrorMessage)
	})

	t.Run("invalid_unknown_type", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     0x05, // Unknown future type
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if result.Valid {
			t.Error("VerifySetCodeTx() should reject unknown transaction type")
		}
		if result.TxTypeValid {
			t.Error("TxTypeValid should be false for unknown type")
		}
		t.Logf("Correctly rejected unknown type: %s", result.ErrorMessage)
	})
}

func TestVerifySetCodeTx_EmptyAuthList(t *testing.T) {
	tx := &SetCodeTx{
		Type:     SetCodeTxType,
		Nonce:    0,
		Gas:      50000,
		To:       &TestAddresses.Simple,
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

// TestVerifySetCodeTx_NilDestination tests EIP-7702 nil destination (contract creation) rejection
func TestVerifySetCodeTx_NilDestination(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)
	chainIDUint := uint256.MustFromBig(chainID)

	// Create a valid authorization
	auth := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}
	signedAuth, _ := SignSetCode(key, auth)

	t.Run("nil_destination_rejected", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       nil, // Contract creation attempt
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if result.Valid {
			t.Error("VerifySetCodeTx() should reject nil destination")
		}
		if !result.IsContractCreation {
			t.Error("IsContractCreation should be true for nil To")
		}
		if result.ToFieldValid {
			t.Error("ToFieldValid should be false for nil To")
		}
		if result.ErrorMessage != "EIP-7702 transaction cannot create contracts (To field is nil)" {
			t.Errorf("Wrong error message: %s", result.ErrorMessage)
		}
		t.Logf("Correctly rejected nil destination: %s", result.ErrorMessage)
	})

	t.Run("zero_address_valid", func(t *testing.T) {
		zeroAddr := common.Address{}
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &zeroAddr, // Zero address, not nil
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should accept zero address, error: %s", result.ErrorMessage)
		}
		if result.IsContractCreation {
			t.Error("IsContractCreation should be false for zero address (not nil)")
		}
		if !result.IsZeroAddress {
			t.Error("IsZeroAddress should be true for zero address")
		}
		if !result.ToFieldValid {
			t.Error("ToFieldValid should be true for zero address")
		}
		t.Logf("Correctly accepted zero address: IsZeroAddress=%v", result.IsZeroAddress)
	})

	t.Run("normal_address_valid", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should accept normal address, error: %s", result.ErrorMessage)
		}
		if result.IsContractCreation {
			t.Error("IsContractCreation should be false for normal address")
		}
		if result.IsZeroAddress {
			t.Error("IsZeroAddress should be false for normal address")
		}
		if !result.ToFieldValid {
			t.Error("ToFieldValid should be true for normal address")
		}
	})
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
		Type:     SetCodeTxType,
		ChainID:  *uint256.MustFromBig(chainID),
		Nonce:    0,
		Gas:      500000,
		To:       &TestAddresses.Simple,
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

// TestValidateSignatureS tests EIP-2 s-value validation
func TestValidateSignatureS(t *testing.T) {
	testCases := []struct {
		name        string
		sValue      *uint256.Int
		expectValid bool
		description string
	}{
		{
			name:        "valid_s_value_low",
			sValue:      uint256.NewInt(1),
			expectValid: true,
			description: "Valid low s value",
		},
		{
			name:        "valid_s_value_at_half_n",
			sValue:      Secp256k1HalfN,
			expectValid: true,
			description: "Valid s value exactly at secp256k1n/2",
		},
		{
			name:        "invalid_s_value_above_half_n",
			sValue:      new(uint256.Int).Add(Secp256k1HalfN, uint256.NewInt(1)),
			expectValid: false,
			description: "Invalid s value above secp256k1n/2",
		},
		{
			name:        "invalid_s_value_at_n",
			sValue:      Secp256k1N,
			expectValid: false,
			description: "Invalid s value at secp256k1n (curve order)",
		},
		{
			name:        "valid_s_value_random_low",
			sValue:      uint256.MustFromHex("0x1234567890abcdef"),
			expectValid: true,
			description: "Valid random low s value",
		},
		{
			name:        "invalid_s_value_high",
			sValue:      uint256.MustFromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364140"),
			expectValid: false,
			description: "Invalid high s value close to n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateSignatureS(tc.sValue)
			if result != tc.expectValid {
				t.Errorf("ValidateSignatureS() = %v, want %v for %s", result, tc.expectValid, tc.description)
			}
		})
	}
}

// TestValidateSignatureSValue tests EIP-2 s-value validation with error messages
func TestValidateSignatureSValue(t *testing.T) {
	testCases := []struct {
		name          string
		sValue        *uint256.Int
		expectError   bool
		description   string
	}{
		{
			name:        "valid_s_value",
			sValue:      uint256.NewInt(12345),
			expectError: false,
			description: "Valid s value should return empty string",
		},
		{
			name:        "nil_s_value",
			sValue:      nil,
			expectError: true,
			description: "Nil s value should return error",
		},
		{
			name:        "zero_s_value",
			sValue:      uint256.NewInt(0),
			expectError: true,
			description: "Zero s value should return error",
		},
		{
			name:        "high_s_value",
			sValue:      new(uint256.Int).Add(Secp256k1HalfN, uint256.NewInt(1)),
			expectError: true,
			description: "High s value should return error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errMsg := ValidateSignatureSValue(tc.sValue)
			hasError := errMsg != ""
			if hasError != tc.expectError {
				t.Errorf("ValidateSignatureSValue() error = %v, want error = %v. Message: %s", hasError, tc.expectError, errMsg)
			}
		})
	}
}

// TestVerifyAuthorizationWithHighS tests that authorization with high s value is rejected
func TestVerifyAuthorizationWithHighS(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}

	signedAuth, _ := SignSetCode(key, auth)

	// Manually set s to a value above secp256k1n/2 (simulating malleable signature)
	highS := new(uint256.Int).Add(Secp256k1HalfN, uint256.NewInt(1))
	signedAuth.S = *highS

	result := VerifyAuthorization(&signedAuth, chainID)

	if result.Valid {
		t.Error("VerifyAuthorization() should reject high s value (EIP-2 violation)")
	}
	if result.SValueValid {
		t.Error("VerifyAuthorization() SValueValid should be false for high s")
	}
	if result.ErrorMessage == "" {
		t.Error("VerifyAuthorization() should provide error message for high s value")
	}
	t.Logf("Correctly rejected high s value: %s", result.ErrorMessage)
}

// TestVerifyAuthorizationWithValidS tests that authorization with valid s value passes
func TestVerifyAuthorizationWithValidS(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}

	signedAuth, _ := SignSetCode(key, auth)

	// Verify the signed s value is already in lower half (go-ethereum signs this way)
	if !ValidateSignatureS(&signedAuth.S) {
		t.Skip("Test key produces high s value, need to normalize")
	}

	result := VerifyAuthorization(&signedAuth, chainID)

	if !result.Valid {
		t.Errorf("VerifyAuthorization() should accept valid s value, error: %s", result.ErrorMessage)
	}
	if !result.SValueValid {
		t.Error("VerifyAuthorization() SValueValid should be true for valid s")
	}
}

// TestValidateYParity tests EIP-7702 y_parity validation
func TestValidateYParity(t *testing.T) {
	testCases := []struct {
		name        string
		vValue      uint8
		expectValid bool
		description string
	}{
		{
			name:        "valid_y_parity_0",
			vValue:      0,
			expectValid: true,
			description: "Valid y_parity = 0",
		},
		{
			name:        "valid_y_parity_1",
			vValue:      1,
			expectValid: true,
			description: "Valid y_parity = 1",
		},
		{
			name:        "invalid_y_parity_2",
			vValue:      2,
			expectValid: false,
			description: "Invalid y_parity = 2",
		},
		{
			name:        "invalid_y_parity_27",
			vValue:      27,
			expectValid: false,
			description: "Invalid y_parity = 27 (legacy v value)",
		},
		{
			name:        "invalid_y_parity_28",
			vValue:      28,
			expectValid: false,
			description: "Invalid y_parity = 28 (legacy v value)",
		},
		{
			name:        "invalid_y_parity_255",
			vValue:      255,
			expectValid: false,
			description: "Invalid y_parity = 255 (max uint8)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateYParity(tc.vValue)
			if result != tc.expectValid {
				t.Errorf("ValidateYParity(%d) = %v, want %v for %s", tc.vValue, result, tc.expectValid, tc.description)
			}
		})
	}
}

// TestValidateYParityValue tests EIP-7702 y_parity validation with error messages
func TestValidateYParityValue(t *testing.T) {
	testCases := []struct {
		name        string
		vValue      uint8
		expectError bool
		description string
	}{
		{
			name:        "valid_y_parity_0",
			vValue:      0,
			expectError: false,
			description: "Valid y_parity = 0 should return empty string",
		},
		{
			name:        "valid_y_parity_1",
			vValue:      1,
			expectError: false,
			description: "Valid y_parity = 1 should return empty string",
		},
		{
			name:        "invalid_y_parity_2",
			vValue:      2,
			expectError: true,
			description: "Invalid y_parity = 2 should return error",
		},
		{
			name:        "invalid_y_parity_27",
			vValue:      27,
			expectError: true,
			description: "Invalid y_parity = 27 should return error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errMsg := ValidateYParityValue(tc.vValue)
			hasError := errMsg != ""
			if hasError != tc.expectError {
				t.Errorf("ValidateYParityValue(%d) error = %v, want error = %v. Message: %s", tc.vValue, hasError, tc.expectError, errMsg)
			}
		})
	}
}

// TestVerifyAuthorizationWithInvalidYParity tests that authorization with invalid y_parity is rejected
func TestVerifyAuthorizationWithInvalidYParity(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}

	signedAuth, _ := SignSetCode(key, auth)

	// Manually set V to invalid value (simulating legacy signature)
	signedAuth.V = 27

	result := VerifyAuthorization(&signedAuth, chainID)

	if result.Valid {
		t.Error("VerifyAuthorization() should reject invalid y_parity (v=27)")
	}
	if result.YParityValid {
		t.Error("VerifyAuthorization() YParityValid should be false for v=27")
	}
	if result.ErrorMessage == "" {
		t.Error("VerifyAuthorization() should provide error message for invalid y_parity")
	}
	t.Logf("Correctly rejected invalid y_parity: %s", result.ErrorMessage)
}

// TestVerifyAuthorizationWithValidYParity tests that authorization with valid y_parity passes
func TestVerifyAuthorizationWithValidYParity(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)

	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}

	signedAuth, _ := SignSetCode(key, auth)

	// go-ethereum should produce valid y_parity (0 or 1)
	if !ValidateYParity(signedAuth.V) {
		t.Fatalf("Test key produces invalid y_parity: %d", signedAuth.V)
	}

	result := VerifyAuthorization(&signedAuth, chainID)

	if !result.Valid {
		t.Errorf("VerifyAuthorization() should accept valid y_parity, error: %s", result.ErrorMessage)
	}
	if !result.YParityValid {
		t.Error("VerifyAuthorization() YParityValid should be true for valid y_parity")
	}
}

// TestValidateNonce tests EIP-7702 nonce validation
func TestValidateNonce(t *testing.T) {
	testCases := []struct {
		name        string
		nonce       uint64
		expectValid bool
		description string
	}{
		{
			name:        "valid_nonce_0",
			nonce:       0,
			expectValid: true,
			description: "Valid nonce = 0",
		},
		{
			name:        "valid_nonce_1",
			nonce:       1,
			expectValid: true,
			description: "Valid nonce = 1",
		},
		{
			name:        "valid_nonce_large",
			nonce:       1000000000,
			expectValid: true,
			description: "Valid large nonce",
		},
		{
			name:        "valid_nonce_max_minus_2",
			nonce:       ^uint64(0) - 2,
			expectValid: true,
			description: "Valid nonce = 2^64 - 3 (max valid - 1)",
		},
		{
			name:        "valid_nonce_max_valid",
			nonce:       MaxNonce,
			expectValid: true,
			description: "Valid nonce = 2^64 - 2 (max valid)",
		},
		{
			name:        "invalid_nonce_max_uint64",
			nonce:       ^uint64(0),
			expectValid: false,
			description: "Invalid nonce = 2^64 - 1 (max uint64)",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := ValidateNonce(tc.nonce)
			if result != tc.expectValid {
				t.Errorf("ValidateNonce(%d) = %v, want %v for %s", tc.nonce, result, tc.expectValid, tc.description)
			}
		})
	}
}

// TestValidateNonceValue tests EIP-7702 nonce validation with error messages
func TestValidateNonceValue(t *testing.T) {
	testCases := []struct {
		name        string
		nonce       uint64
		expectError bool
		description string
	}{
		{
			name:        "valid_nonce_0",
			nonce:       0,
			expectError: false,
			description: "Valid nonce = 0 should return empty string",
		},
		{
			name:        "valid_nonce_max_valid",
			nonce:       MaxNonce,
			expectError: false,
			description: "Valid max nonce should return empty string",
		},
		{
			name:        "invalid_nonce_max_uint64",
			nonce:       ^uint64(0),
			expectError: true,
			description: "Invalid max uint64 nonce should return error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			errMsg := ValidateNonceValue(tc.nonce)
			hasError := errMsg != ""
			if hasError != tc.expectError {
				t.Errorf("ValidateNonceValue(%d) error = %v, want error = %v. Message: %s", tc.nonce, hasError, tc.expectError, errMsg)
			}
		})
	}
}

// TestVerifyAuthorizationWithInvalidNonce tests that authorization with invalid nonce is rejected
func TestVerifyAuthorizationWithInvalidNonce(t *testing.T) {
	chainID := big.NewInt(1)

	// Create authorization with max uint64 nonce (invalid)
	auth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   ^uint64(0), // Max uint64 = 2^64 - 1 (invalid)
	}

	// Use structural verification (no signature needed)
	result := VerifyAuthorizationWithOptions(&auth, chainID, false)

	if result.Valid {
		t.Error("VerifyAuthorization() should reject invalid nonce (2^64 - 1)")
	}
	if result.NonceValid {
		t.Error("VerifyAuthorization() NonceValid should be false for max uint64 nonce")
	}
	if result.ErrorMessage == "" {
		t.Error("VerifyAuthorization() should provide error message for invalid nonce")
	}
	t.Logf("Correctly rejected invalid nonce: %s", result.ErrorMessage)
}

// TestVerifyAuthorizationWithValidNonce tests that authorization with valid nonce passes
func TestVerifyAuthorizationWithValidNonce(t *testing.T) {
	chainID := big.NewInt(1)

	testCases := []struct {
		name  string
		nonce uint64
	}{
		{"nonce_0", 0},
		{"nonce_1", 1},
		{"nonce_max_valid", MaxNonce},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			auth := SetCodeAuthorization{
				Address: TestAddresses.AAAA,
				Nonce:   tc.nonce,
			}

			// Use structural verification (no signature needed)
			result := VerifyAuthorizationWithOptions(&auth, chainID, false)

			if !result.Valid {
				t.Errorf("VerifyAuthorization() should accept valid nonce %d, error: %s", tc.nonce, result.ErrorMessage)
			}
			if !result.NonceValid {
				t.Errorf("VerifyAuthorization() NonceValid should be true for nonce %d", tc.nonce)
			}
		})
	}
}

// TestVerifySetCodeTx_SkipInvalidTuples tests EIP-7702 invalid tuple skipping behavior
func TestVerifySetCodeTx_SkipInvalidTuples(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)
	chainIDUint := uint256.MustFromBig(chainID)

	// Create a valid signed authorization
	validAuth := SetCodeAuthorization{
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}
	validAuth.ChainID = *chainIDUint
	signedValidAuth, _ := SignSetCode(key, validAuth)

	// Create an invalid authorization (wrong chain ID)
	invalidAuth := SetCodeAuthorization{
		ChainID: *uint256.NewInt(999), // Wrong chain ID
		Address: TestAddresses.BBBB,
		Nonce:   0,
	}
	signedInvalidAuth, _ := SignSetCode(key, invalidAuth)

	t.Run("skip_one_invalid_tuple", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedInvalidAuth, signedValidAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid when at least one auth is valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 1 {
			t.Errorf("ValidAuthCount = %d, want 1", result.ValidAuthCount)
		}
		if result.SkippedAuthCount != 1 {
			t.Errorf("SkippedAuthCount = %d, want 1", result.SkippedAuthCount)
		}
		if len(result.SkippedAuthIndices) != 1 || result.SkippedAuthIndices[0] != 0 {
			t.Errorf("SkippedAuthIndices = %v, want [0]", result.SkippedAuthIndices)
		}
		t.Logf("Correctly skipped invalid tuple at index 0, valid count: %d", result.ValidAuthCount)
	})

	t.Run("skip_multiple_invalid_tuples", func(t *testing.T) {
		// Create another invalid auth with high s value
		invalidAuthHighS := signedValidAuth
		highS := new(uint256.Int).Add(Secp256k1HalfN, uint256.NewInt(1))
		invalidAuthHighS.S = *highS

		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedInvalidAuth, invalidAuthHighS, signedValidAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid when at least one auth is valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 1 {
			t.Errorf("ValidAuthCount = %d, want 1", result.ValidAuthCount)
		}
		if result.SkippedAuthCount != 2 {
			t.Errorf("SkippedAuthCount = %d, want 2", result.SkippedAuthCount)
		}
		t.Logf("Correctly skipped %d invalid tuples", result.SkippedAuthCount)
	})

	t.Run("all_tuples_invalid", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedInvalidAuth},
		}

		result := VerifySetCodeTx(tx, chainID)

		if result.Valid {
			t.Error("VerifySetCodeTx() should fail when all auths are invalid")
		}
		if result.ValidAuthCount != 0 {
			t.Errorf("ValidAuthCount = %d, want 0", result.ValidAuthCount)
		}
		if result.SkippedAuthCount != 1 {
			t.Errorf("SkippedAuthCount = %d, want 1", result.SkippedAuthCount)
		}
		if result.ErrorMessage != "all authorization tuples are invalid" {
			t.Errorf("ErrorMessage = %s, want 'all authorization tuples are invalid'", result.ErrorMessage)
		}
		t.Logf("Correctly rejected: %s", result.ErrorMessage)
	})

	t.Run("all_tuples_valid", func(t *testing.T) {
		// Create second valid auth
		validAuth2 := SetCodeAuthorization{
			Address: TestAddresses.BBBB,
			Nonce:   0,
		}
		validAuth2.ChainID = *chainIDUint
		signedValidAuth2, _ := SignSetCode(key, validAuth2)

		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedValidAuth, signedValidAuth2},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 2 {
			t.Errorf("ValidAuthCount = %d, want 2", result.ValidAuthCount)
		}
		if result.SkippedAuthCount != 0 {
			t.Errorf("SkippedAuthCount = %d, want 0", result.SkippedAuthCount)
		}
		if len(result.SkippedAuthIndices) != 0 {
			t.Errorf("SkippedAuthIndices = %v, want []", result.SkippedAuthIndices)
		}
	})
}

// TestVerifySetCodeTx_DuplicateAuthority tests EIP-7702 duplicate authority handling
func TestVerifySetCodeTx_DuplicateAuthority(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)
	chainIDUint := uint256.MustFromBig(chainID)

	// Same authority will sign multiple authorizations
	authority := crypto.PubkeyToAddress(key.PublicKey)

	// Create first authorization for authority (target: AAAA)
	auth1 := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}
	signedAuth1, _ := SignSetCode(key, auth1)

	// Create second authorization for same authority (target: BBBB)
	auth2 := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: TestAddresses.BBBB,
		Nonce:   1,
	}
	signedAuth2, _ := SignSetCode(key, auth2)

	// Create third authorization for same authority (target: Simple)
	auth3 := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: TestAddresses.Simple,
		Nonce:   2,
	}
	signedAuth3, _ := SignSetCode(key, auth3)

	t.Run("duplicate_authority_last_wins", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth1, signedAuth2},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 2 {
			t.Errorf("ValidAuthCount = %d, want 2", result.ValidAuthCount)
		}
		if result.EffectiveAuthCount != 1 {
			t.Errorf("EffectiveAuthCount = %d, want 1 (duplicate authority)", result.EffectiveAuthCount)
		}
		if len(result.DuplicateAuthorities) != 1 {
			t.Errorf("DuplicateAuthorities length = %d, want 1", len(result.DuplicateAuthorities))
		}
		if len(result.DuplicateAuthorities) > 0 && result.DuplicateAuthorities[0] != authority {
			t.Errorf("DuplicateAuthorities[0] = %s, want %s", result.DuplicateAuthorities[0].Hex(), authority.Hex())
		}
		// Last tuple (index 1) should be the final one
		if finalIdx, exists := result.FinalAuthorityMap[authority]; !exists || finalIdx != 1 {
			t.Errorf("FinalAuthorityMap[authority] = %d, want 1", finalIdx)
		}
		// First tuple (index 0) should be overridden
		if len(result.OverriddenAuthIndices) != 1 || result.OverriddenAuthIndices[0] != 0 {
			t.Errorf("OverriddenAuthIndices = %v, want [0]", result.OverriddenAuthIndices)
		}
		t.Logf("Correctly handled duplicate authority: effective=%d, overridden=%v",
			result.EffectiveAuthCount, result.OverriddenAuthIndices)
	})

	t.Run("triple_duplicate_authority", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth1, signedAuth2, signedAuth3},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 3 {
			t.Errorf("ValidAuthCount = %d, want 3", result.ValidAuthCount)
		}
		if result.EffectiveAuthCount != 1 {
			t.Errorf("EffectiveAuthCount = %d, want 1 (same authority 3 times)", result.EffectiveAuthCount)
		}
		// Last tuple (index 2) should be the final one
		if finalIdx, exists := result.FinalAuthorityMap[authority]; !exists || finalIdx != 2 {
			t.Errorf("FinalAuthorityMap[authority] = %d, want 2", finalIdx)
		}
		// First two tuples (index 0, 1) should be overridden
		if len(result.OverriddenAuthIndices) != 2 {
			t.Errorf("OverriddenAuthIndices length = %d, want 2", len(result.OverriddenAuthIndices))
		}
		t.Logf("Correctly handled triple duplicate: final index=%d, overridden=%v",
			result.FinalAuthorityMap[authority], result.OverriddenAuthIndices)
	})

	t.Run("no_duplicate_different_keys", func(t *testing.T) {
		// Use second key for different authority
		key2, _ := crypto.HexToECDSA(TestPrivateKeys[1])
		authority2 := crypto.PubkeyToAddress(key2.PublicKey)

		auth2DiffKey := SetCodeAuthorization{
			ChainID: *chainIDUint,
			Address: TestAddresses.BBBB,
			Nonce:   0,
		}
		signedAuth2DiffKey, _ := SignSetCode(key2, auth2DiffKey)

		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth1, signedAuth2DiffKey},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 2 {
			t.Errorf("ValidAuthCount = %d, want 2", result.ValidAuthCount)
		}
		if result.EffectiveAuthCount != 2 {
			t.Errorf("EffectiveAuthCount = %d, want 2 (different authorities)", result.EffectiveAuthCount)
		}
		if len(result.DuplicateAuthorities) != 0 {
			t.Errorf("DuplicateAuthorities = %v, want empty", result.DuplicateAuthorities)
		}
		if len(result.OverriddenAuthIndices) != 0 {
			t.Errorf("OverriddenAuthIndices = %v, want empty", result.OverriddenAuthIndices)
		}
		// Both authorities should be in the map
		if _, exists := result.FinalAuthorityMap[authority]; !exists {
			t.Error("FinalAuthorityMap should contain first authority")
		}
		if _, exists := result.FinalAuthorityMap[authority2]; !exists {
			t.Error("FinalAuthorityMap should contain second authority")
		}
		t.Logf("Correctly handled different authorities: effective=%d", result.EffectiveAuthCount)
	})

	t.Run("duplicate_with_invalid_in_between", func(t *testing.T) {
		// Create an invalid authorization (wrong chain ID)
		invalidAuth := SetCodeAuthorization{
			ChainID: *uint256.NewInt(999),
			Address: TestAddresses.AA,
			Nonce:   0,
		}
		signedInvalidAuth, _ := SignSetCode(key, invalidAuth)

		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedAuth1, signedInvalidAuth, signedAuth2},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.ValidAuthCount != 2 {
			t.Errorf("ValidAuthCount = %d, want 2", result.ValidAuthCount)
		}
		if result.SkippedAuthCount != 1 {
			t.Errorf("SkippedAuthCount = %d, want 1", result.SkippedAuthCount)
		}
		if result.EffectiveAuthCount != 1 {
			t.Errorf("EffectiveAuthCount = %d, want 1", result.EffectiveAuthCount)
		}
		// Last valid tuple (index 2) should be final
		if finalIdx, exists := result.FinalAuthorityMap[authority]; !exists || finalIdx != 2 {
			t.Errorf("FinalAuthorityMap[authority] = %d, want 2", finalIdx)
		}
		t.Logf("Correctly handled duplicate with invalid in between: skipped=%d, effective=%d",
			result.SkippedAuthCount, result.EffectiveAuthCount)
	})
}

// TestSetCodeAuthorizationIsRevocation tests the IsRevocation() method
func TestSetCodeAuthorizationIsRevocation(t *testing.T) {
	testCases := []struct {
		name         string
		address      common.Address
		expectRevoke bool
		description  string
	}{
		{
			name:         "zero_address_is_revocation",
			address:      common.Address{},
			expectRevoke: true,
			description:  "Zero address (0x0) should be detected as revocation",
		},
		{
			name:         "non_zero_address_not_revocation",
			address:      TestAddresses.AAAA,
			expectRevoke: false,
			description:  "Non-zero address should not be revocation",
		},
		{
			name:         "simple_address_not_revocation",
			address:      TestAddresses.Simple,
			expectRevoke: false,
			description:  "Simple test address should not be revocation",
		},
		{
			name:         "all_zeros_explicit",
			address:      common.HexToAddress("0x0000000000000000000000000000000000000000"),
			expectRevoke: true,
			description:  "Explicit zero address should be revocation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			auth := SetCodeAuthorization{
				Address: tc.address,
				Nonce:   0,
			}

			result := auth.IsRevocation()
			if result != tc.expectRevoke {
				t.Errorf("IsRevocation() = %v, want %v for %s", result, tc.expectRevoke, tc.description)
			}
		})
	}
}

// TestSetCodeAuthorizationIsWildcardChain tests the IsWildcardChain() method
func TestSetCodeAuthorizationIsWildcardChain(t *testing.T) {
	testCases := []struct {
		name           string
		chainID        *uint256.Int
		expectWildcard bool
		description    string
	}{
		{
			name:           "zero_chainid_is_wildcard",
			chainID:        uint256.NewInt(0),
			expectWildcard: true,
			description:    "ChainID 0 should be wildcard",
		},
		{
			name:           "chainid_1_not_wildcard",
			chainID:        uint256.NewInt(1),
			expectWildcard: false,
			description:    "ChainID 1 (mainnet) should not be wildcard",
		},
		{
			name:           "chainid_large_not_wildcard",
			chainID:        uint256.NewInt(31337),
			expectWildcard: false,
			description:    "Large ChainID should not be wildcard",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			auth := SetCodeAuthorization{
				ChainID: *tc.chainID,
				Address: TestAddresses.AAAA,
				Nonce:   0,
			}

			result := auth.IsWildcardChain()
			if result != tc.expectWildcard {
				t.Errorf("IsWildcardChain() = %v, want %v for %s", result, tc.expectWildcard, tc.description)
			}
		})
	}
}

// TestVerifyAuthorizationRevocation tests revocation detection in authorization verification
func TestVerifyAuthorizationRevocation(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)
	chainIDUint := uint256.MustFromBig(chainID)

	t.Run("revocation_authorization", func(t *testing.T) {
		// Create a revocation authorization (Address = 0x0)
		auth := SetCodeAuthorization{
			ChainID: *chainIDUint,
			Address: common.Address{}, // Zero address = revocation
			Nonce:   0,
		}
		signedAuth, _ := SignSetCode(key, auth)

		result := VerifyAuthorization(&signedAuth, chainID)

		if !result.Valid {
			t.Errorf("VerifyAuthorization() should be valid for revocation, error: %s", result.ErrorMessage)
		}
		if !result.IsRevocation {
			t.Error("IsRevocation should be true for zero address")
		}
		if result.TargetAddress != (common.Address{}) {
			t.Errorf("TargetAddress = %s, want zero address", result.TargetAddress.Hex())
		}
		t.Logf("Correctly detected revocation authorization")
	})

	t.Run("delegation_authorization", func(t *testing.T) {
		// Create a normal delegation authorization
		auth := SetCodeAuthorization{
			ChainID: *chainIDUint,
			Address: TestAddresses.AAAA, // Non-zero = delegation
			Nonce:   0,
		}
		signedAuth, _ := SignSetCode(key, auth)

		result := VerifyAuthorization(&signedAuth, chainID)

		if !result.Valid {
			t.Errorf("VerifyAuthorization() should be valid for delegation, error: %s", result.ErrorMessage)
		}
		if result.IsRevocation {
			t.Error("IsRevocation should be false for non-zero address")
		}
		if result.TargetAddress != TestAddresses.AAAA {
			t.Errorf("TargetAddress = %s, want %s", result.TargetAddress.Hex(), TestAddresses.AAAA.Hex())
		}
		t.Logf("Correctly detected delegation authorization to %s", result.TargetAddress.Hex())
	})

	t.Run("unsigned_revocation", func(t *testing.T) {
		// Create an unsigned revocation authorization
		auth := SetCodeAuthorization{
			ChainID: *chainIDUint,
			Address: common.Address{}, // Zero address = revocation
			Nonce:   0,
		}

		// Use structural verification (no signature)
		result := VerifyAuthorizationWithOptions(&auth, chainID, false)

		if !result.Valid {
			t.Errorf("VerifyAuthorizationWithOptions() should be valid for unsigned revocation, error: %s", result.ErrorMessage)
		}
		if !result.IsRevocation {
			t.Error("IsRevocation should be true for zero address (unsigned)")
		}
		t.Logf("Correctly detected unsigned revocation authorization")
	})
}

// TestVerifySetCodeTx_RevocationTracking tests revocation tracking in transaction verification
func TestVerifySetCodeTx_RevocationTracking(t *testing.T) {
	key, _ := crypto.HexToECDSA(TestPrivateKeys[0])
	chainID := big.NewInt(1)
	chainIDUint := uint256.MustFromBig(chainID)

	// Create a delegation authorization (non-zero address)
	delegationAuth := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: TestAddresses.AAAA,
		Nonce:   0,
	}
	signedDelegation, _ := SignSetCode(key, delegationAuth)

	// Create a revocation authorization (zero address)
	revocationAuth := SetCodeAuthorization{
		ChainID: *chainIDUint,
		Address: common.Address{}, // Zero address = revocation
		Nonce:   1,
	}
	signedRevocation, _ := SignSetCode(key, revocationAuth)

	t.Run("single_delegation", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedDelegation},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.RevocationCount != 0 {
			t.Errorf("RevocationCount = %d, want 0", result.RevocationCount)
		}
		if result.DelegationCount != 1 {
			t.Errorf("DelegationCount = %d, want 1", result.DelegationCount)
		}
		if len(result.DelegationTargets) != 1 {
			t.Errorf("DelegationTargets length = %d, want 1", len(result.DelegationTargets))
		}
		if len(result.DelegationTargets) > 0 && result.DelegationTargets[0] != TestAddresses.AAAA {
			t.Errorf("DelegationTargets[0] = %s, want %s", result.DelegationTargets[0].Hex(), TestAddresses.AAAA.Hex())
		}
		t.Logf("Single delegation: count=%d, targets=%v", result.DelegationCount, result.DelegationTargets)
	})

	t.Run("single_revocation", func(t *testing.T) {
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedRevocation},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.RevocationCount != 1 {
			t.Errorf("RevocationCount = %d, want 1", result.RevocationCount)
		}
		if result.DelegationCount != 0 {
			t.Errorf("DelegationCount = %d, want 0", result.DelegationCount)
		}
		if len(result.RevocationIndices) != 1 || result.RevocationIndices[0] != 0 {
			t.Errorf("RevocationIndices = %v, want [0]", result.RevocationIndices)
		}
		t.Logf("Single revocation: count=%d, indices=%v", result.RevocationCount, result.RevocationIndices)
	})

	t.Run("mixed_delegation_and_revocation", func(t *testing.T) {
		// Use second key for different authority
		key2, _ := crypto.HexToECDSA(TestPrivateKeys[1])

		// Create second delegation authorization
		delegationAuth2 := SetCodeAuthorization{
			ChainID: *chainIDUint,
			Address: TestAddresses.BBBB,
			Nonce:   0,
		}
		signedDelegation2, _ := SignSetCode(key2, delegationAuth2)

		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedDelegation, signedRevocation, signedDelegation2},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		// Note: signedDelegation and signedRevocation are from same key, so there's duplicate handling
		// The effective counts depend on which are from same authority
		if result.RevocationCount < 1 {
			t.Errorf("RevocationCount = %d, want >= 1", result.RevocationCount)
		}
		if result.DelegationCount < 1 {
			t.Errorf("DelegationCount = %d, want >= 1", result.DelegationCount)
		}
		if len(result.RevocationIndices) < 1 {
			t.Errorf("RevocationIndices length = %d, want >= 1", len(result.RevocationIndices))
		}
		t.Logf("Mixed: delegations=%d, revocations=%d, indices=%v, targets=%v",
			result.DelegationCount, result.RevocationCount, result.RevocationIndices, result.DelegationTargets)
	})

	t.Run("multiple_revocations", func(t *testing.T) {
		// Use second key for different authority
		key2, _ := crypto.HexToECDSA(TestPrivateKeys[1])

		// Create second revocation authorization
		revocationAuth2 := SetCodeAuthorization{
			ChainID: *chainIDUint,
			Address: common.Address{}, // Zero address = revocation
			Nonce:   0,
		}
		signedRevocation2, _ := SignSetCode(key2, revocationAuth2)

		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedRevocation, signedRevocation2},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		if result.RevocationCount != 2 {
			t.Errorf("RevocationCount = %d, want 2", result.RevocationCount)
		}
		if result.DelegationCount != 0 {
			t.Errorf("DelegationCount = %d, want 0", result.DelegationCount)
		}
		if len(result.RevocationIndices) != 2 {
			t.Errorf("RevocationIndices length = %d, want 2", len(result.RevocationIndices))
		}
		t.Logf("Multiple revocations: count=%d, indices=%v", result.RevocationCount, result.RevocationIndices)
	})

	t.Run("delegation_then_revocation_same_authority", func(t *testing.T) {
		// First delegate, then revoke (same authority)
		// This tests the scenario where an EOA delegates then revokes in same tx
		tx := &SetCodeTx{
			Type:     SetCodeTxType,
			ChainID:  *chainIDUint,
			Nonce:    0,
			Gas:      500000,
			To:       &TestAddresses.Simple,
			AuthList: []SetCodeAuthorization{signedDelegation, signedRevocation},
		}

		result := VerifySetCodeTx(tx, chainID)

		if !result.Valid {
			t.Errorf("VerifySetCodeTx() should be valid, error: %s", result.ErrorMessage)
		}
		// Both are valid, but from same authority (duplicate handling)
		if result.ValidAuthCount != 2 {
			t.Errorf("ValidAuthCount = %d, want 2", result.ValidAuthCount)
		}
		if result.EffectiveAuthCount != 1 {
			t.Errorf("EffectiveAuthCount = %d, want 1 (same authority)", result.EffectiveAuthCount)
		}
		// The last one (revocation at index 1) should be the final action
		if len(result.DuplicateAuthorities) != 1 {
			t.Errorf("DuplicateAuthorities length = %d, want 1", len(result.DuplicateAuthorities))
		}
		// Count should reflect both tuples
		if result.RevocationCount != 1 {
			t.Errorf("RevocationCount = %d, want 1", result.RevocationCount)
		}
		if result.DelegationCount != 1 {
			t.Errorf("DelegationCount = %d, want 1", result.DelegationCount)
		}
		t.Logf("Delegate then revoke: effective=%d, delegations=%d, revocations=%d, overridden=%v",
			result.EffectiveAuthCount, result.DelegationCount, result.RevocationCount, result.OverriddenAuthIndices)
	})
}
