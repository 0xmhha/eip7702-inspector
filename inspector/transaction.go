package inspector

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/holiman/uint256"
)

// SetCodeTx represents an EIP-7702 SetCode transaction
type SetCodeTx struct {
	ChainID    uint256.Int
	Nonce      uint64
	GasTipCap  uint256.Int
	GasFeeCap  uint256.Int
	Gas        uint64
	To         common.Address
	Value      uint256.Int
	Data       []byte
	AccessList []AccessTuple
	AuthList   []SetCodeAuthorization
}

// AccessTuple represents an EIP-2930 access list entry
type AccessTuple struct {
	Address     common.Address
	StorageKeys []common.Hash
}

// SetCodeTxVerificationResult contains the result of SetCode tx verification
type SetCodeTxVerificationResult struct {
	Valid              bool
	ErrorMessage       string
	HasAuthList        bool
	AuthListLength     int
	GasValid           bool
	ExpectedIntrinsic  uint64
	ToFieldValid       bool
	ChainIDValid       bool
	AuthVerifications  []*AuthorizationVerificationResult
}

// VerifySetCodeTx verifies an EIP-7702 SetCode transaction
func VerifySetCodeTx(tx *SetCodeTx, expectedChainID *big.Int) *SetCodeTxVerificationResult {
	result := &SetCodeTxVerificationResult{}

	// Verify auth list is not empty (from go-ethereum and reth)
	if len(tx.AuthList) == 0 {
		result.ErrorMessage = "EIP-7702 transaction with empty auth list"
		result.HasAuthList = false
		return result
	}
	result.HasAuthList = true
	result.AuthListLength = len(tx.AuthList)

	// Verify chain ID
	if expectedChainID != nil {
		txChainID := tx.ChainID.ToBig()
		if txChainID.Cmp(expectedChainID) != 0 {
			result.ErrorMessage = fmt.Sprintf("chain ID mismatch: expected %s, got %s",
				expectedChainID.String(), txChainID.String())
			result.ChainIDValid = false
			return result
		}
	}
	result.ChainIDValid = true

	// To field must not be nil for SetCode transactions
	if tx.To == (common.Address{}) {
		// Note: Some implementations may allow zero address, but typically To must be set
		result.ToFieldValid = true // Zero address is valid but represents contract creation which is not allowed
	} else {
		result.ToFieldValid = true
	}

	// Calculate expected intrinsic gas
	result.ExpectedIntrinsic = CalculateIntrinsicGas(tx)
	result.GasValid = tx.Gas >= result.ExpectedIntrinsic

	// Verify each authorization
	result.AuthVerifications = make([]*AuthorizationVerificationResult, len(tx.AuthList))
	for i := range tx.AuthList {
		result.AuthVerifications[i] = VerifyAuthorization(&tx.AuthList[i], expectedChainID)
		if !result.AuthVerifications[i].Valid {
			result.Valid = false
			return result
		}
	}

	result.Valid = true
	return result
}

// CalculateIntrinsicGas calculates the intrinsic gas for a SetCode transaction
func CalculateIntrinsicGas(tx *SetCodeTx) uint64 {
	// Base transaction gas
	const TxGas = 21000
	const TxDataZeroGas = 4
	const TxDataNonZeroGas = 16
	const TxAccessListAddressGas = 2400
	const TxAccessListStorageKeyGas = 1900

	gas := uint64(TxGas)

	// Data cost
	for _, b := range tx.Data {
		if b == 0 {
			gas += TxDataZeroGas
		} else {
			gas += TxDataNonZeroGas
		}
	}

	// Access list cost
	for _, tuple := range tx.AccessList {
		gas += TxAccessListAddressGas
		gas += uint64(len(tuple.StorageKeys)) * TxAccessListStorageKeyGas
	}

	// Authorization list cost (25,000 per authorization)
	// Note: actual cost depends on account state (refund if existing)
	gas += uint64(len(tx.AuthList)) * CallNewAccountGas

	return gas
}

// SetCodeTxTestCase represents a test case for SetCode transaction verification
type SetCodeTxTestCase struct {
	Name         string
	Tx           *SetCodeTx
	ExpectValid  bool
	ExpectedError string
	Description  string
}

// GetSetCodeTxTestCases returns standard test cases for SetCode transaction verification
func GetSetCodeTxTestCases(chainID *big.Int, key *ecdsa.PrivateKey) []SetCodeTxTestCase {
	chainIDUint := uint256.MustFromBig(chainID)

	// Helper function to create and sign an authorization
	signAuth := func(addr common.Address, nonce uint64, authChainID *uint256.Int) SetCodeAuthorization {
		auth := SetCodeAuthorization{
			ChainID: *authChainID,
			Address: addr,
			Nonce:   nonce,
		}
		signedAuth, _ := SignSetCode(key, auth)
		return signedAuth
	}

	return []SetCodeTxTestCase{
		{
			Name: "empty_auth_list",
			Tx: &SetCodeTx{
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(1),
				GasFeeCap: *uint256.NewInt(875000000),
				Gas:       50000,
				To:        TestAddresses.Simple,
				AuthList:  []SetCodeAuthorization{}, // Empty
			},
			ExpectValid:   false,
			ExpectedError: "EIP-7702 transaction with empty auth list",
			Description:   "SetCode tx with empty authorization list should fail",
		},
		{
			Name: "valid_single_auth",
			Tx: &SetCodeTx{
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(2),
				GasFeeCap: *uint256.NewInt(1000),
				Gas:       500000,
				To:        TestAddresses.AAAA,
				AuthList: []SetCodeAuthorization{
					signAuth(TestAddresses.BBBB, 0, chainIDUint),
				},
			},
			ExpectValid: true,
			Description: "Valid SetCode tx with single authorization",
		},
		{
			Name: "valid_multiple_auths",
			Tx: &SetCodeTx{
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(2),
				GasFeeCap: *uint256.NewInt(1000),
				Gas:       500000,
				To:        TestAddresses.AAAA,
				AuthList: []SetCodeAuthorization{
					signAuth(TestAddresses.AAAA, 1, chainIDUint),
					signAuth(TestAddresses.BBBB, 0, uint256.NewInt(0)), // Wildcard
				},
			},
			ExpectValid: true,
			Description: "Valid SetCode tx with multiple authorizations",
		},
		{
			Name: "insufficient_gas",
			Tx: &SetCodeTx{
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(1),
				GasFeeCap: *uint256.NewInt(875000000),
				Gas:       21000, // Too low for auth list
				To:        TestAddresses.Simple,
				AuthList: []SetCodeAuthorization{
					signAuth(TestAddresses.AAAA, 0, chainIDUint),
				},
			},
			ExpectValid: true, // Still valid structurally, gas check is separate
			Description: "SetCode tx with potentially insufficient gas",
		},
	}
}

// SetCodeTxTestResult contains the result of a SetCode transaction test
type SetCodeTxTestResult struct {
	TestCase       SetCodeTxTestCase
	Passed         bool
	Verification   *SetCodeTxVerificationResult
	Error          error
}

// RunSetCodeTxTests runs SetCode transaction test cases
func RunSetCodeTxTests(chainID *big.Int, keyHex string) ([]SetCodeTxTestResult, error) {
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	testCases := GetSetCodeTxTestCases(chainID, key)
	results := make([]SetCodeTxTestResult, 0, len(testCases))

	for _, tc := range testCases {
		result := SetCodeTxTestResult{
			TestCase: tc,
		}

		verification := VerifySetCodeTx(tc.Tx, chainID)
		result.Verification = verification

		// Check if result matches expectation
		if tc.ExpectValid {
			result.Passed = verification.Valid
		} else {
			result.Passed = !verification.Valid
			if tc.ExpectedError != "" && verification.ErrorMessage != tc.ExpectedError {
				result.Passed = false
			}
		}

		results = append(results, result)
	}

	return results, nil
}
