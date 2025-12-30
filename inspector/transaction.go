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
	Type       uint8 // Transaction type (must be 0x04 for EIP-7702)
	ChainID    uint256.Int
	Nonce      uint64
	GasTipCap  uint256.Int
	GasFeeCap  uint256.Int
	Gas        uint64
	To         *common.Address // Pointer: nil means contract creation (not allowed in EIP-7702)
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
	// Transaction type validation
	TxTypeValid        bool   // True if Type == 0x04 (SetCodeTxType)
	TxType             uint8  // The actual transaction type
	HasAuthList        bool
	AuthListLength     int
	GasValid           bool
	ExpectedIntrinsic  uint64
	ToFieldValid       bool
	ChainIDValid       bool
	AuthVerifications  []*AuthorizationVerificationResult
	// EIP-7702 tuple processing results
	ValidAuthCount     int   // Number of valid authorizations
	SkippedAuthCount   int   // Number of skipped (invalid) authorizations
	SkippedAuthIndices []int // Indices of skipped authorizations
	// EIP-7702 duplicate authority handling
	DuplicateAuthorities    []common.Address          // Authorities that appear multiple times
	FinalAuthorityMap       map[common.Address]int    // Maps authority to final (last valid) tuple index
	OverriddenAuthIndices   []int                     // Indices of tuples overridden by later tuples
	EffectiveAuthCount      int                       // Number of unique authorities after deduplication
	// EIP-7702 destination validation
	IsContractCreation bool // True if To is nil (contract creation attempt - not allowed)
	IsZeroAddress      bool // True if To is zero address (0x0...0)
	// EIP-7702 delegation revocation
	RevocationCount    int              // Number of revocation authorizations (Address == 0x0)
	RevocationIndices  []int            // Indices of revocation authorizations
	DelegationCount    int              // Number of delegation authorizations (Address != 0x0)
	DelegationTargets  []common.Address // Target addresses for delegations
}

// AuthorityResult contains the processing result for a single authority
type AuthorityResult struct {
	Authority       common.Address
	FinalTupleIndex int  // Index of the last valid tuple for this authority
	TupleIndices    []int // All tuple indices for this authority
	WasOverridden   bool  // True if earlier tuples were overridden
}

// VerifySetCodeTx verifies an EIP-7702 SetCode transaction
func VerifySetCodeTx(tx *SetCodeTx, expectedChainID *big.Int) *SetCodeTxVerificationResult {
	result := &SetCodeTxVerificationResult{}

	// Store the transaction type in the result
	result.TxType = tx.Type

	// EIP-7702: Validate transaction type (must be 0x04)
	if errMsg := ValidateTxTypeValue(tx.Type); errMsg != "" {
		result.ErrorMessage = errMsg
		result.TxTypeValid = false
		return result
	}
	result.TxTypeValid = true

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

	// EIP-7702: To field must not be nil (contract creation not allowed)
	if tx.To == nil {
		result.IsContractCreation = true
		result.ToFieldValid = false
		result.ErrorMessage = "EIP-7702 transaction cannot create contracts (To field is nil)"
		return result
	}
	result.ToFieldValid = true

	// Check if To is zero address (valid but noteworthy)
	if *tx.To == (common.Address{}) {
		result.IsZeroAddress = true
		// Zero address is valid for SetCode tx (not contract creation, just zero recipient)
	}

	// Calculate expected intrinsic gas
	result.ExpectedIntrinsic = CalculateIntrinsicGas(tx)
	result.GasValid = tx.Gas >= result.ExpectedIntrinsic

	// Verify each authorization (EIP-7702: skip invalid tuples, continue with next)
	result.AuthVerifications = make([]*AuthorizationVerificationResult, len(tx.AuthList))
	result.SkippedAuthIndices = make([]int, 0)
	result.FinalAuthorityMap = make(map[common.Address]int)
	result.OverriddenAuthIndices = make([]int, 0)
	result.DuplicateAuthorities = make([]common.Address, 0)
	result.RevocationIndices = make([]int, 0)
	result.DelegationTargets = make([]common.Address, 0)

	// Track the previous valid tuple index per authority for duplicate detection
	lastValidTupleForAuthority := make(map[common.Address]int)
	duplicateSet := make(map[common.Address]bool)

	for i := range tx.AuthList {
		result.AuthVerifications[i] = VerifyAuthorization(&tx.AuthList[i], expectedChainID)
		if !result.AuthVerifications[i].Valid {
			// EIP-7702: Skip invalid tuple and continue with next
			result.SkippedAuthCount++
			result.SkippedAuthIndices = append(result.SkippedAuthIndices, i)
		} else {
			result.ValidAuthCount++
			authority := result.AuthVerifications[i].RecoveredAuthority

			// Track revocation vs delegation
			if result.AuthVerifications[i].IsRevocation {
				result.RevocationCount++
				result.RevocationIndices = append(result.RevocationIndices, i)
			} else {
				result.DelegationCount++
				result.DelegationTargets = append(result.DelegationTargets, result.AuthVerifications[i].TargetAddress)
			}

			// Check if this authority has appeared before
			if prevIdx, exists := lastValidTupleForAuthority[authority]; exists {
				// This authority has appeared before - mark as duplicate
				if !duplicateSet[authority] {
					duplicateSet[authority] = true
					result.DuplicateAuthorities = append(result.DuplicateAuthorities, authority)
				}
				// Previous tuple will be overridden by this one
				result.OverriddenAuthIndices = append(result.OverriddenAuthIndices, prevIdx)
			}

			// Update last valid tuple for this authority (last valid tuple wins per EIP-7702)
			lastValidTupleForAuthority[authority] = i
			result.FinalAuthorityMap[authority] = i
		}
	}

	// Calculate effective auth count (unique authorities after deduplication)
	result.EffectiveAuthCount = len(result.FinalAuthorityMap)

	// Transaction is valid if at least one authorization is valid
	// Note: Empty auth list is already rejected above
	if result.ValidAuthCount == 0 {
		result.ErrorMessage = "all authorization tuples are invalid"
		result.Valid = false
		return result
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
				Type:      SetCodeTxType,
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(1),
				GasFeeCap: *uint256.NewInt(875000000),
				Gas:       50000,
				To:        &TestAddresses.Simple,
				AuthList:  []SetCodeAuthorization{}, // Empty
			},
			ExpectValid:   false,
			ExpectedError: "EIP-7702 transaction with empty auth list",
			Description:   "SetCode tx with empty authorization list should fail",
		},
		{
			Name: "valid_single_auth",
			Tx: &SetCodeTx{
				Type:      SetCodeTxType,
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(2),
				GasFeeCap: *uint256.NewInt(1000),
				Gas:       500000,
				To:        &TestAddresses.AAAA,
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
				Type:      SetCodeTxType,
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(2),
				GasFeeCap: *uint256.NewInt(1000),
				Gas:       500000,
				To:        &TestAddresses.AAAA,
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
				Type:      SetCodeTxType,
				ChainID:   *chainIDUint,
				Nonce:     0,
				GasTipCap: *uint256.NewInt(1),
				GasFeeCap: *uint256.NewInt(875000000),
				Gas:       21000, // Too low for auth list
				To:        &TestAddresses.Simple,
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
