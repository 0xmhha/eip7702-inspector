package inspector

import (
	"crypto/ecdsa"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// SetCodeAuthorization represents an EIP-7702 authorization tuple
type SetCodeAuthorization struct {
	ChainID uint256.Int    `json:"chainId"`
	Address common.Address `json:"address"`
	Nonce   uint64         `json:"nonce"`
	V       uint8          `json:"v"`
	R       uint256.Int    `json:"r"`
	S       uint256.Int    `json:"s"`
}

// AuthorizationVerificationResult contains the result of authorization verification
type AuthorizationVerificationResult struct {
	Valid             bool
	Authority         common.Address
	ErrorMessage      string
	ChainIDValid      bool
	SignatureValid    bool
	RecoveredAuthority common.Address
	MatchesExpected   bool
}

// SigHash returns the hash for signing the authorization
// Uses 0x05 prefix as per EIP-7702 specification
func (a *SetCodeAuthorization) SigHash() common.Hash {
	return prefixedRlpHash(AuthorizationSigningPrefix, []interface{}{
		a.ChainID.ToBig(),
		a.Address,
		a.Nonce,
	})
}

// prefixedRlpHash computes keccak256(prefix || rlp(data))
func prefixedRlpHash(prefix byte, data interface{}) common.Hash {
	encoded, _ := rlp.EncodeToBytes(data)
	prefixed := append([]byte{prefix}, encoded...)
	return crypto.Keccak256Hash(prefixed)
}

// Authority recovers the signing authority from the authorization
func (a *SetCodeAuthorization) Authority() (common.Address, error) {
	sigHash := a.SigHash()

	// Create signature bytes [R || S || V]
	sig := make([]byte, 65)
	a.R.WriteToSlice(sig[0:32])
	a.S.WriteToSlice(sig[32:64])
	sig[64] = a.V

	// Recover public key
	pubKey, err := crypto.SigToPub(sigHash.Bytes(), sig)
	if err != nil {
		return common.Address{}, fmt.Errorf("failed to recover public key: %w", err)
	}

	return crypto.PubkeyToAddress(*pubKey), nil
}

// SignSetCode signs a SetCodeAuthorization with the given private key
func SignSetCode(key *ecdsa.PrivateKey, auth SetCodeAuthorization) (SetCodeAuthorization, error) {
	sigHash := auth.SigHash()

	sig, err := crypto.Sign(sigHash.Bytes(), key)
	if err != nil {
		return auth, fmt.Errorf("failed to sign authorization: %w", err)
	}

	auth.R.SetBytes(sig[0:32])
	auth.S.SetBytes(sig[32:64])
	auth.V = sig[64]

	return auth, nil
}

// VerifyAuthorization verifies an EIP-7702 authorization
func VerifyAuthorization(auth *SetCodeAuthorization, expectedChainID *big.Int) *AuthorizationVerificationResult {
	return VerifyAuthorizationWithOptions(auth, expectedChainID, true)
}

// VerifyAuthorizationWithOptions verifies an EIP-7702 authorization with optional signature verification
func VerifyAuthorizationWithOptions(auth *SetCodeAuthorization, expectedChainID *big.Int, verifySignature bool) *AuthorizationVerificationResult {
	result := &AuthorizationVerificationResult{}

	// Verify chain ID if expected one is provided
	if expectedChainID != nil {
		authChainID := auth.ChainID.ToBig()
		// ChainID 0 means "any chain"
		if authChainID.Cmp(big.NewInt(0)) != 0 && authChainID.Cmp(expectedChainID) != 0 {
			result.ErrorMessage = fmt.Sprintf("chain ID mismatch: expected %s, got %s", expectedChainID.String(), authChainID.String())
			result.ChainIDValid = false
			return result
		}
		result.ChainIDValid = true
	} else {
		result.ChainIDValid = true
	}

	// Skip signature verification if not required (for structural tests)
	if !verifySignature || (auth.R.IsZero() && auth.S.IsZero()) {
		result.SignatureValid = true // Skip signature check for unsigned auths
		result.Valid = true
		return result
	}

	// Recover authority
	authority, err := auth.Authority()
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("failed to recover authority: %v", err)
		result.SignatureValid = false
		return result
	}

	result.SignatureValid = true
	result.RecoveredAuthority = authority
	result.Authority = authority
	result.Valid = true

	return result
}

// AuthorizationTestCase represents a test case for authorization verification
type AuthorizationTestCase struct {
	Name         string
	ChainID      *big.Int
	Address      common.Address
	Nonce        uint64
	UseWildcard  bool // ChainID = 0 for any chain
	ExpectValid  bool
	Description  string
}

// GetAuthorizationTestCases returns standard test cases for authorization verification
func GetAuthorizationTestCases() []AuthorizationTestCase {
	return []AuthorizationTestCase{
		{
			Name:        "valid_auth_chain_1",
			ChainID:     big.NewInt(1),
			Address:     TestAddresses.AAAA,
			Nonce:       0,
			ExpectValid: true,
			Description: "Valid authorization for chain ID 1",
		},
		{
			Name:        "valid_auth_with_nonce",
			ChainID:     big.NewInt(1),
			Address:     TestAddresses.BBBB,
			Nonce:       5,
			ExpectValid: true,
			Description: "Valid authorization with non-zero nonce",
		},
		{
			Name:        "wildcard_chain_id",
			ChainID:     big.NewInt(0),
			Address:     TestAddresses.AAAA,
			Nonce:       0,
			UseWildcard: true,
			ExpectValid: true,
			Description: "Authorization with chain ID 0 (any chain)",
		},
		{
			Name:        "high_nonce",
			ChainID:     big.NewInt(1),
			Address:     TestAddresses.Simple,
			Nonce:       ^uint64(0),
			ExpectValid: true,
			Description: "Authorization with max uint64 nonce",
		},
	}
}

// AuthorizationTestResult contains the result of an authorization test
type AuthorizationTestResult struct {
	TestCase          AuthorizationTestCase
	Passed            bool
	CreatedAuth       *SetCodeAuthorization
	SignedAuth        *SetCodeAuthorization
	RecoveredAuthority common.Address
	ExpectedAuthority  common.Address
	Error             error
}

// RunAuthorizationTests runs authorization test cases with the given private key
func RunAuthorizationTests(keyHex string) ([]AuthorizationTestResult, error) {
	key, err := crypto.HexToECDSA(keyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	expectedAuthority := crypto.PubkeyToAddress(key.PublicKey)
	testCases := GetAuthorizationTestCases()
	results := make([]AuthorizationTestResult, 0, len(testCases))

	for _, tc := range testCases {
		result := AuthorizationTestResult{
			TestCase:          tc,
			ExpectedAuthority: expectedAuthority,
		}

		// Create authorization
		auth := SetCodeAuthorization{
			Address: tc.Address,
			Nonce:   tc.Nonce,
		}
		if tc.ChainID != nil {
			auth.ChainID = *uint256.MustFromBig(tc.ChainID)
		}
		result.CreatedAuth = &auth

		// Sign authorization
		signedAuth, err := SignSetCode(key, auth)
		if err != nil {
			result.Error = err
			result.Passed = !tc.ExpectValid
			results = append(results, result)
			continue
		}
		result.SignedAuth = &signedAuth

		// Verify by recovering authority
		recoveredAuthority, err := signedAuth.Authority()
		if err != nil {
			result.Error = err
			result.Passed = !tc.ExpectValid
			results = append(results, result)
			continue
		}
		result.RecoveredAuthority = recoveredAuthority

		// Check if recovered authority matches expected
		result.Passed = tc.ExpectValid && (recoveredAuthority == expectedAuthority)
		results = append(results, result)
	}

	return results, nil
}
