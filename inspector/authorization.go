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
	Valid              bool
	Authority          common.Address
	ErrorMessage       string
	ChainIDValid       bool
	SignatureValid     bool
	SValueValid        bool   // EIP-2: s <= secp256k1n/2
	YParityValid       bool   // EIP-7702: v must be 0 or 1
	NonceValid         bool   // EIP-7702: nonce < 2^64 - 1
	RecoveredAuthority common.Address
	MatchesExpected    bool
	// EIP-7702 delegation revocation
	IsRevocation       bool           // True if Address == 0x0 (delegation revocation)
	TargetAddress      common.Address // The target delegation address
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

// IsRevocation returns true if this authorization is a delegation revocation
// A revocation sets the Address field to the zero address (0x0...0)
// This clears any existing delegation from the authority's account
func (a *SetCodeAuthorization) IsRevocation() bool {
	return a.Address == (common.Address{})
}

// IsWildcardChain returns true if this authorization uses chainId = 0
// Wildcard chain authorizations can be replayed on any EVM chain
func (a *SetCodeAuthorization) IsWildcardChain() bool {
	return a.ChainID.IsZero()
}

// prefixedRlpHash computes keccak256(prefix || rlp(data))
func prefixedRlpHash(prefix byte, data interface{}) common.Hash {
	encoded, _ := rlp.EncodeToBytes(data)
	prefixed := append([]byte{prefix}, encoded...)
	return crypto.Keccak256Hash(prefixed)
}

// ValidateSignatureS validates that s <= secp256k1n/2 (EIP-2 compliance)
// This prevents signature malleability attacks
func ValidateSignatureS(s *uint256.Int) bool {
	if s == nil {
		return false
	}
	// s must be <= secp256k1n/2
	return s.Cmp(Secp256k1HalfN) <= 0
}

// ValidateSignatureSValue checks if the s value is in the lower half of the curve order
// Returns an error message if invalid, empty string if valid
func ValidateSignatureSValue(s *uint256.Int) string {
	if s == nil {
		return "s value is nil"
	}
	if s.IsZero() {
		return "s value is zero"
	}
	if s.Cmp(Secp256k1HalfN) > 0 {
		return fmt.Sprintf("s value too high: must be <= secp256k1n/2 (EIP-2), got %s", s.Hex())
	}
	return ""
}

// ValidateYParity validates that y_parity (v) is 0 or 1
// EIP-7702 requires y_parity to be exactly 0 or 1
func ValidateYParity(v uint8) bool {
	return v == 0 || v == 1
}

// ValidateYParityValue checks if the y_parity value is valid
// Returns an error message if invalid, empty string if valid
func ValidateYParityValue(v uint8) string {
	if v != 0 && v != 1 {
		return fmt.Sprintf("invalid y_parity: must be 0 or 1, got %d", v)
	}
	return ""
}

// MaxNonce is the maximum valid nonce value (2^64 - 2)
// EIP-7702 requires nonce < 2^64 - 1, so max valid nonce is 2^64 - 2
const MaxNonce = ^uint64(0) - 1

// ValidateNonce validates that nonce < 2^64 - 1
// EIP-7702 requires nonce to be strictly less than 2^64 - 1
func ValidateNonce(nonce uint64) bool {
	return nonce < ^uint64(0)
}

// ValidateNonceValue checks if the nonce value is valid
// Returns an error message if invalid, empty string if valid
func ValidateNonceValue(nonce uint64) string {
	if nonce >= ^uint64(0) {
		return fmt.Sprintf("nonce too high: must be < 2^64-1, got %d", nonce)
	}
	return ""
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

	// Store target address and detect revocation
	result.TargetAddress = auth.Address
	result.IsRevocation = auth.IsRevocation()

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

	// EIP-7702: Validate nonce < 2^64 - 1
	if errMsg := ValidateNonceValue(auth.Nonce); errMsg != "" {
		result.ErrorMessage = errMsg
		result.NonceValid = false
		return result
	}
	result.NonceValid = true

	// Skip signature verification if not required (for structural tests)
	if !verifySignature || (auth.R.IsZero() && auth.S.IsZero()) {
		result.SignatureValid = true // Skip signature check for unsigned auths
		result.SValueValid = true    // Skip s value check for unsigned auths
		result.YParityValid = true   // Skip y_parity check for unsigned auths
		result.Valid = true
		return result
	}

	// EIP-7702: Validate y_parity (v) is 0 or 1
	if errMsg := ValidateYParityValue(auth.V); errMsg != "" {
		result.ErrorMessage = errMsg
		result.YParityValid = false
		return result
	}
	result.YParityValid = true

	// EIP-2: Validate s value is in lower half of curve order
	// This prevents signature malleability attacks
	if errMsg := ValidateSignatureSValue(&auth.S); errMsg != "" {
		result.ErrorMessage = errMsg
		result.SValueValid = false
		return result
	}
	result.SValueValid = true

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
