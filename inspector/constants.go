// Package inspector provides EIP-7702 verification and inspection utilities.
// This package is designed to verify EIP-7702 (EOA Code Delegation) implementations
// based on test patterns from go-ethereum and reth.
package inspector

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common"
	"github.com/holiman/uint256"
)

// Transaction Types
const (
	// LegacyTxType is the transaction type for legacy transactions (0x00)
	LegacyTxType = 0x00

	// AccessListTxType is the transaction type for EIP-2930 (0x01)
	AccessListTxType = 0x01

	// DynamicFeeTxType is the transaction type for EIP-1559 (0x02)
	DynamicFeeTxType = 0x02

	// BlobTxType is the transaction type for EIP-4844 (0x03)
	BlobTxType = 0x03

	// SetCodeTxType is the transaction type for EIP-7702 (0x04)
	SetCodeTxType = 0x04
)

// EIP-7702 Constants
const (
	// DelegationPrefixLength is the length of the delegation prefix (0xef0100)
	DelegationPrefixLength = 3

	// DelegationCodeLength is the total length of delegation code (prefix + address)
	DelegationCodeLength = 23

	// AuthorizationSigningPrefix is the prefix used for authorization signing (0x05)
	AuthorizationSigningPrefix = 0x05

	// CallNewAccountGas is the gas cost per authorization (25,000)
	CallNewAccountGas = 25000

	// TxAuthTupleGas is the gas refund for existing accounts (12,500)
	TxAuthTupleGas = 12500

	// PerEmptyAccountCost is the base cost for setting code on empty account
	PerEmptyAccountCost = 25000

	// PerExistingAccountRefund is the refund for existing accounts
	PerExistingAccountRefund = 12500
)

// DelegationPrefix is the 3-byte prefix for delegation code (0xef0100)
var DelegationPrefix = []byte{0xef, 0x01, 0x00}

// Secp256k1N is the order of the secp256k1 curve
// secp256k1n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
var Secp256k1N = uint256.MustFromHex("0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")

// Secp256k1HalfN is half of the secp256k1 curve order (secp256k1n / 2)
// Used for EIP-2 signature malleability check: s must be <= secp256k1n/2
// secp256k1n/2 = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
var Secp256k1HalfN = uint256.MustFromHex("0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0")

// InvalidPrefixes are known invalid prefixes for testing
var InvalidPrefixes = [][]byte{
	{0xef, 0x01, 0x01}, // Wrong last byte
	{0xef, 0x00, 0x00}, // Wrong middle byte
	{0xef, 0x02, 0x00}, // Wrong middle byte variant
	{0x00, 0x01, 0x00}, // Wrong first byte
}

// TestAddresses are common addresses used in testing
var TestAddresses = struct {
	Zero    common.Address
	Simple  common.Address
	AA      common.Address
	BB      common.Address
	AAAA    common.Address
	BBBB    common.Address
}{
	Zero:    common.Address{},
	Simple:  common.HexToAddress("0x0000000000000000000000000000000000000042"),
	AA:      common.HexToAddress("0x00000000000000000000000000000000000000aa"),
	BB:      common.HexToAddress("0x00000000000000000000000000000000000000bb"),
	AAAA:    common.HexToAddress("0x000000000000000000000000000000000000aaaa"),
	BBBB:    common.HexToAddress("0x000000000000000000000000000000000000bbbb"),
}

// TestPrivateKeys are known test private keys (DO NOT USE IN PRODUCTION)
var TestPrivateKeys = []string{
	"b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291",
	"8a1f9a8f95be41cd7ccb6168179afb4504aefe388d1e14474d32c45c72ce7b7a",
	"0202020202020202020202020202020202020202020202020202002020202020",
}

// ValidateTxType validates that the transaction type is SetCodeTxType (0x04)
// Returns true if the type is valid for EIP-7702
func ValidateTxType(txType uint8) bool {
	return txType == SetCodeTxType
}

// ValidateTxTypeValue validates the transaction type and returns an error message if invalid
// Returns empty string if valid
func ValidateTxTypeValue(txType uint8) string {
	if txType != SetCodeTxType {
		return fmt.Sprintf("invalid transaction type: expected 0x%02x (SetCodeTxType), got 0x%02x", SetCodeTxType, txType)
	}
	return ""
}

// GetTxTypeName returns a human-readable name for the transaction type
func GetTxTypeName(txType uint8) string {
	switch txType {
	case LegacyTxType:
		return "Legacy"
	case AccessListTxType:
		return "AccessList (EIP-2930)"
	case DynamicFeeTxType:
		return "DynamicFee (EIP-1559)"
	case BlobTxType:
		return "Blob (EIP-4844)"
	case SetCodeTxType:
		return "SetCode (EIP-7702)"
	default:
		return fmt.Sprintf("Unknown (0x%02x)", txType)
	}
}
