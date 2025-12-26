package inspector

import (
	"bytes"
	"fmt"

	"github.com/ethereum/go-ethereum/common"
)

// DelegationVerificationResult contains the result of delegation verification
type DelegationVerificationResult struct {
	Valid           bool
	Address         *common.Address
	ErrorMessage    string
	PrefixCorrect   bool
	LengthCorrect   bool
	ParsedCorrectly bool
}

// VerifyDelegation verifies if the given code is a valid EIP-7702 delegation
func VerifyDelegation(code []byte) *DelegationVerificationResult {
	result := &DelegationVerificationResult{}

	// Check length
	if len(code) != DelegationCodeLength {
		result.ErrorMessage = fmt.Sprintf("invalid delegation length: expected %d, got %d", DelegationCodeLength, len(code))
		result.LengthCorrect = false
		return result
	}
	result.LengthCorrect = true

	// Check prefix
	if !bytes.HasPrefix(code, DelegationPrefix) {
		result.ErrorMessage = fmt.Sprintf("invalid delegation prefix: expected 0x%x, got 0x%x", DelegationPrefix, code[:3])
		result.PrefixCorrect = false
		return result
	}
	result.PrefixCorrect = true

	// Extract address
	addr := common.BytesToAddress(code[DelegationPrefixLength:])
	result.Address = &addr
	result.ParsedCorrectly = true
	result.Valid = true

	return result
}

// ParseDelegation parses a delegation code and returns the delegated address
// Returns (address, true) if valid, (zero address, false) if invalid
func ParseDelegation(code []byte) (common.Address, bool) {
	if len(code) != DelegationCodeLength {
		return common.Address{}, false
	}
	if !bytes.HasPrefix(code, DelegationPrefix) {
		return common.Address{}, false
	}
	return common.BytesToAddress(code[DelegationPrefixLength:]), true
}

// AddressToDelegation creates a delegation code from an address
func AddressToDelegation(addr common.Address) []byte {
	result := make([]byte, DelegationCodeLength)
	copy(result, DelegationPrefix)
	copy(result[DelegationPrefixLength:], addr.Bytes())
	return result
}

// IsDelegation checks if the code is a valid delegation
func IsDelegation(code []byte) bool {
	_, ok := ParseDelegation(code)
	return ok
}

// DelegationTestCase represents a test case for delegation parsing
type DelegationTestCase struct {
	Name        string
	Input       []byte
	ExpectValid bool
	ExpectedAddr *common.Address
	Description string
}

// GetDelegationTestCases returns standard test cases based on go-ethereum patterns
func GetDelegationTestCases() []DelegationTestCase {
	addr := common.HexToAddress("0x0000000000000000000000000000000000000042")

	return []DelegationTestCase{
		{
			Name:         "valid_simple_delegation",
			Input:        append(DelegationPrefix, addr.Bytes()...),
			ExpectValid:  true,
			ExpectedAddr: &addr,
			Description:  "Simple correct delegation with 0x42 address",
		},
		{
			Name:        "wrong_address_size_19",
			Input:       append(DelegationPrefix, addr.Bytes()[0:19]...),
			ExpectValid: false,
			Description: "Address is only 19 bytes instead of 20",
		},
		{
			Name:        "short_address_1_byte",
			Input:       append(DelegationPrefix, 0x42),
			ExpectValid: false,
			Description: "Address is only 1 byte",
		},
		{
			Name:        "long_address_21_bytes",
			Input:       append(append(DelegationPrefix, addr.Bytes()...), 0x42),
			ExpectValid: false,
			Description: "Address is 21 bytes (extra byte at end)",
		},
		{
			Name:        "wrong_prefix_size_2",
			Input:       append(DelegationPrefix[:2], addr.Bytes()...),
			ExpectValid: false,
			Description: "Prefix is only 2 bytes instead of 3",
		},
		{
			Name:        "wrong_prefix_ef0101",
			Input:       append([]byte{0xef, 0x01, 0x01}, addr.Bytes()...),
			ExpectValid: false,
			Description: "Wrong prefix 0xef0101 (last byte wrong)",
		},
		{
			Name:        "wrong_prefix_ef0000",
			Input:       append([]byte{0xef, 0x00, 0x00}, addr.Bytes()...),
			ExpectValid: false,
			Description: "Wrong prefix 0xef0000 (middle and last bytes wrong)",
		},
		{
			Name:        "no_prefix_address_only",
			Input:       addr.Bytes(),
			ExpectValid: false,
			Description: "No prefix, just the address",
		},
		{
			Name:        "prefix_only_no_address",
			Input:       DelegationPrefix,
			ExpectValid: false,
			Description: "Only prefix without address",
		},
		{
			Name:        "empty_input",
			Input:       []byte{},
			ExpectValid: false,
			Description: "Empty byte slice",
		},
		{
			Name:        "nil_input",
			Input:       nil,
			ExpectValid: false,
			Description: "Nil byte slice",
		},
	}
}

// RunDelegationTests runs all delegation test cases and returns results
func RunDelegationTests() []DelegationTestResult {
	testCases := GetDelegationTestCases()
	results := make([]DelegationTestResult, 0, len(testCases))

	for _, tc := range testCases {
		addr, valid := ParseDelegation(tc.Input)

		passed := valid == tc.ExpectValid
		if tc.ExpectValid && tc.ExpectedAddr != nil {
			passed = passed && (addr == *tc.ExpectedAddr)
		}

		results = append(results, DelegationTestResult{
			TestCase: tc,
			Passed:   passed,
			GotValid: valid,
			GotAddr:  addr,
		})
	}

	return results
}

// DelegationTestResult contains the result of a delegation test
type DelegationTestResult struct {
	TestCase DelegationTestCase
	Passed   bool
	GotValid bool
	GotAddr  common.Address
}
