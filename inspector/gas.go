package inspector

import (
	"fmt"
)

// GasCalculationResult contains detailed gas calculation results
type GasCalculationResult struct {
	TotalGas           uint64
	BaseGas            uint64
	DataGas            uint64
	AccessListGas      uint64
	AuthListGas        uint64
	AuthListRefund     uint64
	NetAuthGas         uint64
	DetailedBreakdown  []GasComponent
}

// GasComponent represents a single component of gas calculation
type GasComponent struct {
	Name       string
	Gas        uint64
	Count      uint64
	UnitCost   uint64
	Description string
}

// GasConstants contains EIP-7702 specific gas constants
type GasConstants struct {
	TxGas                   uint64
	TxDataZeroGas           uint64
	TxDataNonZeroGas        uint64
	TxAccessListAddressGas  uint64
	TxAccessListStorageGas  uint64
	PerAuthNewAccountGas    uint64
	PerAuthExistingRefund   uint64
	TxCreateGas             uint64
	InitCodeWordGas         uint64
	MaxInitCodeSize         uint64
}

// DefaultGasConstants returns the default EIP-7702 gas constants
func DefaultGasConstants() GasConstants {
	return GasConstants{
		TxGas:                   21000,
		TxDataZeroGas:           4,
		TxDataNonZeroGas:        16,
		TxAccessListAddressGas:  2400,
		TxAccessListStorageGas:  1900,
		PerAuthNewAccountGas:    25000, // PER_EMPTY_ACCOUNT_COST
		PerAuthExistingRefund:   12500, // PER_AUTH_BASE_COST
		TxCreateGas:             53000,
		InitCodeWordGas:         2,
		MaxInitCodeSize:         49152, // 48KB
	}
}

// CalculateDetailedGas calculates gas with detailed breakdown
func CalculateDetailedGas(tx *SetCodeTx, existingAccounts []bool) *GasCalculationResult {
	constants := DefaultGasConstants()
	result := &GasCalculationResult{
		DetailedBreakdown: make([]GasComponent, 0),
	}

	// Base transaction gas
	result.BaseGas = constants.TxGas
	result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
		Name:        "base_tx_gas",
		Gas:         constants.TxGas,
		Count:       1,
		UnitCost:    constants.TxGas,
		Description: "Base transaction gas",
	})

	// Data gas
	var zeroBytes, nonZeroBytes uint64
	for _, b := range tx.Data {
		if b == 0 {
			zeroBytes++
		} else {
			nonZeroBytes++
		}
	}
	zeroGas := zeroBytes * constants.TxDataZeroGas
	nonZeroGas := nonZeroBytes * constants.TxDataNonZeroGas
	result.DataGas = zeroGas + nonZeroGas

	if zeroBytes > 0 {
		result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
			Name:        "data_zero_bytes",
			Gas:         zeroGas,
			Count:       zeroBytes,
			UnitCost:    constants.TxDataZeroGas,
			Description: "Zero bytes in calldata",
		})
	}
	if nonZeroBytes > 0 {
		result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
			Name:        "data_non_zero_bytes",
			Gas:         nonZeroGas,
			Count:       nonZeroBytes,
			UnitCost:    constants.TxDataNonZeroGas,
			Description: "Non-zero bytes in calldata",
		})
	}

	// Access list gas
	var accessListAddresses, accessListStorageKeys uint64
	for _, tuple := range tx.AccessList {
		accessListAddresses++
		accessListStorageKeys += uint64(len(tuple.StorageKeys))
	}
	result.AccessListGas = accessListAddresses*constants.TxAccessListAddressGas +
		accessListStorageKeys*constants.TxAccessListStorageGas

	if accessListAddresses > 0 {
		result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
			Name:        "access_list_addresses",
			Gas:         accessListAddresses * constants.TxAccessListAddressGas,
			Count:       accessListAddresses,
			UnitCost:    constants.TxAccessListAddressGas,
			Description: "Access list address entries",
		})
	}
	if accessListStorageKeys > 0 {
		result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
			Name:        "access_list_storage_keys",
			Gas:         accessListStorageKeys * constants.TxAccessListStorageGas,
			Count:       accessListStorageKeys,
			UnitCost:    constants.TxAccessListStorageGas,
			Description: "Access list storage key entries",
		})
	}

	// Authorization list gas
	authCount := uint64(len(tx.AuthList))
	newAccountCount := authCount
	existingAccountCount := uint64(0)

	// Count existing vs new accounts if provided
	if len(existingAccounts) > 0 {
		newAccountCount = 0
		for i := 0; i < len(tx.AuthList) && i < len(existingAccounts); i++ {
			if existingAccounts[i] {
				existingAccountCount++
			} else {
				newAccountCount++
			}
		}
	}

	// Calculate auth list gas with potential refunds
	result.AuthListGas = authCount * constants.PerAuthNewAccountGas
	result.AuthListRefund = existingAccountCount * constants.PerAuthExistingRefund
	result.NetAuthGas = result.AuthListGas - result.AuthListRefund

	result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
		Name:        "auth_list_base",
		Gas:         result.AuthListGas,
		Count:       authCount,
		UnitCost:    constants.PerAuthNewAccountGas,
		Description: fmt.Sprintf("Authorization list base cost (new accounts: %d, existing: %d)", newAccountCount, existingAccountCount),
	})

	if result.AuthListRefund > 0 {
		result.DetailedBreakdown = append(result.DetailedBreakdown, GasComponent{
			Name:        "auth_list_refund",
			Gas:         result.AuthListRefund,
			Count:       existingAccountCount,
			UnitCost:    constants.PerAuthExistingRefund,
			Description: "Refund for existing delegated accounts",
		})
	}

	// Total
	result.TotalGas = result.BaseGas + result.DataGas + result.AccessListGas + result.NetAuthGas

	return result
}

// GasTestCase represents a test case for gas calculation
type GasTestCase struct {
	Name             string
	Tx               *SetCodeTx
	ExistingAccounts []bool
	ExpectedGas      uint64
	Description      string
}

// GetGasTestCases returns standard test cases for gas calculation
func GetGasTestCases() []GasTestCase {
	return []GasTestCase{
		{
			Name: "single_new_auth",
			Tx: &SetCodeTx{
				AuthList: []SetCodeAuthorization{
					{Address: TestAddresses.AAAA},
				},
			},
			ExistingAccounts: []bool{false},
			ExpectedGas:      21000 + 25000, // base + 1 new auth
			Description:      "Single authorization to new account",
		},
		{
			Name: "single_existing_auth",
			Tx: &SetCodeTx{
				AuthList: []SetCodeAuthorization{
					{Address: TestAddresses.AAAA},
				},
			},
			ExistingAccounts: []bool{true},
			ExpectedGas:      21000 + 25000 - 12500, // base + auth - refund
			Description:      "Single authorization to existing account",
		},
		{
			Name: "two_auths_mixed",
			Tx: &SetCodeTx{
				AuthList: []SetCodeAuthorization{
					{Address: TestAddresses.AAAA},
					{Address: TestAddresses.BBBB},
				},
			},
			ExistingAccounts: []bool{false, true},
			ExpectedGas:      21000 + 50000 - 12500, // base + 2 auths - 1 refund
			Description:      "Two authorizations: one new, one existing",
		},
		{
			Name: "auth_with_data",
			Tx: &SetCodeTx{
				Data: []byte{0x00, 0x01, 0x02, 0x00}, // 2 zero, 2 non-zero
				AuthList: []SetCodeAuthorization{
					{Address: TestAddresses.AAAA},
				},
			},
			ExistingAccounts: []bool{false},
			ExpectedGas:      21000 + 25000 + 2*4 + 2*16, // base + auth + data
			Description:      "Authorization with calldata",
		},
	}
}

// GasTestResult contains the result of a gas calculation test
type GasTestResult struct {
	TestCase    GasTestCase
	Passed      bool
	Calculation *GasCalculationResult
	Difference  int64
}

// RunGasTests runs gas calculation test cases
func RunGasTests() []GasTestResult {
	testCases := GetGasTestCases()
	results := make([]GasTestResult, 0, len(testCases))

	for _, tc := range testCases {
		result := GasTestResult{
			TestCase: tc,
		}

		calculation := CalculateDetailedGas(tc.Tx, tc.ExistingAccounts)
		result.Calculation = calculation
		result.Difference = int64(calculation.TotalGas) - int64(tc.ExpectedGas)
		result.Passed = calculation.TotalGas == tc.ExpectedGas

		results = append(results, result)
	}

	return results
}
