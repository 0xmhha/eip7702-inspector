// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test, console} from "forge-std/Test.sol";
import {SetCodeTestTarget} from "../src/SetCodeTestTarget.sol";

/// @title SetCodeValidationTest
/// @notice Tests to verify EIP-7702 SetCode validation behavior
/// @dev Note: Actual SetCode transaction validation happens at the node level.
///      These tests verify contract deployment and code existence checks.
contract SetCodeValidationTest is Test {
    SetCodeTestTarget public target;

    function setUp() public {
        target = new SetCodeTestTarget();
    }

    /// @notice Verify that deployed contract has code
    function test_ContractHasCode() public view {
        uint256 codeSize = target.getCodeSize();
        assertGt(codeSize, 0, "Contract should have code");
    }

    /// @notice Verify isContract returns true for contract address
    function test_IsContractReturnsTrue() public view {
        bool isContractAddress = target.isContract(address(target));
        assertTrue(isContractAddress, "Contract address should be identified as contract");
    }

    /// @notice Verify isContract returns false for EOA
    function test_IsContractReturnsFalseForEOA() public {
        address eoa = makeAddr("testEOA");
        bool isContractAddress = target.isContract(eoa);
        assertFalse(isContractAddress, "EOA should not be identified as contract");
    }

    /// @notice Verify contract functionality works
    function test_SetValue() public {
        target.setValue(42);
        assertEq(target.value(), 42);
        assertEq(target.lastCaller(), address(this));
    }

    /// @notice Verify contract can receive ETH
    function test_ReceiveETH() public {
        vm.deal(address(this), 1 ether);
        (bool success,) = address(target).call{value: 0.1 ether}("");
        assertTrue(success, "Contract should receive ETH");
        assertEq(address(target).balance, 0.1 ether);
    }

    /// @notice Log contract info for manual verification
    function test_LogContractInfo() public view {
        console.log("=== SetCode Validation Test Contract ===");
        console.log("Contract Address:", address(target));
        console.log("Code Size:", target.getCodeSize());
        console.log("Is Contract:", target.isContract(address(target)));
        console.log("");
        console.log("To test EIP-7702 SetCode validation:");
        console.log("1. Deploy this contract to testnet");
        console.log("2. Try to create SetCode authorization with this address as authority");
        console.log("3. Should fail with: ErrAuthorizationDestinationHasCode");
    }
}
