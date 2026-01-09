// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title SetCodeTestTarget
/// @notice A simple contract used to test EIP-7702 SetCode validation
/// @dev This contract is deployed to verify that:
///      1. Contract addresses (CA) cannot be the authority in SetCode transactions
///      2. SetCode authorization with authority that has code should be rejected
contract SetCodeTestTarget {
    uint256 public value;
    address public lastCaller;

    event ValueSet(address indexed caller, uint256 newValue);
    event Received(address indexed sender, uint256 amount);

    /// @notice Set a value (simple function to verify contract has code)
    function setValue(uint256 _value) external {
        value = _value;
        lastCaller = msg.sender;
        emit ValueSet(msg.sender, _value);
    }

    /// @notice Get the contract's code size (should be > 0 for CA)
    function getCodeSize() external view returns (uint256) {
        return address(this).code.length;
    }

    /// @notice Check if an address is a contract (has code)
    function isContract(address _addr) external view returns (bool) {
        return _addr.code.length > 0;
    }

    /// @notice Receive ETH
    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    /// @notice Fallback function
    fallback() external payable {
        emit Received(msg.sender, msg.value);
    }
}
