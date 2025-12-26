// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IEIP7702Account.sol";

/// @title BatchExecutor
/// @notice Execute multiple calls in a single transaction via EIP-7702 delegation
/// @dev When an EOA delegates to this contract, it can batch multiple calls
/// @custom:eip-delegation This contract is designed for EIP-7702 code delegation
contract BatchExecutor is IEIP7702Account {
    /// @notice Emitted when a call is executed
    event Executed(address indexed target, uint256 value, bytes data, bytes result);

    /// @notice Emitted when a batch is executed
    event BatchExecuted(uint256 indexed count, uint256 totalValue);

    /// @notice Error when caller is not the delegating EOA (address(this))
    error OnlyDelegator();

    /// @notice Error when array lengths don't match
    error ArrayLengthMismatch();

    /// @notice Error when a call fails
    error CallFailed(uint256 index, bytes reason);

    /// @notice Ensures only the delegating EOA can call this function
    /// @dev In EIP-7702, when EOA delegates to this contract, msg.sender == address(this)
    modifier onlyDelegator() {
        if (msg.sender != address(this)) revert OnlyDelegator();
        _;
    }

    /// @notice Execute a single call
    /// @param target The address to call
    /// @param value The ETH value to send
    /// @param data The calldata
    /// @return result The return data
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable override returns (bytes memory result) {
        // In EIP-7702 context, this runs as the EOA
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) {
            // Bubble up the revert reason
            assembly {
                revert(add(returnData, 32), mload(returnData))
            }
        }

        emit Executed(target, value, data, returnData);
        return returnData;
    }

    /// @notice Execute multiple calls in a single transaction
    /// @param targets Array of target addresses
    /// @param values Array of ETH values
    /// @param datas Array of calldata
    /// @return results Array of return data
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable override returns (bytes[] memory results) {
        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert ArrayLengthMismatch();
        }

        results = new bytes[](length);
        uint256 totalValue = 0;

        for (uint256 i = 0; i < length; i++) {
            (bool success, bytes memory returnData) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) {
                revert CallFailed(i, returnData);
            }
            results[i] = returnData;
            totalValue += values[i];

            emit Executed(targets[i], values[i], datas[i], returnData);
        }

        emit BatchExecuted(length, totalValue);
        return results;
    }

    /// @notice Execute batch with optional continue-on-failure
    /// @param targets Array of target addresses
    /// @param values Array of ETH values
    /// @param datas Array of calldata
    /// @param continueOnFail If true, continue execution even if a call fails
    /// @return results Array of return data
    /// @return successes Array of success flags
    function executeBatchWithFallback(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas,
        bool continueOnFail
    ) external payable returns (bytes[] memory results, bool[] memory successes) {
        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert ArrayLengthMismatch();
        }

        results = new bytes[](length);
        successes = new bool[](length);

        for (uint256 i = 0; i < length; i++) {
            (bool success, bytes memory returnData) = targets[i].call{value: values[i]}(datas[i]);

            if (!success && !continueOnFail) {
                revert CallFailed(i, returnData);
            }

            results[i] = returnData;
            successes[i] = success;

            if (success) {
                emit Executed(targets[i], values[i], datas[i], returnData);
            }
        }

        return (results, successes);
    }

    /// @notice Check if an address is authorized (for EIP-7702, only the EOA itself)
    /// @param signer The address to check
    /// @return True if signer is authorized (is this contract/EOA)
    function isAuthorized(address signer) external view override returns (bool) {
        return signer == address(this);
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
