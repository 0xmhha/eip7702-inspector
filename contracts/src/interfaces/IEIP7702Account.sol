// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title IEIP7702Account
/// @notice Base interface for EIP-7702 delegated accounts
/// @dev EOAs can delegate to contracts implementing this interface
interface IEIP7702Account {
    /// @notice Execute a call from this account
    /// @param target The address to call
    /// @param value The ETH value to send
    /// @param data The calldata to send
    /// @return result The return data from the call
    function execute(address target, uint256 value, bytes calldata data) external payable returns (bytes memory result);

    /// @notice Execute multiple calls from this account
    /// @param targets The addresses to call
    /// @param values The ETH values to send
    /// @param datas The calldatas to send
    /// @return results The return data from each call
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable returns (bytes[] memory results);

    /// @notice Check if an address is authorized to execute on behalf of this account
    /// @param signer The address to check
    /// @return True if the signer is authorized
    function isAuthorized(address signer) external view returns (bool);
}
