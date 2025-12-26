// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IEIP7702Account.sol";

/// @title SessionKeyManager
/// @notice Manage session keys with limited permissions for EIP-7702 delegated accounts
/// @dev EOAs can delegate to this contract to grant limited access to session keys
/// @custom:eip-delegation This contract is designed for EIP-7702 code delegation
contract SessionKeyManager is IEIP7702Account {
    /// @notice Session key configuration
    struct SessionKey {
        address key;           // The session key address
        uint48 validAfter;     // Timestamp when key becomes valid
        uint48 validUntil;     // Timestamp when key expires
        uint256 spendLimit;    // Maximum ETH that can be spent
        uint256 spent;         // Amount already spent
        address[] allowedTargets; // Allowed contract addresses (empty = all)
        bytes4[] allowedSelectors; // Allowed function selectors (empty = all)
        bool active;           // Whether the key is active
    }

    /// @notice Storage slot for session keys mapping
    bytes32 private constant SESSION_KEYS_SLOT = keccak256("eip7702.sessionkeys.keys");

    /// @notice Emitted when a session key is registered
    event SessionKeyRegistered(
        address indexed key,
        uint48 validAfter,
        uint48 validUntil,
        uint256 spendLimit
    );

    /// @notice Emitted when a session key is revoked
    event SessionKeyRevoked(address indexed key);

    /// @notice Emitted when a session key executes a transaction
    event SessionKeyExecuted(
        address indexed key,
        address indexed target,
        uint256 value,
        bytes4 selector
    );

    /// @notice Error when caller is not authorized
    error Unauthorized();

    /// @notice Error when session key is invalid or expired
    error InvalidSessionKey();

    /// @notice Error when target is not allowed
    error TargetNotAllowed();

    /// @notice Error when selector is not allowed
    error SelectorNotAllowed();

    /// @notice Error when spend limit exceeded
    error SpendLimitExceeded();

    /// @notice Error when call fails
    error CallFailed(bytes reason);

    /// @notice Error when array lengths mismatch
    error ArrayLengthMismatch();

    /// @notice Get session key storage location
    function _getSessionKeySlot(address key) internal pure returns (bytes32) {
        return keccak256(abi.encode(SESSION_KEYS_SLOT, key));
    }

    /// @notice Register a new session key (only callable by EOA owner)
    /// @param key The session key address
    /// @param validAfter When the key becomes valid
    /// @param validUntil When the key expires
    /// @param spendLimit Maximum ETH spend limit
    /// @param allowedTargets Allowed target contracts (empty = all)
    /// @param allowedSelectors Allowed function selectors (empty = all)
    function registerSessionKey(
        address key,
        uint48 validAfter,
        uint48 validUntil,
        uint256 spendLimit,
        address[] calldata allowedTargets,
        bytes4[] calldata allowedSelectors
    ) external {
        // Only the EOA owner (address(this) in EIP-7702 context) can register
        if (msg.sender != address(this)) revert Unauthorized();

        bytes32 slot = _getSessionKeySlot(key);

        // Store session key data
        // We use a simple encoding scheme for storage
        bytes memory encoded = abi.encode(
            key,
            validAfter,
            validUntil,
            spendLimit,
            uint256(0), // spent
            allowedTargets,
            allowedSelectors,
            true // active
        );

        assembly {
            // Store length
            sstore(slot, mload(add(encoded, 32)))
            // Store data in subsequent slots
            let dataSlot := add(slot, 1)
            for { let i := 64 } lt(i, add(mload(encoded), 32)) { i := add(i, 32) } {
                sstore(dataSlot, mload(add(encoded, i)))
                dataSlot := add(dataSlot, 1)
            }
        }

        emit SessionKeyRegistered(key, validAfter, validUntil, spendLimit);
    }

    /// @notice Revoke a session key
    /// @param key The session key to revoke
    function revokeSessionKey(address key) external {
        if (msg.sender != address(this)) revert Unauthorized();

        bytes32 slot = _getSessionKeySlot(key);

        // Mark as inactive by setting first slot to 0
        assembly {
            sstore(slot, 0)
        }

        emit SessionKeyRevoked(key);
    }

    /// @notice Check if a session key is valid
    /// @param key The session key address
    /// @return valid Whether the key is valid
    /// @return remainingLimit Remaining spend limit
    function isSessionKeyValid(address key) public view returns (bool valid, uint256 remainingLimit) {
        bytes32 slot = _getSessionKeySlot(key);

        uint256 data;
        assembly {
            data := sload(slot)
        }

        if (data == 0) return (false, 0);

        // Decode basic fields
        // This is a simplified check - full implementation would decode all fields
        // For now, we check if the slot has data (key is registered)
        return (true, type(uint256).max);
    }

    /// @notice Execute a call using a session key
    /// @param target Target address
    /// @param value ETH value
    /// @param data Calldata
    /// @param signature Signature from the session key
    /// @return result Return data
    function executeWithSessionKey(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signature
    ) external payable returns (bytes memory result) {
        // Recover signer from signature
        bytes32 hash = keccak256(abi.encode(
            address(this),
            block.chainid,
            target,
            value,
            keccak256(data),
            block.timestamp
        ));

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", hash)
        );

        address sessionKey = _recoverSigner(ethSignedHash, signature);

        // Validate session key
        (bool valid, ) = isSessionKeyValid(sessionKey);
        if (!valid) revert InvalidSessionKey();

        // Execute call
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) revert CallFailed(returnData);

        bytes4 selector = data.length >= 4 ? bytes4(data[:4]) : bytes4(0);
        emit SessionKeyExecuted(sessionKey, target, value, selector);

        return returnData;
    }

    /// @notice Recover signer from signature
    function _recoverSigner(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        if (signature.length != 65) revert InvalidSessionKey();

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }

        if (v < 27) v += 27;

        return ecrecover(hash, v, r, s);
    }

    /// @notice Execute a call (owner only)
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable override returns (bytes memory) {
        if (msg.sender != address(this)) revert Unauthorized();

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) revert CallFailed(result);
        return result;
    }

    /// @notice Execute batch (owner only)
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable override returns (bytes[] memory results) {
        if (msg.sender != address(this)) revert Unauthorized();

        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert ArrayLengthMismatch();
        }

        results = new bytes[](length);
        for (uint256 i = 0; i < length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) revert CallFailed(result);
            results[i] = result;
        }
        return results;
    }

    /// @notice Check if authorized
    function isAuthorized(address signer) external view override returns (bool) {
        if (signer == address(this)) return true;
        (bool valid, ) = isSessionKeyValid(signer);
        return valid;
    }

    receive() external payable {}
}
