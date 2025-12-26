// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IEIP7702Account.sol";

/// @title MultisigLogic
/// @notice Multi-signature wallet logic for EIP-7702 delegation
/// @dev EOAs can delegate to this contract to require multiple signatures for transactions
/// @custom:eip-delegation This contract is designed for EIP-7702 code delegation
contract MultisigLogic is IEIP7702Account {
    /// @notice Storage slot for signers array (using EIP-7201 namespaced storage)
    /// @dev keccak256("eip7702.multisig.signers") = 0x...
    bytes32 private constant SIGNERS_SLOT = 0x8c6a659f0e8d0e7e4e4b7d1c1a9d8b7c6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b;

    /// @notice Storage slot for threshold
    /// @dev keccak256("eip7702.multisig.threshold") = 0x...
    bytes32 private constant THRESHOLD_SLOT = 0x1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b;

    /// @notice Storage slot for nonce
    /// @dev keccak256("eip7702.multisig.nonce") = 0x...
    bytes32 private constant NONCE_SLOT = 0x2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c;

    /// @notice Emitted when signers are set
    event SignersSet(address[] signers, uint256 threshold);

    /// @notice Emitted when a transaction is executed
    event TransactionExecuted(bytes32 indexed txHash, address indexed target, uint256 value);

    /// @notice Emitted when a signer approves a transaction
    event Approved(bytes32 indexed txHash, address indexed signer);

    /// @notice Error for invalid threshold
    error InvalidThreshold();

    /// @notice Error for duplicate signer
    error DuplicateSigner();

    /// @notice Error for invalid signature
    error InvalidSignature();

    /// @notice Error for not enough signatures
    error NotEnoughSignatures();

    /// @notice Error for invalid signer
    error InvalidSigner();

    /// @notice Error for call failed
    error CallFailed(bytes reason);

    /// @notice Error for array mismatch
    error ArrayLengthMismatch();

    /// @notice Error for not initialized
    error NotInitialized();

    /// @notice Transaction structure
    struct Transaction {
        address target;
        uint256 value;
        bytes data;
        uint256 nonce;
    }

    /// @notice Initialize the multisig with signers and threshold
    /// @param signers Array of signer addresses
    /// @param threshold Number of required signatures
    function initialize(address[] calldata signers, uint256 threshold) external {
        if (threshold == 0 || threshold > signers.length) revert InvalidThreshold();

        // Store threshold
        bytes32 thresholdSlot = THRESHOLD_SLOT;
        assembly {
            sstore(thresholdSlot, threshold)
        }

        // Store signers count and addresses
        bytes32 signersSlot = SIGNERS_SLOT;
        assembly {
            sstore(signersSlot, signers.length)
        }

        for (uint256 i = 0; i < signers.length; i++) {
            if (signers[i] == address(0)) revert InvalidSigner();

            // Check for duplicates
            for (uint256 j = 0; j < i; j++) {
                if (signers[j] == signers[i]) revert DuplicateSigner();
            }

            bytes32 slot = keccak256(abi.encode(signersSlot, i));
            address signer = signers[i];
            assembly {
                sstore(slot, signer)
            }
        }

        emit SignersSet(signers, threshold);
    }

    /// @notice Get the current threshold
    /// @return The required number of signatures
    function getThreshold() public view returns (uint256) {
        uint256 threshold;
        bytes32 thresholdSlot = THRESHOLD_SLOT;
        assembly {
            threshold := sload(thresholdSlot)
        }
        return threshold;
    }

    /// @notice Get the number of signers
    /// @return The number of signers
    function getSignerCount() public view returns (uint256) {
        uint256 count;
        bytes32 signersSlot = SIGNERS_SLOT;
        assembly {
            count := sload(signersSlot)
        }
        return count;
    }

    /// @notice Get a signer by index
    /// @param index The signer index
    /// @return The signer address
    function getSigner(uint256 index) public view returns (address) {
        bytes32 slot = keccak256(abi.encode(SIGNERS_SLOT, index));
        address signer;
        assembly {
            signer := sload(slot)
        }
        return signer;
    }

    /// @notice Get the current nonce
    /// @return The current nonce
    function getNonce() public view returns (uint256) {
        uint256 nonce;
        bytes32 nonceSlot = NONCE_SLOT;
        assembly {
            nonce := sload(nonceSlot)
        }
        return nonce;
    }

    /// @notice Check if an address is a signer
    /// @param account The address to check
    /// @return True if the address is a signer
    function isSigner(address account) public view returns (bool) {
        uint256 count = getSignerCount();
        for (uint256 i = 0; i < count; i++) {
            if (getSigner(i) == account) return true;
        }
        return false;
    }

    /// @notice Compute the hash of a transaction
    /// @param target Target address
    /// @param value ETH value
    /// @param data Calldata
    /// @param nonce Transaction nonce
    /// @return The transaction hash
    function getTransactionHash(
        address target,
        uint256 value,
        bytes calldata data,
        uint256 nonce
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            address(this),
            block.chainid,
            target,
            value,
            keccak256(data),
            nonce
        ));
    }

    /// @notice Execute a transaction with multiple signatures
    /// @param target Target address
    /// @param value ETH value
    /// @param data Calldata
    /// @param signatures Concatenated signatures (65 bytes each)
    /// @return result The return data
    function executeWithSignatures(
        address target,
        uint256 value,
        bytes calldata data,
        bytes calldata signatures
    ) external payable returns (bytes memory result) {
        uint256 threshold = getThreshold();
        if (threshold == 0) revert NotInitialized();

        uint256 nonce = getNonce();
        bytes32 txHash = getTransactionHash(target, value, data, nonce);

        // Verify signatures
        _verifySignatures(txHash, signatures, threshold);

        // Increment nonce
        bytes32 nonceSlot = NONCE_SLOT;
        assembly {
            sstore(nonceSlot, add(nonce, 1))
        }

        // Execute
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) revert CallFailed(returnData);

        emit TransactionExecuted(txHash, target, value);
        return returnData;
    }

    /// @notice Verify that enough valid signatures are provided
    /// @param txHash The transaction hash
    /// @param signatures Concatenated signatures
    /// @param threshold Required number of signatures
    function _verifySignatures(
        bytes32 txHash,
        bytes calldata signatures,
        uint256 threshold
    ) internal view {
        if (signatures.length < threshold * 65) revert NotEnoughSignatures();

        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)
        );

        address lastSigner = address(0);

        for (uint256 i = 0; i < threshold; i++) {
            uint256 offset = i * 65;
            bytes32 r;
            bytes32 s;
            uint8 v;

            assembly {
                r := calldataload(add(signatures.offset, offset))
                s := calldataload(add(signatures.offset, add(offset, 32)))
                v := byte(0, calldataload(add(signatures.offset, add(offset, 64))))
            }

            if (v < 27) v += 27;

            address signer = ecrecover(ethSignedHash, v, r, s);

            // Signers must be in ascending order to prevent duplicates
            if (signer <= lastSigner) revert InvalidSignature();
            if (!isSigner(signer)) revert InvalidSigner();

            lastSigner = signer;
        }
    }

    /// @notice Execute a single call (for compatibility with IEIP7702Account)
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable override returns (bytes memory) {
        // Direct execution only allowed by self (internal calls)
        if (msg.sender != address(this)) revert InvalidSigner();

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) revert CallFailed(result);
        return result;
    }

    /// @notice Execute batch (for compatibility with IEIP7702Account)
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable override returns (bytes[] memory results) {
        if (msg.sender != address(this)) revert InvalidSigner();

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

    /// @notice Check if authorized (signer or self)
    function isAuthorized(address signer) external view override returns (bool) {
        return signer == address(this) || isSigner(signer);
    }

    receive() external payable {}
}
