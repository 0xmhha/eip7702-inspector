// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IEIP7702Account} from "./interfaces/IEIP7702Account.sol";
import {IEntryPoint, UserOperation, IAccount} from "./interfaces/IEntryPoint.sol";

/// @title PaymasterHelper
/// @notice Gas sponsorship integration for EIP-7702 delegated accounts
/// @dev EOAs can delegate to this contract to use paymasters for gas sponsorship
/// @custom:eip-delegation This contract is designed for EIP-7702 code delegation
contract PaymasterHelper is IEIP7702Account, IAccount {
    /// @notice The ERC-4337 EntryPoint
    IEntryPoint public immutable ENTRY_POINT;

    /// @notice Trusted paymaster addresses
    mapping(address => bool) public trustedPaymasters;

    /// @notice Storage slot for trusted paymasters (for EIP-7702 persistent storage)
    bytes32 private constant TRUSTED_PAYMASTERS_SLOT = keccak256("eip7702.paymaster.trusted");

    /// @notice Emitted when a paymaster is trusted/untrusted
    event PaymasterTrustUpdated(address indexed paymaster, bool trusted);

    /// @notice Emitted when gas is sponsored
    event GasSponsored(address indexed paymaster, address indexed account, uint256 gasUsed);

    /// @notice Emitted when a call is executed
    event Executed(address indexed target, uint256 value);

    /// @notice Error when caller is not authorized
    error Unauthorized();

    /// @notice Error when paymaster is not trusted
    error UntrustedPaymaster();

    /// @notice Error when call fails
    error CallFailed(bytes reason);

    /// @notice Error when array lengths mismatch
    error ArrayLengthMismatch();

    /// @notice Validation success
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;

    /// @notice Validation failed
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @param entryPoint_ The ERC-4337 EntryPoint address
    constructor(IEntryPoint entryPoint_) {
        ENTRY_POINT = entryPoint_;
    }

    /// @notice Add or remove a trusted paymaster
    /// @param paymaster The paymaster address
    /// @param trusted Whether to trust the paymaster
    function setTrustedPaymaster(address paymaster, bool trusted) external {
        if (msg.sender != address(this)) revert Unauthorized();

        bytes32 slot = keccak256(abi.encode(TRUSTED_PAYMASTERS_SLOT, paymaster));
        assembly {
            sstore(slot, trusted)
        }

        emit PaymasterTrustUpdated(paymaster, trusted);
    }

    /// @notice Check if a paymaster is trusted
    /// @param paymaster The paymaster address
    /// @return Whether the paymaster is trusted
    function isPaymasterTrusted(address paymaster) public view returns (bool) {
        bytes32 slot = keccak256(abi.encode(TRUSTED_PAYMASTERS_SLOT, paymaster));
        bool trusted;
        assembly {
            trusted := sload(slot)
        }
        return trusted;
    }

    /// @notice Validate a UserOperation (ERC-4337)
    /// @param userOp The UserOperation
    /// @param userOpHash Hash of the UserOperation
    /// @param missingAccountFunds Funds to pay to EntryPoint
    /// @return validationData Validation result
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        if (msg.sender != address(ENTRY_POINT)) revert Unauthorized();

        // Check if paymaster is trusted (if using a paymaster)
        if (userOp.paymasterAndData.length >= 20) {
            address paymaster = address(bytes20(userOp.paymasterAndData[:20]));
            if (!isPaymasterTrusted(paymaster)) {
                return SIG_VALIDATION_FAILED;
            }
        }

        // Validate signature
        validationData = _validateSignature(userOp, userOpHash);

        // Pay prefund if needed (only if not using paymaster)
        if (missingAccountFunds > 0 && userOp.paymasterAndData.length == 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            (success); // Silence unused variable warning
        }

        return validationData;
    }

    /// @notice Validate signature
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );

        if (userOp.signature.length != 65) return SIG_VALIDATION_FAILED;

        bytes32 r;
        bytes32 s;
        uint8 v;
        bytes memory sig = userOp.signature;

        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }

        if (v < 27) v += 27;

        address recovered = ecrecover(ethSignedHash, v, r, s);

        if (recovered == address(this)) {
            return SIG_VALIDATION_SUCCESS;
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice Execute a call
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable override returns (bytes memory) {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this)) {
            revert Unauthorized();
        }

        (bool success, bytes memory result) = target.call{value: value}(data);
        if (!success) revert CallFailed(result);

        emit Executed(target, value);
        return result;
    }

    /// @notice Execute batch
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable override returns (bytes[] memory results) {
        if (msg.sender != address(ENTRY_POINT) && msg.sender != address(this)) {
            revert Unauthorized();
        }

        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert ArrayLengthMismatch();
        }

        results = new bytes[](length);
        for (uint256 i = 0; i < length; i++) {
            (bool success, bytes memory result) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) revert CallFailed(result);
            results[i] = result;
            emit Executed(targets[i], values[i]);
        }
        return results;
    }

    /// @notice Check if authorized
    function isAuthorized(address signer) external view override returns (bool) {
        return signer == address(this) || signer == address(ENTRY_POINT);
    }

    /// @notice Get deposit at EntryPoint
    function getDeposit() public view returns (uint256) {
        return ENTRY_POINT.balanceOf(address(this));
    }

    /// @notice Add deposit to EntryPoint
    function addDeposit() public payable {
        ENTRY_POINT.depositTo{value: msg.value}(address(this));
    }

    receive() external payable {}
}
