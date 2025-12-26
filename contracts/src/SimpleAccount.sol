// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./interfaces/IEIP7702Account.sol";
import "./interfaces/IEntryPoint.sol";

/// @title SimpleAccount
/// @notice ERC-4337 compatible smart account for EIP-7702 delegation
/// @dev EOAs can delegate to this contract to gain Account Abstraction features
/// @custom:eip-delegation This contract is designed for EIP-7702 code delegation
contract SimpleAccount is IEIP7702Account, IAccount {
    /// @notice The ERC-4337 EntryPoint address
    IEntryPoint public immutable entryPoint;

    /// @notice Emitted when a call is executed
    event Executed(address indexed target, uint256 value, bytes data);

    /// @notice Emitted when UserOp is validated
    event UserOpValidated(bytes32 indexed userOpHash, uint256 validationData);

    /// @notice Error when caller is not authorized
    error Unauthorized();

    /// @notice Error when signature is invalid
    error InvalidSignature();

    /// @notice Error when call fails
    error CallFailed(bytes reason);

    /// @notice Error when array lengths mismatch
    error ArrayLengthMismatch();

    /// @notice Signature validation success
    uint256 internal constant SIG_VALIDATION_SUCCESS = 0;

    /// @notice Signature validation failed
    uint256 internal constant SIG_VALIDATION_FAILED = 1;

    /// @param _entryPoint The ERC-4337 EntryPoint address
    constructor(IEntryPoint _entryPoint) {
        entryPoint = _entryPoint;
    }

    /// @notice Modifier to restrict access to EntryPoint or self
    modifier onlyEntryPointOrSelf() {
        if (msg.sender != address(entryPoint) && msg.sender != address(this)) {
            revert Unauthorized();
        }
        _;
    }

    /// @notice Validate a UserOperation
    /// @param userOp The UserOperation to validate
    /// @param userOpHash Hash of the UserOperation
    /// @param missingAccountFunds Amount to pay to EntryPoint
    /// @return validationData 0 for success, 1 for failure
    function validateUserOp(
        UserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 missingAccountFunds
    ) external override returns (uint256 validationData) {
        if (msg.sender != address(entryPoint)) revert Unauthorized();

        // Validate signature
        validationData = _validateSignature(userOp, userOpHash);

        // Pay prefund if needed
        if (missingAccountFunds > 0) {
            (bool success, ) = payable(msg.sender).call{value: missingAccountFunds}("");
            // Ignore failure (EntryPoint will handle it)
            (success);
        }

        emit UserOpValidated(userOpHash, validationData);
    }

    /// @notice Validate signature for UserOp
    /// @param userOp The UserOperation
    /// @param userOpHash Hash of the UserOperation
    /// @return validationData 0 for success, 1 for failure
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal view returns (uint256) {
        // For EIP-7702: the EOA is the owner, recover signer from signature
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", userOpHash)
        );

        // Extract signature components
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

        // In EIP-7702 context, the owner is address(this) (the delegating EOA)
        if (recovered == address(this)) {
            return SIG_VALIDATION_SUCCESS;
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice Execute a call
    /// @param target Target address
    /// @param value ETH value
    /// @param data Calldata
    /// @return result Return data
    function execute(
        address target,
        uint256 value,
        bytes calldata data
    ) external payable override onlyEntryPointOrSelf returns (bytes memory result) {
        (bool success, bytes memory returnData) = target.call{value: value}(data);
        if (!success) {
            revert CallFailed(returnData);
        }

        emit Executed(target, value, data);
        return returnData;
    }

    /// @notice Execute multiple calls
    /// @param targets Array of target addresses
    /// @param values Array of ETH values
    /// @param datas Array of calldata
    /// @return results Array of return data
    function executeBatch(
        address[] calldata targets,
        uint256[] calldata values,
        bytes[] calldata datas
    ) external payable override onlyEntryPointOrSelf returns (bytes[] memory results) {
        uint256 length = targets.length;
        if (length != values.length || length != datas.length) {
            revert ArrayLengthMismatch();
        }

        results = new bytes[](length);

        for (uint256 i = 0; i < length; i++) {
            (bool success, bytes memory returnData) = targets[i].call{value: values[i]}(datas[i]);
            if (!success) {
                revert CallFailed(returnData);
            }
            results[i] = returnData;
            emit Executed(targets[i], values[i], datas[i]);
        }

        return results;
    }

    /// @notice Check if an address is authorized
    /// @param signer The address to check
    /// @return True if authorized (is self or EntryPoint)
    function isAuthorized(address signer) external view override returns (bool) {
        return signer == address(this) || signer == address(entryPoint);
    }

    /// @notice Get the nonce for this account
    /// @return The current nonce from EntryPoint
    function getNonce() public view returns (uint256) {
        return entryPoint.getNonce(address(this), 0);
    }

    /// @notice Deposit to EntryPoint for gas
    function addDeposit() public payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /// @notice Get deposit balance at EntryPoint
    /// @return The deposit balance
    function getDeposit() public view returns (uint256) {
        return entryPoint.balanceOf(address(this));
    }

    /// @notice Allow receiving ETH
    receive() external payable {}
}
