// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/MultisigLogic.sol";

/// @title MockTarget
/// @notice A mock contract for testing
contract MockTarget {
    uint256 public value;

    function setValue(uint256 _value) external {
        value = _value;
    }

    receive() external payable {}
}

/// @title MultisigLogicTest
/// @notice Test suite for MultisigLogic contract
contract MultisigLogicTest is Test {
    MultisigLogic public multisig;
    MockTarget public target;

    // Test signers
    uint256 public signer1Key = 0x1111;
    uint256 public signer2Key = 0x2222;
    uint256 public signer3Key = 0x3333;

    address public signer1;
    address public signer2;
    address public signer3;

    function setUp() public {
        multisig = new MultisigLogic();
        target = new MockTarget();

        signer1 = vm.addr(signer1Key);
        signer2 = vm.addr(signer2Key);
        signer3 = vm.addr(signer3Key);

        // Fund the multisig
        vm.deal(address(multisig), 10 ether);
    }

    function testInitialize() public {
        address[] memory signers = new address[](3);
        signers[0] = signer1;
        signers[1] = signer2;
        signers[2] = signer3;

        vm.prank(address(multisig));
        multisig.initialize(signers, 2);

        assertEq(multisig.getThreshold(), 2);
        assertEq(multisig.getSignerCount(), 3);
        assertEq(multisig.getSigner(0), signer1);
        assertEq(multisig.getSigner(1), signer2);
        assertEq(multisig.getSigner(2), signer3);
    }

    function testIsSigner() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        vm.prank(address(multisig));
        multisig.initialize(signers, 2);

        assertTrue(multisig.isSigner(signer1));
        assertTrue(multisig.isSigner(signer2));
        assertFalse(multisig.isSigner(signer3));
    }

    function testInvalidThresholdReverts() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        vm.prank(address(multisig));
        vm.expectRevert(MultisigLogic.InvalidThreshold.selector);
        multisig.initialize(signers, 0); // threshold = 0

        vm.prank(address(multisig));
        vm.expectRevert(MultisigLogic.InvalidThreshold.selector);
        multisig.initialize(signers, 3); // threshold > signers.length
    }

    function testDuplicateSignerReverts() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer1; // duplicate

        vm.prank(address(multisig));
        vm.expectRevert(MultisigLogic.DuplicateSigner.selector);
        multisig.initialize(signers, 2);
    }

    function testExecuteWithSignatures() public {
        // Initialize with 2-of-2 multisig
        address[] memory signers = new address[](2);
        // Sort signers in ascending order (required for signature verification)
        if (signer1 < signer2) {
            signers[0] = signer1;
            signers[1] = signer2;
        } else {
            signers[0] = signer2;
            signers[1] = signer1;
        }

        vm.prank(address(multisig));
        multisig.initialize(signers, 2);

        // Prepare transaction
        bytes memory data = abi.encodeWithSelector(MockTarget.setValue.selector, 42);
        uint256 nonce = multisig.getNonce();

        bytes32 txHash = multisig.getTransactionHash(address(target), 0, data, nonce);
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)
        );

        // Sign with both signers (in ascending address order)
        bytes memory signatures;
        if (signer1 < signer2) {
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signer1Key, ethSignedHash);
            (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signer2Key, ethSignedHash);
            signatures = abi.encodePacked(r1, s1, v1, r2, s2, v2);
        } else {
            (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(signer2Key, ethSignedHash);
            (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signer1Key, ethSignedHash);
            signatures = abi.encodePacked(r2, s2, v2, r1, s1, v1);
        }

        // Execute
        multisig.executeWithSignatures(address(target), 0, data, signatures);

        assertEq(target.value(), 42);
        assertEq(multisig.getNonce(), 1);
    }

    function testNotEnoughSignaturesReverts() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        vm.prank(address(multisig));
        multisig.initialize(signers, 2);

        bytes memory data = abi.encodeWithSelector(MockTarget.setValue.selector, 42);
        uint256 nonce = multisig.getNonce();

        bytes32 txHash = multisig.getTransactionHash(address(target), 0, data, nonce);
        bytes32 ethSignedHash = keccak256(
            abi.encodePacked("\x19Ethereum Signed Message:\n32", txHash)
        );

        // Only one signature
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(signer1Key, ethSignedHash);
        bytes memory signatures = abi.encodePacked(r1, s1, v1);

        vm.expectRevert(MultisigLogic.NotEnoughSignatures.selector);
        multisig.executeWithSignatures(address(target), 0, data, signatures);
    }

    function testIsAuthorized() public {
        address[] memory signers = new address[](2);
        signers[0] = signer1;
        signers[1] = signer2;

        vm.prank(address(multisig));
        multisig.initialize(signers, 2);

        assertTrue(multisig.isAuthorized(address(multisig)));
        assertTrue(multisig.isAuthorized(signer1));
        assertTrue(multisig.isAuthorized(signer2));
        assertFalse(multisig.isAuthorized(signer3));
    }
}
