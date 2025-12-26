// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/BatchExecutor.sol";

/// @title MockTarget
/// @notice A mock contract for testing batch execution
contract MockTarget {
    uint256 public value;
    event ValueSet(uint256 newValue);

    function setValue(uint256 _value) external payable {
        value = _value;
        emit ValueSet(_value);
    }

    function revertingCall() external pure {
        revert("intentional revert");
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    receive() external payable {}
}

/// @title BatchExecutorTest
/// @notice Test suite for BatchExecutor contract
contract BatchExecutorTest is Test {
    BatchExecutor public executor;
    MockTarget public target1;
    MockTarget public target2;

    address public user = address(0x1234);

    function setUp() public {
        executor = new BatchExecutor();
        target1 = new MockTarget();
        target2 = new MockTarget();

        // Fund the user
        vm.deal(user, 10 ether);
    }

    function testExecuteSingleCall() public {
        bytes memory data = abi.encodeWithSelector(MockTarget.setValue.selector, 42);

        vm.prank(address(executor)); // Simulate EIP-7702 context
        bytes memory result = executor.execute(address(target1), 0, data);

        assertEq(target1.value(), 42);
    }

    function testExecuteBatch() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(target1);
        targets[1] = address(target2);

        values[0] = 0;
        values[1] = 0;

        datas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 100);
        datas[1] = abi.encodeWithSelector(MockTarget.setValue.selector, 200);

        vm.prank(address(executor));
        bytes[] memory results = executor.executeBatch(targets, values, datas);

        assertEq(results.length, 2);
        assertEq(target1.value(), 100);
        assertEq(target2.value(), 200);
    }

    function testExecuteBatchWithValue() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(target1);
        targets[1] = address(target2);

        values[0] = 1 ether;
        values[1] = 2 ether;

        datas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 1);
        datas[1] = abi.encodeWithSelector(MockTarget.setValue.selector, 2);

        vm.deal(address(executor), 5 ether);
        vm.prank(address(executor));
        executor.executeBatch{value: 3 ether}(targets, values, datas);

        assertEq(address(target1).balance, 1 ether);
        assertEq(address(target2).balance, 2 ether);
    }

    function testExecuteBatchRevertsOnFailure() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(target1);
        targets[1] = address(target1);

        values[0] = 0;
        values[1] = 0;

        datas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 100);
        datas[1] = abi.encodeWithSelector(MockTarget.revertingCall.selector);

        vm.prank(address(executor));
        vm.expectRevert();
        executor.executeBatch(targets, values, datas);
    }

    function testExecuteBatchWithFallbackContinuesOnFailure() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](2);
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(target1);
        targets[1] = address(target1);

        values[0] = 0;
        values[1] = 0;

        datas[0] = abi.encodeWithSelector(MockTarget.setValue.selector, 100);
        datas[1] = abi.encodeWithSelector(MockTarget.revertingCall.selector);

        vm.prank(address(executor));
        (bytes[] memory results, bool[] memory successes) = executor.executeBatchWithFallback(
            targets,
            values,
            datas,
            true // continueOnFail
        );

        assertEq(results.length, 2);
        assertTrue(successes[0]);
        assertFalse(successes[1]);
        assertEq(target1.value(), 100);
    }

    function testArrayLengthMismatchReverts() public {
        address[] memory targets = new address[](2);
        uint256[] memory values = new uint256[](1); // Mismatch
        bytes[] memory datas = new bytes[](2);

        targets[0] = address(target1);
        targets[1] = address(target2);
        values[0] = 0;
        datas[0] = "";
        datas[1] = "";

        vm.prank(address(executor));
        vm.expectRevert(BatchExecutor.ArrayLengthMismatch.selector);
        executor.executeBatch(targets, values, datas);
    }

    function testIsAuthorized() public view {
        assertTrue(executor.isAuthorized(address(executor)));
        assertFalse(executor.isAuthorized(address(0x9999)));
    }

    function testReceiveEther() public {
        vm.deal(user, 1 ether);
        vm.prank(user);
        (bool success, ) = address(executor).call{value: 1 ether}("");
        assertTrue(success);
        assertEq(address(executor).balance, 1 ether);
    }
}
