// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Script.sol";
import "../src/BatchExecutor.sol";
import "../src/SimpleAccount.sol";
import "../src/MultisigLogic.sol";
import "../src/SessionKeyManager.sol";
import "../src/PaymasterHelper.sol";
import "../src/interfaces/IEntryPoint.sol";

/// @title Deploy
/// @notice Deployment script for EIP-7702 contracts
contract Deploy is Script {
    // Sepolia EntryPoint v0.6
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        // Deploy BatchExecutor (no constructor args)
        BatchExecutor batchExecutor = new BatchExecutor();
        console.log("BatchExecutor deployed at:", address(batchExecutor));

        // Deploy SimpleAccount with EntryPoint
        SimpleAccount simpleAccount = new SimpleAccount(IEntryPoint(ENTRYPOINT_V06));
        console.log("SimpleAccount deployed at:", address(simpleAccount));

        // Deploy MultisigLogic (no constructor args)
        MultisigLogic multisigLogic = new MultisigLogic();
        console.log("MultisigLogic deployed at:", address(multisigLogic));

        // Deploy SessionKeyManager (no constructor args)
        SessionKeyManager sessionKeyManager = new SessionKeyManager();
        console.log("SessionKeyManager deployed at:", address(sessionKeyManager));

        // Deploy PaymasterHelper with EntryPoint
        PaymasterHelper paymasterHelper = new PaymasterHelper(IEntryPoint(ENTRYPOINT_V06));
        console.log("PaymasterHelper deployed at:", address(paymasterHelper));

        vm.stopBroadcast();

        // Output summary
        console.log("\n=== Deployment Summary ===");
        console.log("Network: Sepolia (Chain ID: 11155111)");
        console.log("EntryPoint: ", ENTRYPOINT_V06);
        console.log("\nContracts:");
        console.log("  BatchExecutor:     ", address(batchExecutor));
        console.log("  SimpleAccount:     ", address(simpleAccount));
        console.log("  MultisigLogic:     ", address(multisigLogic));
        console.log("  SessionKeyManager: ", address(sessionKeyManager));
        console.log("  PaymasterHelper:   ", address(paymasterHelper));
    }
}

/// @title DeployBatchExecutor
/// @notice Deploy only BatchExecutor
contract DeployBatchExecutor is Script {
    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        BatchExecutor batchExecutor = new BatchExecutor();
        console.log("BatchExecutor deployed at:", address(batchExecutor));

        vm.stopBroadcast();
    }
}

/// @title DeploySimpleAccount
/// @notice Deploy only SimpleAccount
contract DeploySimpleAccount is Script {
    address constant ENTRYPOINT_V06 = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    function run() external {
        uint256 deployerPrivateKey = vm.envUint("PRIVATE_KEY");

        vm.startBroadcast(deployerPrivateKey);

        SimpleAccount simpleAccount = new SimpleAccount(IEntryPoint(ENTRYPOINT_V06));
        console.log("SimpleAccount deployed at:", address(simpleAccount));

        vm.stopBroadcast();
    }
}
