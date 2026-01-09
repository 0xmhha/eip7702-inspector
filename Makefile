# EIP-7702 Inspector Makefile
# Build and run commands for the EIP-7702 verification tool

# Load .env file if exists
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Binary name
BINARY_NAME := eip7702-inspector
BUILD_DIR := build
INSTALL_DIR := /usr/local/bin

# Go parameters
GOCMD := go
GOBUILD := $(GOCMD) build
GOTEST := $(GOCMD) test
GOMOD := $(GOCMD) mod
GOVET := $(GOCMD) vet
GOFMT := gofmt

# Build flags
LDFLAGS := -s -w
BUILD_FLAGS := -ldflags "$(LDFLAGS)"

# Default target
.DEFAULT_GOAL := help

##@ Build

.PHONY: build
build: ## Build the binary
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) $(BUILD_FLAGS) -o $(BUILD_DIR)/$(BINARY_NAME) .

.PHONY: build-debug
build-debug: ## Build with debug symbols
	@mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) .

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

.PHONY: install
install: build ## Install binary to /usr/local/bin (may require sudo)
	@echo "Installing to $(INSTALL_DIR)/$(BINARY_NAME)"
	sudo cp $(BUILD_DIR)/$(BINARY_NAME) $(INSTALL_DIR)/
	@echo "Installed! Run '$(BINARY_NAME)' from anywhere."

.PHONY: uninstall
uninstall: ## Remove installed binary
	@echo "Removing $(INSTALL_DIR)/$(BINARY_NAME)"
	sudo rm -f $(INSTALL_DIR)/$(BINARY_NAME)
	@echo "Uninstalled."

.PHONY: install-user
install-user: build ## Install binary to ~/bin (no sudo required)
	@mkdir -p $(HOME)/bin
	cp $(BUILD_DIR)/$(BINARY_NAME) $(HOME)/bin/
	@echo "Installed to ~/bin/$(BINARY_NAME)"
	@echo "Make sure ~/bin is in your PATH"

##@ Development

.PHONY: deps
deps: ## Download dependencies
	$(GOMOD) download
	$(GOMOD) tidy

.PHONY: fmt
fmt: ## Format code
	$(GOFMT) -s -w .

.PHONY: vet
vet: ## Run go vet
	$(GOVET) ./...

.PHONY: lint
lint: fmt vet ## Run all linters

.PHONY: test
test: ## Run tests
	$(GOTEST) -v ./...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

##@ Run Commands

.PHONY: run
run: build ## Run with default settings
	./$(BUILD_DIR)/$(BINARY_NAME)

.PHONY: quick
quick: build ## Run quick verification
	./$(BUILD_DIR)/$(BINARY_NAME) -quick

.PHONY: verbose
verbose: build ## Run full inspection with verbose output
	./$(BUILD_DIR)/$(BINARY_NAME) -verbose

.PHONY: network
network: build ## Run network tests (requires RPC)
	./$(BUILD_DIR)/$(BINARY_NAME) -network

.PHONY: security
security: build ## Run security analysis (requires -target)
	@if [ -z "$(TARGET)" ]; then \
		echo "Usage: make security TARGET=0x..."; \
		exit 1; \
	fi
	./$(BUILD_DIR)/$(BINARY_NAME) -security -target $(TARGET)

.PHONY: attack
attack: build ## Run attack simulations
	./$(BUILD_DIR)/$(BINARY_NAME) -attack

.PHONY: validate
validate: build ## Run validation checks
	./$(BUILD_DIR)/$(BINARY_NAME) -validate

##@ Delegation

.PHONY: delegate
delegate: build ## Send SetCode transaction to delegate EOA to target (usage: make delegate ADDR=0x...)
	@if [ -z "$(ADDR)" ]; then \
		echo "Usage: make delegate ADDR=0x..."; \
		exit 1; \
	fi
	@echo "Delegating EOA to: $(ADDR)"
	./$(BUILD_DIR)/$(BINARY_NAME) -delegate -target $(ADDR)

.PHONY: delegate-target
delegate-target: build ## Send SetCode transaction using TARGET_ADDRESS from .env
	@if [ -z "$(TARGET_ADDRESS)" ]; then \
		echo "Error: TARGET_ADDRESS not set. Use 'make set-target ADDR=0x...' first"; \
		exit 1; \
	fi
	@echo "Delegating EOA to: $(TARGET_ADDRESS)"
	./$(BUILD_DIR)/$(BINARY_NAME) -delegate -target $(TARGET_ADDRESS)

.PHONY: revoke-delegation
revoke-delegation: build ## Revoke delegation by setting code to 0x0
	@echo "Revoking delegation (setting code to 0x0)..."
	./$(BUILD_DIR)/$(BINARY_NAME) -delegate -target 0x0000000000000000000000000000000000000000

##@ Presets

.PHONY: presets
presets: build ## List available chain presets
	./$(BUILD_DIR)/$(BINARY_NAME) -list-presets

.PHONY: local
local: build ## Run with local preset (Anvil/Hardhat)
	./$(BUILD_DIR)/$(BINARY_NAME) -preset local -network

.PHONY: sepolia
sepolia: build ## Run with Sepolia preset
	./$(BUILD_DIR)/$(BINARY_NAME) -preset sepolia -network

.PHONY: holesky
holesky: build ## Run with Holesky preset
	./$(BUILD_DIR)/$(BINARY_NAME) -preset holesky -network

.PHONY: mainnet
mainnet: build ## Run with Mainnet preset
	./$(BUILD_DIR)/$(BINARY_NAME) -preset mainnet -network

##@ Environment

.PHONY: env-setup
env-setup: ## Create .env from .env.example
	@if [ ! -f .env ]; then \
		cp .env.example .env; \
		echo "Created .env from .env.example"; \
		echo "Please edit .env with your configuration"; \
	else \
		echo ".env already exists"; \
	fi

.PHONY: env-show
env-show: ## Show current .env configuration
	@if [ -f .env ]; then \
		echo "=== Current .env configuration ==="; \
		grep -v '^#' .env | grep -v '^$$'; \
	else \
		echo "No .env file found. Run 'make env-setup' first."; \
	fi

.PHONY: set-target
set-target: ## Set TARGET_ADDRESS in .env (usage: make set-target ADDR=0x...)
	@if [ -z "$(ADDR)" ]; then \
		echo "Usage: make set-target ADDR=0x..."; \
		exit 1; \
	fi
	@if grep -q "^TARGET_ADDRESS=" .env 2>/dev/null; then \
		sed -i.bak 's|^TARGET_ADDRESS=.*|TARGET_ADDRESS=$(ADDR)|' .env && rm -f .env.bak; \
	else \
		echo "TARGET_ADDRESS=$(ADDR)" >> .env; \
	fi
	@echo "TARGET_ADDRESS set to: $(ADDR)"

.PHONY: show-target
show-target: ## Show current TARGET_ADDRESS
	@if [ -f .env ]; then \
		grep "^TARGET_ADDRESS=" .env 2>/dev/null || echo "TARGET_ADDRESS not set"; \
	else \
		echo "No .env file"; \
	fi

##@ Contracts (Foundry)

.PHONY: contracts-build
contracts-build: ## Build Solidity contracts
	cd contracts && forge build

.PHONY: contracts-test
contracts-test: ## Test Solidity contracts
	cd contracts && forge test

.PHONY: contracts-clean
contracts-clean: ## Clean contract build artifacts
	cd contracts && forge clean

##@ Deploy Contracts

.PHONY: deploy
deploy: contracts-build ## Deploy all contracts (uses RPC_URL from .env)
	@if [ -z "$(RPC_URL)" ]; then \
		echo "Error: RPC_URL not set. Set it in .env or pass RPC_URL=<url>"; \
		exit 1; \
	fi
	@echo "Deploying to: $(RPC_URL)"
	cd contracts && forge script script/Deploy.s.sol:Deploy \
		--rpc-url $(RPC_URL) \
		--broadcast \
		--slow \
		-vvv

.PHONY: deploy-batch-executor
deploy-batch-executor: contracts-build ## Deploy BatchExecutor only
	@if [ -z "$(RPC_URL)" ]; then \
		echo "Error: RPC_URL not set. Set it in .env or pass RPC_URL=<url>"; \
		exit 1; \
	fi
	cd contracts && forge script script/Deploy.s.sol:DeployBatchExecutor \
		--rpc-url $(RPC_URL) \
		--broadcast \
		--slow \
		-vvv

.PHONY: deploy-simple-account
deploy-simple-account: contracts-build ## Deploy SimpleAccount only
	@if [ -z "$(RPC_URL)" ]; then \
		echo "Error: RPC_URL not set. Set it in .env or pass RPC_URL=<url>"; \
		exit 1; \
	fi
	cd contracts && forge script script/Deploy.s.sol:DeploySimpleAccount \
		--rpc-url $(RPC_URL) \
		--broadcast \
		--slow \
		-vvv

.PHONY: deploy-dry-run
deploy-dry-run: contracts-build ## Simulate deploy without broadcasting
	@if [ -z "$(RPC_URL)" ]; then \
		echo "Error: RPC_URL not set. Set it in .env or pass RPC_URL=<url>"; \
		exit 1; \
	fi
	@echo "Simulating deploy to: $(RPC_URL)"
	cd contracts && forge script script/Deploy.s.sol:Deploy \
		--rpc-url $(RPC_URL) \
		-vvv

.PHONY: deploy-local
deploy-local: contracts-build ## Deploy to local Anvil node (localhost:8545)
	cd contracts && forge script script/Deploy.s.sol:Deploy \
		--rpc-url http://localhost:8545 \
		--broadcast \
		--slow \
		-vvv

##@ SetCode Validation Tests

.PHONY: contracts-test-setcode
contracts-test-setcode: ## Run SetCode validation Foundry tests
	cd contracts && forge test --match-contract SetCodeValidation -vv

.PHONY: deploy-test-target
deploy-test-target: contracts-build ## Deploy SetCodeTestTarget contract for CA validation
	@if [ -z "$(RPC_URL)" ]; then \
		echo "Error: RPC_URL not set. Set it in .env or pass RPC_URL=<url>"; \
		exit 1; \
	fi
	@echo "Deploying SetCodeTestTarget to: $(RPC_URL)"
	cd contracts && forge create src/SetCodeTestTarget.sol:SetCodeTestTarget \
		--rpc-url $(RPC_URL) \
		--broadcast

.PHONY: test-ca-authority
test-ca-authority: build ## Test that CA cannot be SetCode authority (usage: make test-ca-authority ADDR=0x<contract>)
	@if [ -z "$(ADDR)" ]; then \
		echo "Usage: make test-ca-authority ADDR=0x<contract-address>"; \
		echo ""; \
		echo "This tests that a Contract Account (CA) cannot be used as SetCode authority."; \
		echo "Expected result: SetCode authorization should fail with ErrAuthorizationDestinationHasCode"; \
		exit 1; \
	fi
	@echo "Testing CA cannot be SetCode authority: $(ADDR)"
	./$(BUILD_DIR)/$(BINARY_NAME) -network -target $(ADDR) -verbose

.PHONY: test-setcode-to-contract
test-setcode-to-contract: build ## Test SetCode delegation to contract target (usage: make test-setcode-to-contract ADDR=0x<contract>)
	@if [ -z "$(ADDR)" ]; then \
		echo "Usage: make test-setcode-to-contract ADDR=0x<contract-address>"; \
		echo ""; \
		echo "This tests delegating an EOA to a contract address."; \
		echo "Expected result: SetCode should succeed (spec allows delegation to contract targets)"; \
		exit 1; \
	fi
	@echo "Testing SetCode delegation to contract: $(ADDR)"
	./$(BUILD_DIR)/$(BINARY_NAME) -delegate -target $(ADDR)

.PHONY: ca-validation-workflow
ca-validation-workflow: ## Show CA validation testing workflow
	@echo ""
	@echo "=== Contract Account (CA) SetCode Validation Workflow ==="
	@echo ""
	@echo "This workflow tests EIP-7702 validation rules:"
	@echo "  - CA (Contract Account) CANNOT be SetCode authority"
	@echo "  - EOA CAN delegate to contract target"
	@echo ""
	@echo "1. Run Foundry unit tests:"
	@echo "   make contracts-test-setcode"
	@echo ""
	@echo "2. Generate genesis.json entry for CA test:"
	@echo "   make genesis-ca-entry"
	@echo "   # Copy the output to your genesis.json alloc section"
	@echo ""
	@echo "3. Start node with modified genesis, then test:"
	@echo "   make test-ca-setcode-rejection"
	@echo "   # Should fail with: ErrAuthorizationDestinationHasCode"
	@echo ""
	@echo "=== Quick Test ==="
	@echo "  make contracts-test-setcode    # Run all SetCode validation tests"
	@echo "  make genesis-ca-entry          # Generate genesis.json entry"
	@echo ""

.PHONY: genesis-ca-entry
genesis-ca-entry: contracts-build ## Generate genesis.json entry for CA SetCode test
	@echo ""
	@echo "=== Genesis.json Entry for CA SetCode Test ==="
	@echo ""
	@echo "Add this to your genesis.json 'alloc' section to test CA cannot be SetCode authority."
	@echo ""
	@echo "Test Account (DO NOT USE IN PRODUCTION):"
	@echo "  Private Key: 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	@echo "  Address:     0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266"
	@echo ""
	@echo "Genesis.json entry:"
	@echo "----------------------------------------"
	@echo '"0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266": {'
	@echo '  "balance": "10000000000000000000000",'
	@printf '  "code": "'
	@cd contracts && cat out/SetCodeTestTarget.sol/SetCodeTestTarget.json | jq -r '.deployedBytecode.object'
	@echo '"'
	@echo '}'
	@echo "----------------------------------------"
	@echo ""
	@echo "After adding to genesis.json:"
	@echo "  1. Restart your node with the new genesis"
	@echo "  2. Set CA_TEST_KEY in .env:"
	@echo "     CA_TEST_KEY=ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
	@echo "  3. Run: make test-ca-setcode-rejection"
	@echo ""

.PHONY: genesis-ca-json
genesis-ca-json: contracts-build ## Output genesis.json entry as valid JSON (for scripting)
	@echo '{'
	@echo '  "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266": {'
	@echo '    "balance": "10000000000000000000000",'
	@printf '    "code": "%s"\n' "$$(cd contracts && cat out/SetCodeTestTarget.sol/SetCodeTestTarget.json | jq -r '.deployedBytecode.object')"
	@echo '  }'
	@echo '}'

.PHONY: test-ca-setcode-rejection
test-ca-setcode-rejection: build ## Test that CA with code cannot be SetCode authority
	@if [ -z "$(CA_TEST_KEY)" ]; then \
		echo "Error: CA_TEST_KEY not set."; \
		echo ""; \
		echo "This test requires a genesis.json with pre-loaded contract code."; \
		echo "Run 'make genesis-ca-entry' for setup instructions."; \
		echo ""; \
		echo "Set CA_TEST_KEY in .env or pass it directly:"; \
		echo "  make test-ca-setcode-rejection CA_TEST_KEY=<private-key>"; \
		exit 1; \
	fi
	@echo "Testing CA cannot be SetCode authority..."
	@echo "Expected result: Transaction should be REJECTED with ErrAuthorizationDestinationHasCode"
	@echo ""
	CA_TEST_KEY=$(CA_TEST_KEY) ./$(BUILD_DIR)/$(BINARY_NAME) -test-ca-authority

##@ EIP-7702 Test Workflow

.PHONY: test-eip7702
test-eip7702: build ## Run EIP-7702 network test with current TARGET_ADDRESS
	@if [ -z "$(TARGET_ADDRESS)" ]; then \
		echo "Error: TARGET_ADDRESS not set. Use 'make set-target ADDR=0x...' first"; \
		exit 1; \
	fi
	@echo "Testing EIP-7702 with target: $(TARGET_ADDRESS)"
	./$(BUILD_DIR)/$(BINARY_NAME) -network -target $(TARGET_ADDRESS)

.PHONY: test-delegation
test-delegation: build ## Run delegation test with specified address (usage: make test-delegation ADDR=0x...)
	@if [ -z "$(ADDR)" ]; then \
		echo "Usage: make test-delegation ADDR=0x..."; \
		exit 1; \
	fi
	@echo "Testing delegation to: $(ADDR)"
	./$(BUILD_DIR)/$(BINARY_NAME) -network -target $(ADDR)

.PHONY: workflow
workflow: ## Show recommended workflow for EIP-7702 testing
	@echo ""
	@echo "=== EIP-7702 Testing Workflow ==="
	@echo ""
	@echo "1. Setup environment:"
	@echo "   make env-setup"
	@echo "   # Edit .env with your PRIVATE_KEY, RPC_URL, CHAIN_ID"
	@echo ""
	@echo "2. Deploy contracts:"
	@echo "   make deploy"
	@echo "   # Note the deployed contract address (e.g., BatchExecutor)"
	@echo ""
	@echo "3. Send SetCode transaction to delegate EOA to contract:"
	@echo "   make delegate ADDR=0x<deployed-contract-address>"
	@echo "   # This sends an EIP-7702 SetCode transaction on-chain"
	@echo ""
	@echo "4. (Optional) Save target address for later:"
	@echo "   make set-target ADDR=0x<deployed-contract-address>"
	@echo "   # Only updates .env file, does NOT send transaction"
	@echo ""
	@echo "5. Run EIP-7702 network tests:"
	@echo "   make test-eip7702"
	@echo ""
	@echo "6. Or delegate and test in one step:"
	@echo "   make delegate ADDR=0x<address> && make test-delegation ADDR=0x<address>"
	@echo ""
	@echo "=== Quick Commands ==="
	@echo "  make delegate ADDR=0x...      # Send SetCode tx to delegate"
	@echo "  make delegate-target          # Send SetCode tx using TARGET_ADDRESS from .env"
	@echo "  make set-target ADDR=0x...    # Save target to .env (no tx)"
	@echo "  make test-eip7702             # Run tests with TARGET_ADDRESS"
	@echo ""
	@echo "=== Current Configuration ==="
	@make -s env-show
	@echo ""

##@ Help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

.PHONY: version
version: build ## Show version info
	@echo "EIP-7702 Inspector"
	@echo "Go version: $$(go version)"
	@./$(BUILD_DIR)/$(BINARY_NAME) -help 2>&1 | head -1
