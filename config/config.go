// Package config provides configuration management for EIP-7702 Inspector
// with support for environment variables and chain presets.
package config

import (
	"fmt"
	"math/big"
	"os"
	"sort"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all configuration values
type Config struct {
	ChainID    *big.Int
	RPCURL     string
	PrivateKey string
	Address    string
}

// ChainPreset represents a predefined chain configuration
type ChainPreset struct {
	Name    string
	ChainID *big.Int
	RPCURL  string
}

// ChainPresets contains predefined configurations for common networks
var ChainPresets = map[string]ChainPreset{
	"local": {
		Name:    "local",
		ChainID: big.NewInt(31337),
		RPCURL:  "http://localhost:8545",
	},
	"mainnet": {
		Name:    "mainnet",
		ChainID: big.NewInt(1),
		RPCURL:  "https://eth.llamarpc.com",
	},
	"sepolia": {
		Name:    "sepolia",
		ChainID: big.NewInt(11155111),
		RPCURL:  "https://rpc.sepolia.org",
	},
	"holesky": {
		Name:    "holesky",
		ChainID: big.NewInt(17000),
		RPCURL:  "https://rpc.holesky.ethpandaops.io",
	},
	"goerli": {
		Name:    "goerli",
		ChainID: big.NewInt(5),
		RPCURL:  "https://rpc.goerli.mudit.blog",
	},
}

// LoadConfig loads configuration from .env file
// It silently ignores if the file doesn't exist
func LoadConfig(envPath string) error {
	if envPath != "" {
		return godotenv.Load(envPath)
	}
	// Try to load from current directory, ignore if not exists
	_ = godotenv.Load()
	return nil
}

// GetChainID returns chain ID from environment variable or default
func GetChainID() *big.Int {
	if val := os.Getenv("CHAIN_ID"); val != "" {
		if id, ok := new(big.Int).SetString(val, 10); ok {
			return id
		}
	}
	// Check if preset is specified
	if preset := os.Getenv("CHAIN_PRESET"); preset != "" {
		if p, ok := GetChainPreset(preset); ok {
			return p.ChainID
		}
	}
	return big.NewInt(1) // Default: mainnet
}

// GetRPCURL returns RPC URL from environment variable or default
func GetRPCURL() string {
	if val := os.Getenv("RPC_URL"); val != "" {
		return val
	}
	// Check if preset is specified
	if preset := os.Getenv("CHAIN_PRESET"); preset != "" {
		if p, ok := GetChainPreset(preset); ok {
			return p.RPCURL
		}
	}
	return "http://localhost:8545"
}

// GetPrivateKey returns private key from environment variable
// Returns empty string if not set
func GetPrivateKey() string {
	key := os.Getenv("PRIVATE_KEY")
	return strings.TrimPrefix(key, "0x")
}

// GetAddress returns address from environment variable (optional)
func GetAddress() string {
	return os.Getenv("ADDRESS")
}

// GetTargetAddress returns delegation target address from environment variable
// Returns empty string if not set
func GetTargetAddress() string {
	return os.Getenv("TARGET_ADDRESS")
}

// GetChainPreset returns a preset by name (case-insensitive)
func GetChainPreset(name string) (ChainPreset, bool) {
	preset, ok := ChainPresets[strings.ToLower(name)]
	return preset, ok
}

// ApplyPreset returns configuration from a named preset
func ApplyPreset(name string) (*Config, error) {
	preset, ok := GetChainPreset(name)
	if !ok {
		return nil, fmt.Errorf("unknown chain preset: %s (available: %s)", name, strings.Join(ListPresets(), ", "))
	}
	return &Config{
		ChainID: preset.ChainID,
		RPCURL:  preset.RPCURL,
	}, nil
}

// ListPresets returns all available preset names sorted alphabetically
func ListPresets() []string {
	names := make([]string, 0, len(ChainPresets))
	for name := range ChainPresets {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// PrintPresets prints all available presets to stdout
func PrintPresets() {
	fmt.Println("Available chain presets:")
	names := ListPresets()
	for _, name := range names {
		p := ChainPresets[name]
		fmt.Printf("  %-10s chainId: %-10s rpc: %s\n", name, p.ChainID.String(), p.RPCURL)
	}
}
