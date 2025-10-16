module github.com/multiversx/mx-chain-crypto-go

go 1.23.0

toolchain go1.24.9

replace github.com/multiversx/mx-chain-core-go => github.com/multiversx/mx-chain-core-sovereign-go v1.2.25-0.20251016085427-f3e9cd4fff15

require (
	filippo.io/edwards25519 v1.0.0
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1
	github.com/ethereum/go-ethereum v1.13.15
	github.com/herumi/bls-go-binary v1.28.2
	github.com/multiversx/mx-chain-core-go v1.4.0
	github.com/multiversx/mx-chain-logger-go v1.1.0
	github.com/stretchr/testify v1.8.4
	golang.org/x/crypto v0.33.0
)

require (
	github.com/btcsuite/btcd/btcec/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/denisbrodbeck/machineid v1.0.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/holiman/uint256 v1.2.4 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
	github.com/pelletier/go-toml v1.9.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
