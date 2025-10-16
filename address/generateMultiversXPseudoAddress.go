package address

import (
	"bytes"
	"filippo.io/edwards25519"
	"github.com/multiversx/mx-chain-core-go/core"
)

var mvxAddressSize = len(core.SystemAccountAddress)

var multiversXPseudoAddressPrefix = []byte{'m', 'v', 'x', '-', '-', 'o', 'n', 'e'}

func generatePseudoMultiversXAddress(seed []byte) ([]byte, error) {
	return generateOffCurvePublicKey(seed, func(bumpedSeed []byte) ([]byte, error) {
		baseAddress := sha256Hasher.Compute(string(bumpedSeed))[:mvxAddressSize]
		generatedAddress, err := convertMultiversXAddressToPseudoAddress(baseAddress)
		if err != nil {
			return nil, err
		}
		if core.IsSmartContractAddress(generatedAddress) {
			return nil, ErrGeneratedAddressIsSmartContractAddress
		}
		if _, err = new(edwards25519.Point).SetBytes(generatedAddress); err != nil {
			return nil, err
		}

		return generatedAddress, nil
	})
}

func isPseudoMultiversXAddress(address []byte) bool {
	return bytes.HasPrefix(referenceMultiversXPseudoAddressPrefix(address), multiversXPseudoAddressPrefix)
}

func convertMultiversXAddressToPseudoAddress(address []byte) ([]byte, error) {
	if len(address) != mvxAddressSize {
		return nil, ErrInvalidAddressSizeForPseudoConversion
	}

	pseudoAddress := make([]byte, mvxAddressSize)
	copy(pseudoAddress, address)
	copy(referenceMultiversXPseudoAddressPrefix(pseudoAddress), multiversXPseudoAddressPrefix)
	return pseudoAddress, nil
}

func referenceMultiversXPseudoAddressPrefix(address []byte) []byte {
	if core.IsSmartContractAddress(address) {
		return address[core.NumInitCharactersForScAddress:]
	}
	return address
}
