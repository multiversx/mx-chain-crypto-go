package address

import (
	"bytes"
	ethCommon "github.com/ethereum/go-ethereum/common"
)

var ethAddressSize = ethCommon.AddressLength

var ethereumPseudoAddressPrefix = []byte{'e', 't', 'h', '-', '-', 'o', 'n', 'e'}

func generatePseudoEthereumAddress(seed []byte) ([]byte, error) {
	baseAddress := sha256Hasher.Compute(string(seed))[:ethAddressSize]
	return convertEthereumAddressToPseudoAddress(baseAddress)
}

func isPseudoEthereumAddress(address []byte) bool {
	return bytes.HasPrefix(address, ethereumPseudoAddressPrefix)
}

func convertEthereumAddressToPseudoAddress(address []byte) ([]byte, error) {
	if len(address) != ethAddressSize {
		return nil, ErrInvalidAddressSizeForPseudoConversion
	}

	pseudoAddress := make([]byte, ethAddressSize)
	copy(pseudoAddress, address)
	copy(pseudoAddress, ethereumPseudoAddressPrefix)
	return pseudoAddress, nil
}
