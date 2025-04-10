package address

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/multiversx/mx-chain-core-go/hashing/sha256"
	"math"
)

var baseSeed = []byte(core.OneAddressPrefix + "PublicKey")

var sha256Hasher = sha256.NewSha256()

func enhanceBaseSeed(
	sourceAddress []byte,
	sourceIdentifier core.AddressIdentifier,
	targetIdentifier core.AddressIdentifier,
) []byte {
	seed := append(baseSeed, sourceAddress...)
	seed = append(seed, sourceIdentifier.Spread()...)
	return append(seed, targetIdentifier.Spread()...)
}

func generateOffCurvePublicKey(seed []byte, generator func([]byte) ([]byte, error)) ([]byte, error) {
	for bump := math.MaxUint8; bump >= 0; bump-- {
		bumpedSeed := append(seed, byte(bump))
		publicKey, err := generator(bumpedSeed)
		if err != nil {
			continue
		}

		return publicKey, nil
	}
	return nil, ErrFailedToGenerateOffCurvePublicKey
}

func isSourceInvalid(sourceAddress []byte, sourceIdentifier core.AddressIdentifier) bool {
	switch sourceIdentifier {
	case core.MVXAddressIdentifier:
		return isPseudoMultiversXAddress(sourceAddress)
	case core.ETHAddressIdentifier:
		return isPseudoEthereumAddress(sourceAddress)
	default:
		return true
	}
}

func generatePseudoAddressForSeed(seed []byte, targetIdentifier core.AddressIdentifier) ([]byte, error) {
	switch targetIdentifier {
	case core.MVXAddressIdentifier:
		return generatePseudoMultiversXAddress(seed)
	case core.ETHAddressIdentifier:
		return generatePseudoEthereumAddress(seed)
	default:
		return nil, ErrAddressIdentifierNotHandled
	}
}

func GeneratePseudoAddress(
	sourceAddress []byte,
	sourceIdentifier core.AddressIdentifier,
	targetIdentifier core.AddressIdentifier,
) ([]byte, error) {
	if sourceIdentifier == targetIdentifier {
		return nil, ErrSourceIdentifierMatchesTargetIdentifier
	}
	if isSourceInvalid(sourceAddress, sourceIdentifier) {
		return nil, ErrSourceAddressIsGenerated
	}
	seed := enhanceBaseSeed(sourceAddress, sourceIdentifier, targetIdentifier)
	return generatePseudoAddressForSeed(seed, targetIdentifier)
}

func ConvertAddressToPseudoAddress(sourceAddress []byte, sourceIdentifier core.AddressIdentifier) ([]byte, error) {
	switch sourceIdentifier {
	case core.MVXAddressIdentifier:
		return convertMultiversXAddressToPseudoAddress(sourceAddress)
	case core.ETHAddressIdentifier:
		return convertEthereumAddressToPseudoAddress(sourceAddress)
	default:
		return nil, ErrAddressIdentifierNotHandled
	}
}
