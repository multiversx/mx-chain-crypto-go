package signing

import (
	"fmt"
	"github.com/multiversx/mx-chain-crypto-go"
)

var _ crypto.KeyGenerator = (*MultiKeyGenerator)(nil)

var _ crypto.SingleSigner = (*MultiSingleSigner)(nil)

// MultiKeyGenerator handles a set of key generators - selector based
type MultiKeyGenerator struct {
	crypto.KeyGenerator
	MainSelector    string
	OtherGenerators map[string]crypto.KeyGenerator
}

// MultiSingleSigner handles a set of single singers - selector based
type MultiSingleSigner struct {
	crypto.SingleSigner
	MainSelector string
	OtherSigners map[string]crypto.SingleSigner
}

// ChooseKeyGenerator returns the key generator to be used based on the given selector
func (kg *MultiKeyGenerator) ChooseKeyGenerator(selector string) (crypto.KeyGenerator, error) {
	return chooseForSelector(selector, kg.MainSelector, kg.KeyGenerator, kg.OtherGenerators)
}

// ChooseSingleSigner returns the single signer to be used based on the given selector
func (ss *MultiSingleSigner) ChooseSingleSigner(selector string) (crypto.SingleSigner, error) {
	return chooseForSelector(selector, ss.MainSelector, ss.SingleSigner, ss.OtherSigners)
}

func chooseForSelector[T interface{}](selector string, mainSelector string, mainItem T, otherItems map[string]T) (T, error) {
	if selector != mainSelector {
		otherItem, found := otherItems[selector]
		if !found {
			return otherItem, fmt.Errorf("%w: %v", crypto.ErrImplementationNotDefinedForSelector, selector)
		}
		return otherItem, nil
	}
	return mainItem, nil
}
