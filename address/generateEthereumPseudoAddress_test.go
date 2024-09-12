package address

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGeneratePseudoEthereumAddress(t *testing.T) {
	_, err := GeneratePseudoAddress([]byte("multiversXAddress"), core.MVXAddressIdentifier, core.ETHAddressIdentifier)
	assert.NoError(t, err)
}
