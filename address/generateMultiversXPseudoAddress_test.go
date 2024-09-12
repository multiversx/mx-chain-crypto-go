package address

import (
	"github.com/multiversx/mx-chain-core-go/core"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGeneratePseudoMultiversXAddress(t *testing.T) {
	_, err := GeneratePseudoAddress([]byte("ethereumAddress"), core.ETHAddressIdentifier, core.MVXAddressIdentifier)
	assert.NoError(t, err)
}
