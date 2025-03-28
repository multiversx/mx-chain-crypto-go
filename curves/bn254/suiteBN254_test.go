package bn254

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSuiteBN254(t *testing.T) {
	suite := NewSuiteBN254()

	assert.NotNil(t, suite)
}

func TestSuiteBN254_RandomStream(t *testing.T) {
	suite := NewSuiteBN254()
	stream := suite.RandomStream()
	require.Nil(t, stream)
}
