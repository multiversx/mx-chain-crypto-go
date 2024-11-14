package bls12381

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewSuiteBLS12(t *testing.T) {
	suite := NewSuiteBLS12()

	assert.NotNil(t, suite)
}

func TestSuiteBLS12_RandomStream(t *testing.T) {
	suite := NewSuiteBLS12()
	stream := suite.RandomStream()
	require.Nil(t, stream)
}
