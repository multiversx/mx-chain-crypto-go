package x25519_test

import (
	"github.com/ElrondNetwork/elrond-go-core/core/check"
	"github.com/ElrondNetwork/elrond-go-crypto/encryption/x25519"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/curve25519"
	"testing"
)

func TestNewX25519(t *testing.T) {
	suite := x25519.NewX25519()
	assert.False(t, check.IfNil(suite))
}

func TestNewX25519CreateKeyPair(t *testing.T) {
	suite := x25519.NewX25519()
	privateKey, publicKey := suite.CreateKeyPair()
	assert.NotNil(t, privateKey)
	assert.NotNil(t, publicKey)
}

func TestNewX25519CreateKeyPair_GeneratesDifferentKeys(t *testing.T) {
	suite := x25519.NewX25519()
	privateKey, publicKey := suite.CreateKeyPair()
	privateKey2, publicKey2 := suite.CreateKeyPair()

	assert.NotEqual(t, privateKey, privateKey2)
	assert.NotEqual(t, publicKey, publicKey2)
}

func TestNewX25519CreatePoint(t *testing.T) {
	suite := x25519.NewX25519()
	publicKey := suite.CreatePoint()
	assert.NotNil(t, publicKey)
}

func TestNewX25519CreateScalar(t *testing.T) {
	suite := x25519.NewX25519()
	privateKey := suite.CreateScalar()
	assert.NotNil(t, privateKey)
}

func TestNewX25519String(t *testing.T) {
	suite := x25519.NewX25519()
	assert.Equal(t, x25519.X25519, suite.String())
}

func TestNewX25519ScalarLen(t *testing.T) {
	suite := x25519.NewX25519()
	assert.Equal(t, curve25519.ScalarSize, suite.ScalarLen())
}

func TestNewX25519PointLen(t *testing.T) {
	suite := x25519.NewX25519()
	assert.Equal(t, curve25519.PointSize, suite.PointLen())
}
