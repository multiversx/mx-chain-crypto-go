package secp256k1_test

import (
	"testing"

	"github.com/ElrondNetwork/elrond-go-core/core/check"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/secp256k1"
	"github.com/btcsuite/btcd/btcec"
	"github.com/stretchr/testify/assert"
)

func TestNewSecp256k1Suite(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.False(t, check.IfNil(suite))
}

func TestCreateKeys(t *testing.T) {
	t.Parallel()

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()

		privateKey, publicKey := suite.CreateKeyPair()
		assert.NotNil(t, privateKey)
		assert.NotNil(t, publicKey)
	})

	t.Run("generates different key pairs", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		privateKey, publicKey := suite.CreateKeyPair()
		privateKey2, publicKey2 := suite.CreateKeyPair()

		assert.NotEqual(t, privateKey, privateKey2)
		assert.NotEqual(t, publicKey, publicKey2)
	})

	t.Run("create scalar", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		privateKey := suite.CreateScalar()
		assert.NotNil(t, privateKey)
	})

	t.Run("create point", func(t *testing.T) {
		t.Parallel()

		suite := secp256k1.NewSecp256k1()
		publicKey := suite.CreatePoint()
		assert.NotNil(t, publicKey)
	})
}

func TestString(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.Equal(t, secp256k1.Secp256k1Str, suite.String())
}

func TestScalarLen(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.Equal(t, btcec.PrivKeyBytesLen, suite.ScalarLen())
}

func TestPointLen(t *testing.T) {
	t.Parallel()

	suite := secp256k1.NewSecp256k1()
	assert.Equal(t, btcec.PubKeyBytesLenCompressed, suite.PointLen())
}
