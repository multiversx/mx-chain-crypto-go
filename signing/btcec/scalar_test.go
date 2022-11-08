package btcec_test

import (
	"testing"

	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/btcec"
	"github.com/stretchr/testify/assert"
)

func TestScalar_Equal(t *testing.T) {
	t.Parallel()

	t.Run("nil param should error", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		scalar := suite.CreateScalar()

		_, err := scalar.Equal(nil)
		assert.Equal(t, crypto.ErrNilParam, err)
	})

	t.Run("returns false for different keys", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		scalar := suite.CreateScalar()
		scalar2 := suite.CreateScalar()

		ok, err := scalar.Equal(scalar2)
		assert.Nil(t, err)
		assert.False(t, ok)
	})

	t.Run("returns true for same keys", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		scalar := suite.CreateScalar()

		ok, err := scalar.Equal(scalar)
		assert.Nil(t, err)
		assert.True(t, ok)
	})
}

func TestScalar_Set(t *testing.T) {
	t.Parallel()

	t.Run("nil param should error", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		scalar := suite.CreateScalar()

		err := scalar.Set(nil)
		assert.Equal(t, crypto.ErrNilParam, err)
	})

	t.Run("should work", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		scalar := suite.CreateScalar()
		scalar2 := suite.CreateScalar()

		_ = scalar.Set(scalar2)
		eq, _ := scalar.Equal(scalar2)
		assert.True(t, eq)
	})

	t.Run("it should set by value", func(t *testing.T) {
		t.Parallel()

		suite := btcec.NewBtcecSuite()
		scalar := suite.CreateScalar()
		scalar2 := suite.CreateScalar()
		scalar3 := suite.CreateScalar()

		_ = scalar.Set(scalar2)
		_ = scalar2.Set(scalar3)
		eq, _ := scalar.Equal(scalar3)
		assert.False(t, eq)
	})
}

func TestScalar_Clone(t *testing.T) {
	t.Parallel()

	suite := btcec.NewBtcecSuite()
	scalar := suite.CreateScalar()
	scalar2 := scalar.Clone()

	eq, _ := scalar.Equal(scalar2)
	assert.True(t, eq)
}

func TestScalar_MarshallUnmarshall(t *testing.T) {
	t.Parallel()

	suite := btcec.NewBtcecSuite()
	scalar := suite.CreateScalar()

	bytes, _ := scalar.MarshalBinary()
	scalar2 := suite.CreateScalar()
	_ = scalar2.UnmarshalBinary(bytes)

	eq, _ := scalar.Equal(scalar2)
	assert.True(t, eq)
}
