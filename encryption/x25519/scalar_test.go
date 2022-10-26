package x25519_test

import (
	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/ElrondNetwork/elrond-go-crypto/encryption/x25519"
	"github.com/ElrondNetwork/elrond-go-crypto/mock"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestX25519ScalarEqual_NilParamShouldErr(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()

	_, err := scalar.Equal(nil)
	assert.Equal(t, crypto.ErrNilParam, err)
}

func TestX25519ScalarEqual_InvalidParamShouldErr(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()

	scalar2 := &mock.ScalarMock{}
	_, err := scalar.Equal(scalar2)
	assert.Equal(t, crypto.ErrInvalidPrivateKey, err)
}

func TestX25519ScalarEqual_ReturnsTrueForTheSameKey(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()

	eq, _ := scalar.Equal(scalar)
	assert.True(t, eq)
}

func TestX25519ScalarEqual_ReturnsFalseForDifferentKeys(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	scalar2 := suite.CreateScalar()

	eq, _ := scalar.Equal(scalar2)
	assert.False(t, eq)
}

func TestX25519ScalarSet_NilParamShouldErr(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()

	err := scalar.Set(nil)
	assert.Equal(t, crypto.ErrNilParam, err)
}

func TestX25519ScalarSet_SavesCorrectValue(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	scalar2 := suite.CreateScalar()

	_ = scalar.Set(scalar2)
	eq, _ := scalar.Equal(scalar2)
	assert.True(t, eq)
}

func TestX25519ScalarSet_CopiesValue(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	scalar2 := suite.CreateScalar()
	scalar3 := suite.CreateScalar()

	_ = scalar.Set(scalar2)
	_ = scalar2.Set(scalar3)
	eq, _ := scalar.Equal(scalar3)
	assert.False(t, eq)
}

func TestX25519ScalarClone_ReturnsSameScalarValue(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	scalar2 := scalar.Clone()

	eq, _ := scalar.Equal(scalar2)
	assert.True(t, eq)
}

func TestX25519ScalarClone_CopiesValue(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	scalar2 := scalar.Clone()
	scalar3 := suite.CreateScalar()
	_ = scalar.Set(scalar3)

	eq, _ := scalar2.Equal(scalar)
	assert.False(t, eq)
}

func TestX25519MarshalBinary_WrongKeyType(t *testing.T) {
	scalar := x25519.NewScalar([]byte("wrong key"))
	_, err := scalar.MarshalBinary()

	assert.Equal(t, crypto.ErrWrongPrivateKeySize, err)
}

func TestX25519ScalarMarshalUnmarshal(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()

	bytes, _ := scalar.MarshalBinary()
	scalar2 := suite.CreateScalar()
	_ = scalar2.UnmarshalBinary(bytes)

	eq, _ := scalar.Equal(scalar2)
	assert.True(t, eq)
}

func TestX25519ScalarUnmarshal_WorksWithSeed(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	scalar2 := suite.CreateScalar()

	bytes, _ := scalar.MarshalBinary()
	_ = scalar2.UnmarshalBinary(bytes[:32])

	eq, _ := scalar.Equal(scalar2)
	assert.True(t, eq)
}

func TestX25519ScalarUnmarshal_ErrorOnWrongSize(t *testing.T) {
	suite := x25519.NewX25519()
	scalar := suite.CreateScalar()
	err := scalar.UnmarshalBinary([]byte("wrong size"))

	assert.Equal(t, crypto.ErrWrongPrivateKeySize, err)
}

func TestX255192IsKeyValid_ErrOnWrongSize(t *testing.T) {
	privateKey := []byte("wrong size")
	err := x25519.IsKeyValid(privateKey)

	assert.Equal(t, crypto.ErrWrongPrivateKeySize, err)
}

func TestX255192IsKeyValid_CorrectKey(t *testing.T) {
	suite := x25519.NewX25519()
	privateKey, _ := suite.CreateKeyPair()
	privateKeyBytes, _ := (privateKey.GetUnderlyingObj()).(x25519.PrivateKey)

	err := x25519.IsKeyValid(privateKeyBytes)
	assert.Nil(t, err)
}

func TestX25519GetUnderlyingObj_InvalidKey(t *testing.T) {
	scalar := x25519.NewScalar([]byte("wrong size"))
	privateKey := scalar.GetUnderlyingObj()

	assert.Nil(t, privateKey)
}
