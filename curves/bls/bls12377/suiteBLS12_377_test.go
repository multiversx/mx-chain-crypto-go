package bls12377

import (
	"encoding/hex"
	"math/big"
	"testing"

	gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
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

func TestSuiteBLS12_CreatePoint(t *testing.T) {
	suite := NewSuiteBLS12()

	point1 := suite.CreatePoint()
	point2 := suite.CreatePoint()

	assert.NotNil(t, point1)
	assert.NotNil(t, point2)
	assert.False(t, point1 == point2)
}

func TestSuiteBLS12_String(t *testing.T) {
	suite := NewSuiteBLS12()

	str := suite.String()
	assert.Equal(t, "BLS12-377 suite", str)
}

func TestSuiteBLS12_ScalarLen(t *testing.T) {
	suite := NewSuiteBLS12()

	length := suite.ScalarLen()
	assert.Equal(t, 32, length)
}

func TestSuiteBLS12_CreateScalar(t *testing.T) {
	suite := NewSuiteBLS12()

	scalar := suite.CreateScalar()
	assert.NotNil(t, scalar)
}

func TestSuiteBLS12_CreatePointForScalar(t *testing.T) {
	suite := NewSuiteBLS12()
	scalar := NewScalar()

	point, err := suite.CreatePointForScalar(scalar)
	require.Nil(t, err)
	pG2, ok := point.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)
	require.NotNil(t, pG2)

	bG2 := NewPointG2().G2
	var scalarBigInt big.Int
	blsScalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	blsScalar.BigInt(&scalarBigInt)
	computedG2 := bG2.ScalarMultiplication(bG2, &scalarBigInt)

	require.True(t, pG2.Equal(computedG2))
}
func TestSuiteBLS12_PointLen(t *testing.T) {
	suite := NewSuiteBLS12()

	pointLength := suite.PointLen()

	// G2 point length is 128 bytes
	assert.Equal(t, 96, pointLength)
}

func TestSuiteBLS12_CreateKey(t *testing.T) {
	suite := NewSuiteBLS12()
	private, public := suite.CreateKeyPair()
	assert.NotNil(t, private)
	assert.NotNil(t, public)
}

func TestSuiteBLS12_GetUnderlyingSuite(t *testing.T) {
	suite := NewSuiteBLS12()

	obj := suite.GetUnderlyingSuite()

	assert.NotNil(t, obj)
}

func TestSuiteBLS12_CheckPointValidOK(t *testing.T) {
	t.Skip()
	// valid point: "a0ea6040e700403170dc5a51b1b140d5532777ee6651cecbe7223ece0799c9de5cf89984bff76fe6b26bfefa6ea16a" +
	//		"fe018480be71c785fec89630a2a3841d01c565f071203e50317ea501f557db6b9b71889f52bb53540274e3e48f7c005196"

	validPointHexStr := "33e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7" +
		"e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
	suite := NewSuiteBLS12()

	validPointBytes, err := hex.DecodeString(validPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(validPointBytes)
	require.Nil(t, err)
}

func TestSuiteBLS12_CheckPointValidShortHexStringShouldErr(t *testing.T) {
	shortPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74d"

	suite := NewSuiteBLS12()

	shortPointBytes, err := hex.DecodeString(shortPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(shortPointBytes)
	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestSuiteBLS12_CheckPointValidLongHexStrShouldErr(t *testing.T) {
	longPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74d" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74d"

	suite := NewSuiteBLS12()

	longPointBytes, err := hex.DecodeString(longPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(longPointBytes)
	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestSuiteBLS12_CheckPointValidInvalidPointHexStrShouldErr(t *testing.T) {
	invalidPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5caaaaaaaaaaa"
	oneHexCharCorruptedPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74dca0a"
	suite := NewSuiteBLS12()

	invalidPointBytes, err := hex.DecodeString(invalidPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(invalidPointBytes)
	require.NotNil(t, err)

	oneHexCharCorruptedPointBytes, err := hex.DecodeString(oneHexCharCorruptedPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(oneHexCharCorruptedPointBytes)
	require.NotNil(t, err)
}

func TestSuiteBLS12_CheckPointValidZeroHexStrShouldErr(t *testing.T) {
	t.Skip()

	zeroPointHexStr := "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	suite := NewSuiteBLS12()

	zeroPointBytes, err := hex.DecodeString(zeroPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(zeroPointBytes)
	require.Equal(t, crypto.ErrInvalidPoint, err)
}

func TestSuiteBLS12_IsInterfaceNil(t *testing.T) {
	t.Parallel()
	var suite *SuiteBLS12377

	require.True(t, check.IfNil(suite))
	suite = NewSuiteBLS12()
	require.False(t, check.IfNil(suite))
}
