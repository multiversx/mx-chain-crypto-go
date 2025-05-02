package bn254

import (
	"encoding/hex"
	"math/big"
	"testing"

	gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/multiversx/mx-chain-core-go/core/check"
	crypto "github.com/multiversx/mx-chain-crypto-go"
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

func TestSuiteBN254_CreatePoint(t *testing.T) {
	suite := NewSuiteBN254()

	point1 := suite.CreatePoint()
	point2 := suite.CreatePoint()

	assert.NotNil(t, point1)
	assert.NotNil(t, point2)
	assert.False(t, point1 == point2)
}

func TestSuiteBN254_String(t *testing.T) {
	suite := NewSuiteBN254()

	str := suite.String()
	assert.Equal(t, "BN254 suite", str)
}

func TestSuiteBN254_ScalarLen(t *testing.T) {
	suite := NewSuiteBN254()

	length := suite.ScalarLen()
	assert.Equal(t, 32, length)
}

func TestSuiteBN254_CreateScalar(t *testing.T) {
	suite := NewSuiteBN254()

	scalar := suite.CreateScalar()
	assert.NotNil(t, scalar)
}

func TestSuiteBN254_CreatePointForScalar(t *testing.T) {
	suite := NewSuiteBN254()
	scalar := NewScalar()

	point, err := suite.CreatePointForScalar(scalar)
	require.Nil(t, err)
	pG2, ok := point.GetUnderlyingObj().(*gnark.G2Jac)
	require.True(t, ok)
	require.NotNil(t, pG2)

	bG2 := NewPointG2().G2
	var scalarBigInt big.Int
	bn254Scalar, ok := scalar.GetUnderlyingObj().(*fr.Element)
	bn254Scalar.BigInt(&scalarBigInt)
	computedG2 := bG2.ScalarMultiplication(bG2, &scalarBigInt)

	require.True(t, pG2.Equal(computedG2))
}

func TestSuiteBN254_PointLen(t *testing.T) {
	suite := NewSuiteBN254()

	pointLength := suite.PointLen()

	assert.Equal(t, 64, pointLength)
}

func TestSuiteBN254_CreateKey(t *testing.T) {
	suite := NewSuiteBN254()
	private, public := suite.CreateKeyPair()
	assert.NotNil(t, private)
	assert.NotNil(t, public)
}

func TestSuiteBN254_GetUnderlyingSuite(t *testing.T) {
	suite := NewSuiteBN254()

	obj := suite.GetUnderlyingSuite()

	assert.NotNil(t, obj)
}

func TestSuiteBN254_CheckPointValidOK(t *testing.T) {
	validPointHexStr := "998e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c44" +
		"79674322d4f75edadd46debd5cd992f6ed"

	suite := NewSuiteBN254()

	validPointBytes, err := hex.DecodeString(validPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(validPointBytes)
	require.Nil(t, err)
}

func TestSuiteBN254_CheckPointValidZeroHexStrShouldWork(t *testing.T) {
	zeroPointHexStr := "400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" +
		"00000000000000000000000000000000"

	suite := NewSuiteBN254()

	zeroPointBytes, err := hex.DecodeString(zeroPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(zeroPointBytes)
	require.Nil(t, err)
}

func TestSuiteBN254_CheckPointValidShortHexStringShouldErr(t *testing.T) {
	shortPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74d"

	suite := NewSuiteBN254()

	shortPointBytes, err := hex.DecodeString(shortPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(shortPointBytes)
	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestSuiteBN254_CheckPointValidLongHexStrShouldErr(t *testing.T) {
	longPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74d" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74d"

	suite := NewSuiteBN254()

	longPointBytes, err := hex.DecodeString(longPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(longPointBytes)
	require.Equal(t, crypto.ErrInvalidParam, err)
}

func TestSuiteBN254_CheckPointValidInvalidPointHexStrShouldErr(t *testing.T) {
	invalidPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5caaaaaaaaaaa"
	oneHexCharCorruptedPointHexStr := "368723d835fca6bc0c17a270e51b731f69f9fe482ed88e8c3d879f228291d48057aa12d0de8476b4a111e945399253" +
		"15d2d3fd1b85e29e465b8814b713cbf833115f4562e28dcf58e960751f0581578ca1819c8790aa5a5300c5c317b74dca0a"
	suite := NewSuiteBN254()

	invalidPointBytes, err := hex.DecodeString(invalidPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(invalidPointBytes)
	require.NotNil(t, err)

	oneHexCharCorruptedPointBytes, err := hex.DecodeString(oneHexCharCorruptedPointHexStr)
	require.Nil(t, err)
	err = suite.CheckPointValid(oneHexCharCorruptedPointBytes)
	require.NotNil(t, err)
}

func TestSuiteBN254_IsInterfaceNil(t *testing.T) {
	t.Parallel()
	var suite *SuiteBN254

	require.True(t, check.IfNil(suite))
	suite = NewSuiteBN254()
	require.False(t, check.IfNil(suite))
}
