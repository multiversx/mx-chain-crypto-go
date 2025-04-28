package integrationTests

import (
	"testing"

	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381"
	blsInterop "github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381/interop"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
	mclInterop "github.com/multiversx/mx-chain-crypto-go/signing/mcl/interop"
	"github.com/stretchr/testify/require"
)

func TestFromMCLToGnark(t *testing.T) {
	mclSuite := mcl.NewSuiteBLS12()
	bls12381Suite := bls12381.NewSuiteBLS12()

	for i := 0; i < 500; i++ {
		_, pk := mclSuite.CreateKeyPair()

		pointBytes, _ := pk.MarshalBinary()
		convertedPoint, err := blsInterop.PointBytesFromMcl(pointBytes)
		require.Nil(t, err)

		err = bls12381Suite.CheckPointValid(convertedPoint)

		require.Nil(t, err)
	}
}

func TestFromGnarkToMCL(t *testing.T) {
	gnarkSuite := bls12381.NewSuiteBLS12()
	mclSuite := mcl.NewSuiteBLS12()

	for i := 0; i < 500; i++ {
		_, pk := gnarkSuite.CreateKeyPair()

		pointBytes, _ := pk.MarshalBinary()
		compressedPointBytes := pointBytes[:96]
		convertedPoint, err := mclInterop.PointBytesFromBls(compressedPointBytes)
		require.Nil(t, err)

		err = mclSuite.CheckPointValid(convertedPoint)

		require.Nil(t, err)
	}
}

func TestSameOperationsDifferentSuitesShouldBeEqual(t *testing.T) {
	t.Skip()

	gnarkSuite := bls12381.NewSuiteBLS12()
	_, pk1 := gnarkSuite.CreateKeyPair()
	_, pk2 := gnarkSuite.CreateKeyPair()

	gnarkScalar := bls12381.NewScalar()
	gnarkScalar.SetInt64(5)
	pk1, err := pk1.Mul(gnarkScalar)
	require.Nil(t, err)
	gnarkScalar.SetInt64(37)
	pk2, err = pk2.Mul(gnarkScalar)
	require.Nil(t, err)
	gnarkResult, err := pk1.Add(pk2)
	require.Nil(t, err)

	mclSuite := mcl.NewSuiteBLS12()
	_, pk3 := mclSuite.CreateKeyPair()
	_, pk4 := mclSuite.CreateKeyPair()

	mclScalar := mcl.NewScalar()
	mclScalar.SetInt64(5)
	pk3, err = pk3.Mul(mclScalar)
	require.Nil(t, err)
	mclScalar.SetInt64(37)
	pk4, err = pk4.Mul(mclScalar)
	require.Nil(t, err)
	mclResult, err := pk3.Add(pk4)
	require.Nil(t, err)

	pointBytes, _ := mclResult.MarshalBinary()
	convertedPointBytes, err := blsInterop.PointBytesFromMcl(pointBytes)
	convertedPoint := bls12381.NewPointG2()
	err = convertedPoint.UnmarshalBinary(convertedPointBytes)
	require.Nil(t, err)

	equal, err := gnarkResult.Equal(convertedPoint)
	require.Nil(t, err)
	require.True(t, equal)
}
