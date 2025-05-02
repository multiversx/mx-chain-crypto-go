package integrationTests

import (
	"fmt"
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
		convertedPoint, err := mclInterop.PointBytesFromGnark(pointBytes)
		require.Nil(t, err)

		err = mclSuite.CheckPointValid(convertedPoint)

		require.Nil(t, err)
	}
}

func printBytesAsBinary(data []byte) {
	for i, b := range data {
		// %08b formats b as binary, padded to 8 digits with leading zeros
		fmt.Printf("%08b", b)
		if i < len(data)-1 {
			fmt.Print(" ")
		}
	}
	fmt.Println()
}

func TestPointsBackAndForth(t *testing.T) {
	mclSuite := mcl.NewSuiteBLS12()
	_, pk1 := mclSuite.CreateKeyPair()
	pointBytes1, _ := pk1.MarshalBinary()

	convertedPointBytes1, _ := blsInterop.PointBytesFromMcl(pointBytes1)
	gnarkPoint1 := bls12381.NewPointG2()
	_ = gnarkPoint1.UnmarshalBinary(convertedPointBytes1)

	actualGnarkBytes, _ := gnarkPoint1.MarshalBinary()
	convertBackGnarkForMCL, _ := mclInterop.PointBytesFromGnark(actualGnarkBytes)

	lastPoint := mcl.NewPointG2()
	_ = lastPoint.UnmarshalBinary(convertBackGnarkForMCL)
	lastPointBytes, _ := lastPoint.MarshalBinary()

	require.Equal(t, pointBytes1, lastPointBytes)
}

func TestSameOperationsDifferentSuitesShouldBeEqual(t *testing.T) {
	t.Skip("TODO: Find the difference in curve operations")

	mclSuite := mcl.NewSuiteBLS12()
	_, pk1 := mclSuite.CreateKeyPair()
	_, pk2 := mclSuite.CreateKeyPair()
	mclResult, err := pk1.Add(pk2)

	fmt.Println("starting point")
	spb, _ := mclResult.MarshalBinary()
	printBytesAsBinary(spb)

	require.Nil(t, err)

	pointBytes1, _ := pk1.MarshalBinary()
	convertedPointBytes1, err := blsInterop.PointBytesFromMcl(pointBytes1)
	convertedPoint1 := bls12381.NewPointG2()
	err = convertedPoint1.UnmarshalBinary(convertedPointBytes1)
	require.Nil(t, err)

	pointBytes2, _ := pk2.MarshalBinary()
	convertedPointBytes2, err := blsInterop.PointBytesFromMcl(pointBytes2)
	convertedPoint2 := bls12381.NewPointG2()
	err = convertedPoint2.UnmarshalBinary(convertedPointBytes2)
	require.Nil(t, err)

	gnarkResult, err := convertedPoint1.Add(convertedPoint2)
	require.Nil(t, err)
	gnarkResult1, _ := gnarkResult.(*bls12381.PointG2)
	gnarkResult1.G2.ClearCofactor(gnarkResult1.G2)

	gnarkResultBytes, err := gnarkResult1.MarshalBinary()
	require.Nil(t, err)
	convertedPointBytes, err := mclInterop.PointBytesFromGnark(gnarkResultBytes)
	require.Nil(t, err)
	convertedPoint := mcl.NewPointG2()

	err = convertedPoint.UnmarshalBinary(convertedPointBytes)
	require.Nil(t, err)

	fmt.Println("resulting point")
	printBytesAsBinary(convertedPointBytes)
	equal, err := mclResult.Equal(convertedPoint)
	require.Nil(t, err)
	require.True(t, equal)
}
