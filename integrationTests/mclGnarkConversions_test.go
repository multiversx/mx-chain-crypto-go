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
		convertedPoint, err := mclInterop.PointBytesFromBLS(compressedPointBytes)
		require.Nil(t, err)

		err = mclSuite.CheckPointValid(convertedPoint)

		require.Nil(t, err)
	}
}
