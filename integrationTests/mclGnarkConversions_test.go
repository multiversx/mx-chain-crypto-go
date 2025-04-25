package integrationTests

import (
	"testing"

	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381"
	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381/interop"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
	"github.com/stretchr/testify/require"
)

func TestFromMCL(t *testing.T) {
	mclSuite := mcl.NewSuiteBLS12()
	bls12381Suite := bls12381.NewSuiteBLS12()

	for i := 0; i < 500; i++ {
		_, pk := mclSuite.CreateKeyPair()

		pointBytes, _ := pk.MarshalBinary()
		convertedPoint, err := interop.PointBytesFromMcl(pointBytes)
		require.Nil(t, err)

		err = bls12381Suite.CheckPointValid(convertedPoint)

		require.Nil(t, err)
	}
}
