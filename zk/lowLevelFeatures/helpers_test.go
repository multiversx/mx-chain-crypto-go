package lowLevelFeatures

import (
	"testing"

	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func generateBLS12381Scalars(t *testing.T, n int) ([]bls12381_fr.Element, [][]byte) {
	t.Helper()
	scalars := make([]bls12381_fr.Element, n)
	scalarsBytes := make([][]byte, n)
	for i := 0; i < n; i++ {
		s, err := new(bls12381_fr.Element).SetRandom()
		require.NoError(t, err)
		scalars[i] = *s
		scalarsBytes[i] = s.Marshal()
	}
	return scalars, scalarsBytes
}

func generateBLS12377Scalars(t *testing.T, n int) ([]bls12377_fr.Element, [][]byte) {
	t.Helper()
	scalars := make([]bls12377_fr.Element, n)
	scalarsBytes := make([][]byte, n)
	for i := 0; i < n; i++ {
		s, err := new(bls12377_fr.Element).SetRandom()
		require.NoError(t, err)
		scalars[i] = *s
		scalarsBytes[i] = s.Marshal()
	}
	return scalars, scalarsBytes
}

func generateBN254Scalars(t *testing.T, n int) ([]bn254_fr.Element, [][]byte) {
	t.Helper()
	scalars := make([]bn254_fr.Element, n)
	scalarsBytes := make([][]byte, n)
	for i := 0; i < n; i++ {
		s, err := new(bn254_fr.Element).SetRandom()
		require.NoError(t, err)
		scalars[i] = *s
		scalarsBytes[i] = s.Marshal()
	}
	return scalars, scalarsBytes
}
