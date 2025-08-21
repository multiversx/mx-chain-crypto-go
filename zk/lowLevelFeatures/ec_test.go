package lowLevelFeatures

import (
	"github.com/consensys/gnark-crypto/ecc"
	bls12377_gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381_gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254_gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
	"math/big"
	"testing"
)

func TestPointAdd(t *testing.T) {
	_, _, p1, _ := bls12381_gnark.Generators()
	p1Bytes := p1.Marshal()
	p2 := p1
	p2Bytes := p2.Marshal()

	var expected bls12381_gnark.G1Affine
	expected.Add(&p1, &p2)

	res, err := PointAdd(BLS12_381, G1, p1Bytes, p2Bytes)
	require.NoError(t, err)
	require.Equal(t, expected.Marshal(), res)

	// Test invalid curve
	_, err = PointAdd(Unknown, G1, p1Bytes, p2Bytes)
	require.ErrorIs(t, err, ErrInvalidCurve)
}

func TestScalarMul(t *testing.T) {
	_, _, p1, _ := bls12381_gnark.Generators()
	p1Bytes := p1.Marshal()
	scalar, err := new(bls12381_fr.Element).SetRandom()
	require.NoError(t, err)
	scalarBytes := scalar.Marshal()
	var expected bls12381_gnark.G1Affine
	expected.ScalarMultiplication(&p1, new(big.Int).SetBytes(scalar.Marshal()))

	res, err := ScalarMul(BLS12_381, G1, p1Bytes, scalarBytes)
	require.NoError(t, err)
	require.Equal(t, expected.Marshal(), res)

	// Test invalid curve
	_, err = ScalarMul(Unknown, G1, p1Bytes, scalarBytes)
	require.ErrorIs(t, err, ErrInvalidCurve)
}

func TestMultiExp(t *testing.T) {
	_, _, p1, _ := bls12381_gnark.Generators()
	points := []bls12381_gnark.G1Affine{p1, p1, p1}
	pointsBytes := [][]byte{p1.Marshal(), p1.Marshal(), p1.Marshal()}
	scalars, scalarsBytes := generateBLS12381Scalars(t, 3)

	var expected bls12381_gnark.G1Affine
	_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
	require.NoError(t, err)

	res, err := MultiExp(BLS12_381, G1, pointsBytes, scalarsBytes)
	require.NoError(t, err)
	require.Equal(t, expected.Marshal(), res)

	// Test invalid curve
	_, err = MultiExp(Unknown, G1, pointsBytes, scalarsBytes)
	require.ErrorIs(t, err, ErrInvalidCurve)
}

func TestMapToCurve(t *testing.T) {
	var fp bls12381_fp.Element
	_, err := fp.SetRandom()
	require.NoError(t, err)
	element := fp.Marshal()

	_, err = MapToCurve(BLS12_381, G1, element)
	require.NoError(t, err)

	// Test invalid curve
	_, err = MapToCurve(Unknown, G1, element)
	require.ErrorIs(t, err, ErrInvalidCurve)
}

func TestPairingCheck(t *testing.T) {
	t.Run("BLS12_381", func(t *testing.T) {
		_, _, p1, p2 := bls12381_gnark.Generators()
		a, err := new(bls12381_fr.Element).SetRandom()
		require.NoError(t, err)

		var aG1, negAG1 bls12381_gnark.G1Affine
		var aG2 bls12381_gnark.G2Affine
		aG1.ScalarMultiplication(&p1, new(big.Int).SetBytes(a.Marshal()))
		aG2.ScalarMultiplication(&p2, new(big.Int).SetBytes(a.Marshal()))
		negAG1.Neg(&aG1)

		pointsG1 := [][]byte{negAG1.Marshal(), p1.Marshal()}
		pointsG2 := [][]byte{p2.Marshal(), aG2.Marshal()}

		ok, err := PairingCheck(BLS12_381, pointsG1, pointsG2)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("BLS12_377", func(t *testing.T) {
		_, _, p1, p2 := bls12377_gnark.Generators()
		a, err := new(bls12377_fr.Element).SetRandom()
		require.NoError(t, err)

		var aG1, negAG1 bls12377_gnark.G1Affine
		var aG2 bls12377_gnark.G2Affine
		aG1.ScalarMultiplication(&p1, new(big.Int).SetBytes(a.Marshal()))
		aG2.ScalarMultiplication(&p2, new(big.Int).SetBytes(a.Marshal()))
		negAG1.Neg(&aG1)

		pointsG1 := [][]byte{negAG1.Marshal(), p1.Marshal()}
		pointsG2 := [][]byte{p2.Marshal(), aG2.Marshal()}

		ok, err := PairingCheck(BLS12_377, pointsG1, pointsG2)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("BN254", func(t *testing.T) {
		_, _, p1, p2 := bn254_gnark.Generators()
		a, err := new(bn254_fr.Element).SetRandom()
		require.NoError(t, err)

		var aG1, negAG1 bn254_gnark.G1Affine
		var aG2 bn254_gnark.G2Affine
		aG1.ScalarMultiplication(&p1, new(big.Int).SetBytes(a.Marshal()))
		aG2.ScalarMultiplication(&p2, new(big.Int).SetBytes(a.Marshal()))
		negAG1.Neg(&aG1)

		pointsG1 := [][]byte{negAG1.Marshal(), p1.Marshal()}
		pointsG2 := [][]byte{p2.Marshal(), aG2.Marshal()}

		ok, err := PairingCheck(BN254, pointsG1, pointsG2)
		require.NoError(t, err)
		require.True(t, ok)
	})

	t.Run("InvalidCurve", func(t *testing.T) {
		_, err := PairingCheck(Unknown, nil, nil)
		require.ErrorIs(t, err, ErrInvalidCurve)
	})
}
