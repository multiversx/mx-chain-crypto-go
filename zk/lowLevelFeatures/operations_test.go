package lowLevelFeatures

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377_gnark "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377_fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	bls12377_fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls12381_gnark "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381_fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381_fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn254_gnark "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254_fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254_fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/require"
)

func TestBLS12_381(t *testing.T) {
	t.Run("G1", func(t *testing.T) {
		g1 := &bls12381G1{}
		_, _, p1, _ := bls12381_gnark.Generators()
		p1Bytes := p1.Marshal()

		t.Run("Add", func(t *testing.T) {
			p2 := p1
			p2Bytes := p2.Marshal()
			var expected bls12381_gnark.G1Affine
			expected.Add(&p1, &p2)

			res, err := g1.Add(p1Bytes, p2Bytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.Add([]byte("invalid"), p2Bytes)
			require.Error(t, err)
			_, err = g1.Add(p1Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12381_gnark.G1Affine
			p.X.SetOne()
			p.Y.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g1.Add(invalidPointBytes, p2Bytes)
			require.Error(t, err)
		})

		t.Run("Mul", func(t *testing.T) {
			scalar, err := new(bls12381_fr.Element).SetRandom()
			require.NoError(t, err)
			scalarBytes := scalar.Marshal()
			var expected bls12381_gnark.G1Affine
			expected.ScalarMultiplication(&p1, new(big.Int).SetBytes(scalar.Marshal()))

			res, err := g1.Mul(p1Bytes, scalarBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.Mul([]byte("invalid"), scalarBytes)
			require.Error(t, err)
			_, err = g1.Mul(p1Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12381_gnark.G1Affine
			p.X.SetOne()
			p.Y.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g1.Mul(invalidPointBytes, scalarBytes)
			require.Error(t, err)
		})

		t.Run("MultiExp", func(t *testing.T) {
			points := []bls12381_gnark.G1Affine{p1, p1, p1}
			pointsBytes := [][]byte{p1.Marshal(), p1.Marshal(), p1.Marshal()}
			scalars, scalarsBytes := generateBLS12381Scalars(t, 3)

			var expected bls12381_gnark.G1Affine
			_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
			require.NoError(t, err)

			res, err := g1.MultiExp(pointsBytes, scalarsBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.MultiExp(pointsBytes, scalarsBytes[:2])
			require.ErrorIs(t, err, ErrPointsAndScalarsShouldMatch)

			invalidPointsBytes := append([][]byte(nil), pointsBytes...)
			invalidPointsBytes[0] = []byte("invalid")
			_, err = g1.MultiExp(invalidPointsBytes, scalarsBytes)
			require.Error(t, err)
		})

		t.Run("MapToCurve", func(t *testing.T) {
			var fp bls12381_fp.Element
			_, err := fp.SetRandom()
			require.NoError(t, err)
			element := fp.Marshal()

			expected := bls12381_gnark.MapToG1(fp)

			res, err := g1.MapToCurve(element)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.MapToCurve(element[:47])
			require.ErrorIs(t, err, ErrInvalidFpElement)

			invalidElement := make([]byte, 48)
			for i := range invalidElement {
				invalidElement[i] = 0xff
			}
			_, err = g1.MapToCurve(invalidElement)
			require.Error(t, err)
		})
	})

	t.Run("G2", func(t *testing.T) {
		g2 := &bls12381G2{}
		_, _, _, p2 := bls12381_gnark.Generators()
		p2Bytes := p2.Marshal()

		t.Run("Add", func(t *testing.T) {
			p1 := p2
			p1Bytes := p1.Marshal()
			var expected bls12381_gnark.G2Affine
			expected.Add(&p2, &p1)

			res, err := g2.Add(p2Bytes, p1Bytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.Add([]byte("invalid"), p1Bytes)
			require.Error(t, err)
			_, err = g2.Add(p2Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12381_gnark.G2Affine
			p.X.A0.SetOne()
			p.Y.A0.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g2.Add(invalidPointBytes, p1Bytes)
			require.Error(t, err)
		})

		t.Run("Mul", func(t *testing.T) {
			scalar, err := new(bls12381_fr.Element).SetRandom()
			require.NoError(t, err)
			scalarBytes := scalar.Marshal()
			var expected bls12381_gnark.G2Affine
			expected.ScalarMultiplication(&p2, new(big.Int).SetBytes(scalar.Marshal()))

			res, err := g2.Mul(p2Bytes, scalarBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.Mul([]byte("invalid"), scalarBytes)
			require.Error(t, err)
			_, err = g2.Mul(p2Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12381_gnark.G2Affine
			p.X.A0.SetOne()
			p.Y.A0.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g2.Mul(invalidPointBytes, scalarBytes)
			require.Error(t, err)
		})

		t.Run("MultiExp", func(t *testing.T) {
			points := []bls12381_gnark.G2Affine{p2, p2, p2}
			pointsBytes := [][]byte{p2.Marshal(), p2.Marshal(), p2.Marshal()}
			scalars, scalarsBytes := generateBLS12381Scalars(t, 3)

			var expected bls12381_gnark.G2Affine
			_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
			require.NoError(t, err)

			res, err := g2.MultiExp(pointsBytes, scalarsBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.MultiExp(pointsBytes, scalarsBytes[:2])
			require.ErrorIs(t, err, ErrPointsAndScalarsShouldMatch)

			invalidPointsBytes := append([][]byte(nil), pointsBytes...)
			invalidPointsBytes[0] = []byte("invalid")
			_, err = g2.MultiExp(invalidPointsBytes, scalarsBytes)
			require.Error(t, err)
		})

		t.Run("MapToCurve", func(t *testing.T) {
			var fpE2 bls12381_gnark.E2
			_, err := fpE2.SetRandom()
			require.NoError(t, err)
			element := append(fpE2.A0.Marshal(), fpE2.A1.Marshal()...)

			expected := bls12381_gnark.MapToG2(fpE2)

			res, err := g2.MapToCurve(element)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.MapToCurve(element[:95])
			require.ErrorIs(t, err, ErrInvalidFpElement)

			invalidElement := make([]byte, 96)
			for i := range invalidElement {
				invalidElement[i] = 0xff
			}
			_, err = g2.MapToCurve(invalidElement)
			require.Error(t, err)

			invalidElement2 := make([]byte, 96)
			var fp bls12381_fp.Element
			_, err = fp.SetRandom()
			require.NoError(t, err)
			copy(invalidElement2, fp.Marshal())
			for i := 48; i < 96; i++ {
				invalidElement2[i] = 0xff
			}
			_, err = g2.MapToCurve(invalidElement2)
			require.Error(t, err)
		})
	})

	t.Run("Pairing", func(t *testing.T) {
		pairing := &bls12381Pairing{}
		_, _, p1, p2 := bls12381_gnark.Generators()

		t.Run("PairingCheck", func(t *testing.T) {
			a, err := new(bls12381_fr.Element).SetRandom()
			require.NoError(t, err)

			var aG1, negAG1 bls12381_gnark.G1Affine
			var aG2 bls12381_gnark.G2Affine
			aG1.ScalarMultiplication(&p1, new(big.Int).SetBytes(a.Marshal()))
			aG2.ScalarMultiplication(&p2, new(big.Int).SetBytes(a.Marshal()))
			negAG1.Neg(&aG1)

			pointsG1 := [][]byte{negAG1.Marshal(), p1.Marshal()}
			pointsG2 := [][]byte{p2.Marshal(), aG2.Marshal()}

			res, err := pairing.PairingCheck(pointsG1, pointsG2)
			require.NoError(t, err)
			require.True(t, res)

			_, err = pairing.PairingCheck(pointsG1, pointsG2[:1])
			require.ErrorIs(t, err, ErrPairingPointsLenShouldMatch)

			invalidPointsG1 := append([][]byte(nil), pointsG1...)
			invalidPointsG1[0] = []byte("invalid")
			_, err = pairing.PairingCheck(invalidPointsG1, pointsG2)
			require.Error(t, err)

			invalidPointsG2 := append([][]byte(nil), pointsG2...)
			invalidPointsG2[0] = []byte("invalid")
			_, err = pairing.PairingCheck(pointsG1, invalidPointsG2)
			require.Error(t, err)
		})
	})
}

func TestBLS12_377(t *testing.T) {
	t.Run("G1", func(t *testing.T) {
		g1 := &bls12377G1{}
		_, _, p1, _ := bls12377_gnark.Generators()
		p1Bytes := p1.Marshal()

		t.Run("Add", func(t *testing.T) {
			p2 := p1
			p2Bytes := p2.Marshal()
			var expected bls12377_gnark.G1Affine
			expected.Add(&p1, &p2)

			res, err := g1.Add(p1Bytes, p2Bytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.Add([]byte("invalid"), p2Bytes)
			require.Error(t, err)
			_, err = g1.Add(p1Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12377_gnark.G1Affine
			p.X.SetOne()
			p.Y.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g1.Add(invalidPointBytes, p2Bytes)
			require.Error(t, err)
		})

		t.Run("Mul", func(t *testing.T) {
			scalar, err := new(bls12377_fr.Element).SetRandom()
			require.NoError(t, err)
			scalarBytes := scalar.Marshal()
			var expected bls12377_gnark.G1Affine
			expected.ScalarMultiplication(&p1, new(big.Int).SetBytes(scalar.Marshal()))

			res, err := g1.Mul(p1Bytes, scalarBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.Mul([]byte("invalid"), scalarBytes)
			require.Error(t, err)
			_, err = g1.Mul(p1Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12377_gnark.G1Affine
			p.X.SetOne()
			p.Y.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g1.Mul(invalidPointBytes, scalarBytes)
			require.Error(t, err)
		})

		t.Run("MultiExp", func(t *testing.T) {
			points := []bls12377_gnark.G1Affine{p1, p1, p1}
			pointsBytes := [][]byte{p1.Marshal(), p1.Marshal(), p1.Marshal()}
			scalars, scalarsBytes := generateBLS12377Scalars(t, 3)

			var expected bls12377_gnark.G1Affine
			_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
			require.NoError(t, err)

			res, err := g1.MultiExp(pointsBytes, scalarsBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.MultiExp(pointsBytes, scalarsBytes[:2])
			require.ErrorIs(t, err, ErrPointsAndScalarsShouldMatch)

			invalidPointsBytes := append([][]byte(nil), pointsBytes...)
			invalidPointsBytes[0] = []byte("invalid")
			_, err = g1.MultiExp(invalidPointsBytes, scalarsBytes)
			require.Error(t, err)
		})

		t.Run("MapToCurve", func(t *testing.T) {
			var fp bls12377_fp.Element
			_, err := fp.SetRandom()
			require.NoError(t, err)
			element := fp.Marshal()

			expected := bls12377_gnark.MapToG1(fp)

			res, err := g1.MapToCurve(element)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.MapToCurve(element[:47])
			require.ErrorIs(t, err, ErrInvalidFpElement)

			invalidElement := make([]byte, 48)
			for i := range invalidElement {
				invalidElement[i] = 0xff
			}
			_, err = g1.MapToCurve(invalidElement)
			require.Error(t, err)
		})
	})

	t.Run("G2", func(t *testing.T) {
		g2 := &bls12377G2{}
		_, _, _, p2 := bls12377_gnark.Generators()
		p2Bytes := p2.Marshal()

		t.Run("Add", func(t *testing.T) {
			p1 := p2
			p1Bytes := p1.Marshal()
			var expected bls12377_gnark.G2Affine
			expected.Add(&p2, &p1)

			res, err := g2.Add(p2Bytes, p1Bytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.Add([]byte("invalid"), p1Bytes)
			require.Error(t, err)
			_, err = g2.Add(p2Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12377_gnark.G2Affine
			p.X.A0.SetOne()
			p.Y.A0.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g2.Add(invalidPointBytes, p1Bytes)
			require.Error(t, err)
		})

		t.Run("Mul", func(t *testing.T) {
			scalar, err := new(bls12377_fr.Element).SetRandom()
			require.NoError(t, err)
			scalarBytes := scalar.Marshal()
			var expected bls12377_gnark.G2Affine
			expected.ScalarMultiplication(&p2, new(big.Int).SetBytes(scalar.Marshal()))

			res, err := g2.Mul(p2Bytes, scalarBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.Mul([]byte("invalid"), scalarBytes)
			require.Error(t, err)
			_, err = g2.Mul(p2Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bls12377_gnark.G2Affine
			p.X.A0.SetOne()
			p.Y.A0.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g2.Mul(invalidPointBytes, scalarBytes)
			require.Error(t, err)
		})

		t.Run("MultiExp", func(t *testing.T) {
			points := []bls12377_gnark.G2Affine{p2, p2, p2}
			pointsBytes := [][]byte{p2.Marshal(), p2.Marshal(), p2.Marshal()}
			scalars, scalarsBytes := generateBLS12377Scalars(t, 3)

			var expected bls12377_gnark.G2Affine
			_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
			require.NoError(t, err)

			res, err := g2.MultiExp(pointsBytes, scalarsBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.MultiExp(pointsBytes, scalarsBytes[:2])
			require.ErrorIs(t, err, ErrPointsAndScalarsShouldMatch)

			invalidPointsBytes := append([][]byte(nil), pointsBytes...)
			invalidPointsBytes[0] = []byte("invalid")
			_, err = g2.MultiExp(invalidPointsBytes, scalarsBytes)
			require.Error(t, err)
		})

		t.Run("MapToCurve", func(t *testing.T) {
			var fpE2 bls12377_gnark.E2
			_, err := fpE2.SetRandom()
			require.NoError(t, err)
			element := append(fpE2.A0.Marshal(), fpE2.A1.Marshal()...)

			expected := bls12377_gnark.MapToG2(fpE2)

			res, err := g2.MapToCurve(element)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.MapToCurve(element[:95])
			require.ErrorIs(t, err, ErrInvalidFpElement)

			invalidElement := make([]byte, 96)
			for i := range invalidElement {
				invalidElement[i] = 0xff
			}
			_, err = g2.MapToCurve(invalidElement)
			require.Error(t, err)

			invalidElement2 := make([]byte, 96)
			var fp bls12377_fp.Element
			_, err = fp.SetRandom()
			require.NoError(t, err)
			copy(invalidElement2, fp.Marshal())
			for i := 48; i < 96; i++ {
				invalidElement2[i] = 0xff
			}
			_, err = g2.MapToCurve(invalidElement2)
			require.Error(t, err)
		})
	})

	t.Run("Pairing", func(t *testing.T) {
		pairing := &bls12377Pairing{}
		_, _, p1, p2 := bls12377_gnark.Generators()

		t.Run("PairingCheck", func(t *testing.T) {
			a, err := new(bls12377_fr.Element).SetRandom()
			require.NoError(t, err)

			var aG1, negAG1 bls12377_gnark.G1Affine
			var aG2 bls12377_gnark.G2Affine
			aG1.ScalarMultiplication(&p1, new(big.Int).SetBytes(a.Marshal()))
			aG2.ScalarMultiplication(&p2, new(big.Int).SetBytes(a.Marshal()))
			negAG1.Neg(&aG1)

			pointsG1 := [][]byte{negAG1.Marshal(), p1.Marshal()}
			pointsG2 := [][]byte{p2.Marshal(), aG2.Marshal()}

			res, err := pairing.PairingCheck(pointsG1, pointsG2)
			require.NoError(t, err)
			require.True(t, res)

			_, err = pairing.PairingCheck(pointsG1, pointsG2[:1])
			require.ErrorIs(t, err, ErrPairingPointsLenShouldMatch)

			invalidPointsG1 := append([][]byte(nil), pointsG1...)
			invalidPointsG1[0] = []byte("invalid")
			_, err = pairing.PairingCheck(invalidPointsG1, pointsG2)
			require.Error(t, err)

			invalidPointsG2 := append([][]byte(nil), pointsG2...)
			invalidPointsG2[0] = []byte("invalid")
			_, err = pairing.PairingCheck(pointsG1, invalidPointsG2)
			require.Error(t, err)
		})
	})
}

func TestBN254(t *testing.T) {
	t.Run("G1", func(t *testing.T) {
		g1 := &bn254G1{}
		_, _, p1, _ := bn254_gnark.Generators()
		p1Bytes := p1.Marshal()

		t.Run("Add", func(t *testing.T) {
			p2 := p1
			p2Bytes := p2.Marshal()
			var expected bn254_gnark.G1Affine
			expected.Add(&p1, &p2)

			res, err := g1.Add(p1Bytes, p2Bytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.Add([]byte("invalid"), p2Bytes)
			require.Error(t, err)
			_, err = g1.Add(p1Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bn254_gnark.G1Affine
			p.X.SetOne()
			p.Y.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g1.Add(invalidPointBytes, p2Bytes)
			require.Error(t, err)
		})

		t.Run("Mul", func(t *testing.T) {
			scalar, err := new(bn254_fr.Element).SetRandom()
			require.NoError(t, err)
			scalarBytes := scalar.Marshal()
			var expected bn254_gnark.G1Affine
			expected.ScalarMultiplication(&p1, new(big.Int).SetBytes(scalar.Marshal()))

			res, err := g1.Mul(p1Bytes, scalarBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.Mul([]byte("invalid"), scalarBytes)
			require.Error(t, err)
			_, err = g1.Mul(p1Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bn254_gnark.G1Affine
			p.X.SetOne()
			p.Y.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g1.Mul(invalidPointBytes, scalarBytes)
			require.Error(t, err)
		})

		t.Run("MultiExp", func(t *testing.T) {
			points := []bn254_gnark.G1Affine{p1, p1, p1}
			pointsBytes := [][]byte{p1.Marshal(), p1.Marshal(), p1.Marshal()}
			scalars, scalarsBytes := generateBN254Scalars(t, 3)

			var expected bn254_gnark.G1Affine
			_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
			require.NoError(t, err)

			res, err := g1.MultiExp(pointsBytes, scalarsBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.MultiExp(pointsBytes, scalarsBytes[:2])
			require.ErrorIs(t, err, ErrPointsAndScalarsShouldMatch)

			invalidPointsBytes := append([][]byte(nil), pointsBytes...)
			invalidPointsBytes[0] = []byte("invalid")
			_, err = g1.MultiExp(invalidPointsBytes, scalarsBytes)
			require.Error(t, err)
		})

		t.Run("MapToCurve", func(t *testing.T) {
			var fp bn254_fp.Element
			_, err := fp.SetRandom()
			require.NoError(t, err)
			element := fp.Marshal()

			expected := bn254_gnark.MapToG1(fp)

			res, err := g1.MapToCurve(element)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g1.MapToCurve(element[:31])
			require.ErrorIs(t, err, ErrInvalidFpElement)

			invalidElement := make([]byte, 32)
			for i := range invalidElement {
				invalidElement[i] = 0xff
			}
			_, err = g1.MapToCurve(invalidElement)
			require.Error(t, err)
		})
	})

	t.Run("G2", func(t *testing.T) {
		g2 := &bn254G2{}
		_, _, _, p2 := bn254_gnark.Generators()
		p2Bytes := p2.Marshal()

		t.Run("Add", func(t *testing.T) {
			p1 := p2
			p1Bytes := p1.Marshal()
			var expected bn254_gnark.G2Affine
			expected.Add(&p2, &p1)

			res, err := g2.Add(p2Bytes, p1Bytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.Add([]byte("invalid"), p1Bytes)
			require.Error(t, err)
			_, err = g2.Add(p2Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bn254_gnark.G2Affine
			p.X.A0.SetOne()
			p.Y.A0.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g2.Add(invalidPointBytes, p1Bytes)
			require.Error(t, err)
		})

		t.Run("Mul", func(t *testing.T) {
			scalar, err := new(bn254_fr.Element).SetRandom()
			require.NoError(t, err)
			scalarBytes := scalar.Marshal()
			var expected bn254_gnark.G2Affine
			expected.ScalarMultiplication(&p2, new(big.Int).SetBytes(scalar.Marshal()))

			res, err := g2.Mul(p2Bytes, scalarBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.Mul([]byte("invalid"), scalarBytes)
			require.Error(t, err)
			_, err = g2.Mul(p2Bytes, []byte("invalid"))
			require.Error(t, err)

			var p bn254_gnark.G2Affine
			p.X.A0.SetOne()
			p.Y.A0.SetOne()
			invalidPointBytes := p.Marshal()
			_, err = g2.Mul(invalidPointBytes, scalarBytes)
			require.Error(t, err)
		})

		t.Run("MultiExp", func(t *testing.T) {
			points := []bn254_gnark.G2Affine{p2, p2, p2}
			pointsBytes := [][]byte{p2.Marshal(), p2.Marshal(), p2.Marshal()}
			scalars, scalarsBytes := generateBN254Scalars(t, 3)

			var expected bn254_gnark.G2Affine
			_, err := expected.MultiExp(points, scalars, ecc.MultiExpConfig{})
			require.NoError(t, err)

			res, err := g2.MultiExp(pointsBytes, scalarsBytes)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.MultiExp(pointsBytes, scalarsBytes[:2])
			require.ErrorIs(t, err, ErrPointsAndScalarsShouldMatch)

			invalidPointsBytes := append([][]byte(nil), pointsBytes...)
			invalidPointsBytes[0] = []byte("invalid")
			_, err = g2.MultiExp(invalidPointsBytes, scalarsBytes)
			require.Error(t, err)
		})

		t.Run("MapToCurve", func(t *testing.T) {
			var fpE2 bn254_gnark.E2
			_, err := fpE2.SetRandom()
			require.NoError(t, err)
			element := append(fpE2.A0.Marshal(), fpE2.A1.Marshal()...)

			expected := bn254_gnark.MapToG2(fpE2)

			res, err := g2.MapToCurve(element)
			require.NoError(t, err)
			require.Equal(t, expected.Marshal(), res)

			_, err = g2.MapToCurve(element[:63])
			require.ErrorIs(t, err, ErrInvalidFpElement)

			invalidElement := make([]byte, 64)
			for i := range invalidElement {
				invalidElement[i] = 0xff
			}
			_, err = g2.MapToCurve(invalidElement)
			require.Error(t, err)

			invalidElement2 := make([]byte, 64)
			var fp bn254_fp.Element
			_, err = fp.SetRandom()
			require.NoError(t, err)
			copy(invalidElement2, fp.Marshal())
			for i := 32; i < 64; i++ {
				invalidElement2[i] = 0xff
			}
			_, err = g2.MapToCurve(invalidElement2)
			require.Error(t, err)
		})
	})

	t.Run("Pairing", func(t *testing.T) {
		pairing := &bn254Pairing{}
		_, _, p1, p2 := bn254_gnark.Generators()

		t.Run("PairingCheck", func(t *testing.T) {
			a, err := new(bn254_fr.Element).SetRandom()
			require.NoError(t, err)

			var aG1, negAG1 bn254_gnark.G1Affine
			var aG2 bn254_gnark.G2Affine
			aG1.ScalarMultiplication(&p1, new(big.Int).SetBytes(a.Marshal()))
			aG2.ScalarMultiplication(&p2, new(big.Int).SetBytes(a.Marshal()))
			negAG1.Neg(&aG1)

			pointsG1 := [][]byte{negAG1.Marshal(), p1.Marshal()}
			pointsG2 := [][]byte{p2.Marshal(), aG2.Marshal()}

			res, err := pairing.PairingCheck(pointsG1, pointsG2)
			require.NoError(t, err)
			require.True(t, res)

			_, err = pairing.PairingCheck(pointsG1, pointsG2[:1])
			require.ErrorIs(t, err, ErrPairingPointsLenShouldMatch)

			invalidPointsG1 := append([][]byte(nil), pointsG1...)
			invalidPointsG1[0] = []byte("invalid")
			_, err = pairing.PairingCheck(invalidPointsG1, pointsG2)
			require.Error(t, err)

			invalidPointsG2 := append([][]byte(nil), pointsG2...)
			invalidPointsG2[0] = []byte("invalid")
			_, err = pairing.PairingCheck(pointsG1, invalidPointsG2)
			require.Error(t, err)
		})
	})
}

func TestECParams_String(t *testing.T) {
	params := ECParams{Curve: BN254, Group: G1}
	require.Equal(t, fmt.Sprintf("%d_%d", BN254, G1), params.String())
}
