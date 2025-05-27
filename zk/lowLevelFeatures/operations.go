package lowLevelFeatures

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	bls123772 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	bls12377fp "github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	bls12377fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls123812 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	bls12381fp "github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
	bls12381fr "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	bn2542 "github.com/consensys/gnark-crypto/ecc/bn254"
	bn254fp "github.com/consensys/gnark-crypto/ecc/bn254/fp"
	bn254fr "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12377"
	"github.com/multiversx/mx-chain-crypto-go/curves/bls/bls12381"
	"github.com/multiversx/mx-chain-crypto-go/curves/bn254"
)

type ECParams struct {
	Curve ID
	Group GroupID
}

func (ecp *ECParams) String() string {
	return fmt.Sprintf("%d_%d", ecp.Curve, ecp.Group)
}

type ECGroup interface {
	Add([]byte, []byte) ([]byte, error)
	Mul([]byte, []byte) ([]byte, error)
	MultiExp([][]byte, [][]byte) ([]byte, error)
	MapToCurve([]byte) ([]byte, error)
}

type PairingGroup interface {
	PairingCheck([][]byte, [][]byte) (bool, error)
}

type bls12381G1 struct{}

func (b12g1 *bls12381G1) unmarshalPointsG1(points ...[]byte) ([]crypto.Point, error) {
	uPoints := make([]crypto.Point, len(points))
	for i, p := range points {
		uPoints[i] = bls12381.NewPointG1()
		err := uPoints[i].UnmarshalBinary(p)
		if err != nil {
			return nil, err
		}
	}

	return uPoints, nil
}

func (b12g1 *bls12381G1) Add(p1, p2 []byte) ([]byte, error) {
	pointsSlice, err := b12g1.unmarshalPointsG1(p1, p2)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 2 {
		return nil, ErrInvalidPoints
	}

	res, err := pointsSlice[0].Add(pointsSlice[1])
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g1 *bls12381G1) Mul(point, scalar []byte) ([]byte, error) {
	pointsSlice, err := b12g1.unmarshalPointsG1(point)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 1 {
		return nil, ErrInvalidPoints
	}

	sc := bls12381.NewScalar()
	err = sc.UnmarshalBinary(scalar)
	if err != nil {
		return nil, err
	}

	res, err := pointsSlice[0].Mul(sc)
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g1 *bls12381G1) MultiExp(points, scalars [][]byte) ([]byte, error) {
	if len(points) != len(scalars) {
		return nil, ErrPointsAndScalarsShouldMatch
	}

	underlyingP := make([]bls123812.G1Affine, len(points))
	underlyingS := make([]bls12381fr.Element, len(scalars))
	for i := range points {
		p := bls123812.G1Affine{}
		err := p.Unmarshal(points[i])
		if err != nil {
			return nil, err
		}

		underlyingP[i] = p
		underlyingS[i] = *new(bls12381fr.Element).SetBytes(scalars[i])
	}

	r := new(bls123812.G1Affine)
	r, err := r.MultiExp(underlyingP, underlyingS, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}

	return r.Marshal(), nil
}

func (b12g1 *bls12381G1) MapToCurve(element []byte) ([]byte, error) {
	if len(element) != 48 {
		return nil, ErrInvalidFpElement
	}

	fpEl, err := bls12381fp.BigEndian.Element((*[48]byte)(element))
	if err != nil {
		return nil, err
	}

	point := bls123812.MapToG1(fpEl)
	return point.Marshal(), nil
}

type bls12381G2 struct{}

func (b12g2 *bls12381G2) unmarshalPointsG2(points ...[]byte) ([]crypto.Point, error) {
	uPoints := make([]crypto.Point, len(points))
	for i, p := range points {
		uPoints[i] = bls12381.NewPointG2()
		err := uPoints[i].UnmarshalBinary(p)
		if err != nil {
			return nil, err
		}
	}

	return uPoints, nil
}

func (b12g2 *bls12381G2) Add(p1, p2 []byte) ([]byte, error) {
	pointsSlice, err := b12g2.unmarshalPointsG2(p1, p2)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 2 {
		return nil, ErrInvalidPoints
	}

	res, err := pointsSlice[0].Add(pointsSlice[1])
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g2 *bls12381G2) Mul(point, scalar []byte) ([]byte, error) {
	pointsSlice, err := b12g2.unmarshalPointsG2(point)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 1 {
		return nil, ErrInvalidPoints
	}

	sc := bls12381.NewScalar()
	err = sc.UnmarshalBinary(scalar)
	if err != nil {
		return nil, err
	}

	res, err := pointsSlice[0].Mul(sc)
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g2 *bls12381G2) MultiExp(points, scalars [][]byte) ([]byte, error) {
	if len(points) != len(scalars) {
		return nil, ErrPointsAndScalarsShouldMatch
	}

	underlyingP := make([]bls123812.G2Affine, len(points))
	underlyingS := make([]bls12381fr.Element, len(scalars))
	for i := range points {
		p := bls123812.G2Affine{}
		err := p.Unmarshal(points[i])
		if err != nil {
			return nil, err
		}

		underlyingP[i] = p
		underlyingS[i] = *new(bls12381fr.Element).SetBytes(scalars[i])
	}

	r := new(bls123812.G2Affine)
	r, err := r.MultiExp(underlyingP, underlyingS, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}

	return r.Marshal(), nil
}

func (b12g2 *bls12381G2) MapToCurve(element []byte) ([]byte, error) {
	if len(element) != 96 {
		return nil, ErrInvalidFpElement
	}

	fpEl0, err := bls12381fp.BigEndian.Element((*[48]byte)(element[:48]))
	if err != nil {
		return nil, err
	}
	fpEl1, err := bls12381fp.BigEndian.Element((*[48]byte)(element[49:]))
	if err != nil {
		return nil, err
	}

	point := bls123812.MapToG2(bls123812.E2{A0: fpEl0, A1: fpEl1})
	return point.Marshal(), nil
}

type bls12377G1 struct{}

func (b12g1 *bls12377G1) unmarshalPointsG1(points ...[]byte) ([]crypto.Point, error) {
	uPoints := make([]crypto.Point, len(points))
	for i, p := range points {
		uPoints[i] = bls12377.NewPointG1()
		err := uPoints[i].UnmarshalBinary(p)
		if err != nil {
			return nil, err
		}
	}

	return uPoints, nil
}

func (b12g1 *bls12377G1) Add(p1, p2 []byte) ([]byte, error) {
	pointsSlice, err := b12g1.unmarshalPointsG1(p1, p2)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 2 {
		return nil, ErrInvalidPoints
	}

	res, err := pointsSlice[0].Add(pointsSlice[1])
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g1 *bls12377G1) Mul(point, scalar []byte) ([]byte, error) {
	pointsSlice, err := b12g1.unmarshalPointsG1(point)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 1 {
		return nil, ErrInvalidPoints
	}

	sc := bls12377.NewScalar()
	err = sc.UnmarshalBinary(scalar)
	if err != nil {
		return nil, err
	}

	res, err := pointsSlice[0].Mul(sc)
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g1 *bls12377G1) MultiExp(points, scalars [][]byte) ([]byte, error) {
	if len(points) != len(scalars) {
		return nil, ErrPointsAndScalarsShouldMatch
	}

	underlyingP := make([]bls123772.G1Affine, len(points))
	underlyingS := make([]bls12377fr.Element, len(scalars))
	for i := range points {
		p := bls123772.G1Affine{}
		err := p.Unmarshal(points[i])
		if err != nil {
			return nil, err
		}

		underlyingP[i] = p
		underlyingS[i] = *new(bls12377fr.Element).SetBytes(scalars[i])
	}

	r := new(bls123772.G1Affine)
	r, err := r.MultiExp(underlyingP, underlyingS, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}

	return r.Marshal(), nil
}

func (b12g1 *bls12377G1) MapToCurve(element []byte) ([]byte, error) {
	if len(element) != 48 {
		return nil, ErrInvalidFpElement
	}

	fpEl, err := bls12377fp.BigEndian.Element((*[48]byte)(element))
	if err != nil {
		return nil, err
	}

	point := bls123772.MapToG1(fpEl)
	return point.Marshal(), nil
}

type bls12377G2 struct{}

func (b12g2 *bls12377G2) unmarshalPointsG2(points ...[]byte) ([]crypto.Point, error) {
	uPoints := make([]crypto.Point, len(points))
	for i, p := range points {
		uPoints[i] = bls12377.NewPointG2()
		err := uPoints[i].UnmarshalBinary(p)
		if err != nil {
			return nil, err
		}
	}

	return uPoints, nil
}

func (b12g2 *bls12377G2) Add(p1, p2 []byte) ([]byte, error) {
	pointsSlice, err := b12g2.unmarshalPointsG2(p1, p2)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 2 {
		return nil, ErrInvalidPoints
	}

	res, err := pointsSlice[0].Add(pointsSlice[1])
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g2 *bls12377G2) Mul(point, scalar []byte) ([]byte, error) {
	pointsSlice, err := b12g2.unmarshalPointsG2(point)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 1 {
		return nil, ErrInvalidPoints
	}

	sc := bls12377.NewScalar()
	err = sc.UnmarshalBinary(scalar)
	if err != nil {
		return nil, err
	}

	res, err := pointsSlice[0].Mul(sc)
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (b12g2 *bls12377G2) MultiExp(points, scalars [][]byte) ([]byte, error) {
	if len(points) != len(scalars) {
		return nil, ErrPointsAndScalarsShouldMatch
	}

	underlyingP := make([]bls123772.G2Affine, len(points))
	underlyingS := make([]bls12377fr.Element, len(scalars))
	for i := range points {
		p := bls123772.G2Affine{}
		err := p.Unmarshal(points[i])
		if err != nil {
			return nil, err
		}

		underlyingP[i] = p
		underlyingS[i] = *new(bls12377fr.Element).SetBytes(scalars[i])
	}

	r := new(bls123772.G2Affine)
	r, err := r.MultiExp(underlyingP, underlyingS, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}

	return r.Marshal(), nil
}

func (b12g2 *bls12377G2) MapToCurve(element []byte) ([]byte, error) {
	if len(element) != 96 {
		return nil, ErrInvalidFpElement
	}

	fpEl0, err := bls12377fp.BigEndian.Element((*[48]byte)(element[:48]))
	if err != nil {
		return nil, err
	}
	fpEl1, err := bls12377fp.BigEndian.Element((*[48]byte)(element[49:]))
	if err != nil {
		return nil, err
	}

	point := bls123772.MapToG2(bls123772.E2{A0: fpEl0, A1: fpEl1})
	return point.Marshal(), nil
}

type bn254G1 struct{}

func (bng1 *bn254G1) unmarshalPointsG1(points ...[]byte) ([]crypto.Point, error) {
	uPoints := make([]crypto.Point, len(points))
	for i, p := range points {
		uPoints[i] = bn254.NewPointG1()
		err := uPoints[i].UnmarshalBinary(p)
		if err != nil {
			return nil, err
		}
	}

	return uPoints, nil
}

func (bng1 *bn254G1) Add(p1, p2 []byte) ([]byte, error) {
	pointsSlice, err := bng1.unmarshalPointsG1(p1, p2)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 2 {
		return nil, ErrInvalidPoints
	}

	res, err := pointsSlice[0].Add(pointsSlice[1])
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (bng1 *bn254G1) Mul(point, scalar []byte) ([]byte, error) {
	pointsSlice, err := bng1.unmarshalPointsG1(point)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 1 {
		return nil, ErrInvalidPoints
	}

	sc := bn254.NewScalar()
	err = sc.UnmarshalBinary(scalar)
	if err != nil {
		return nil, err
	}

	res, err := pointsSlice[0].Mul(sc)
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (bng1 *bn254G1) MultiExp(points, scalars [][]byte) ([]byte, error) {
	if len(points) != len(scalars) {
		return nil, ErrPointsAndScalarsShouldMatch
	}

	underlyingP := make([]bn2542.G1Affine, len(points))
	underlyingS := make([]bn254fr.Element, len(scalars))
	for i := range points {
		p := bn2542.G1Affine{}
		err := p.Unmarshal(points[i])
		if err != nil {
			return nil, err
		}

		underlyingP[i] = p
		underlyingS[i] = *new(bn254fr.Element).SetBytes(scalars[i])
	}

	r := new(bn2542.G1Affine)
	r, err := r.MultiExp(underlyingP, underlyingS, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}

	return r.Marshal(), nil
}

func (bng1 *bn254G1) MapToCurve(element []byte) ([]byte, error) {
	if len(element) != 32 {
		return nil, ErrInvalidFpElement
	}

	fpEl, err := bn254fp.BigEndian.Element((*[32]byte)(element))
	if err != nil {
		return nil, err
	}

	point := bn2542.MapToG1(fpEl)
	return point.Marshal(), nil
}

type bn254G2 struct{}

func (bng2 *bn254G2) unmarshalPointsG2(points ...[]byte) ([]crypto.Point, error) {
	uPoints := make([]crypto.Point, len(points))
	for i, p := range points {
		uPoints[i] = bn254.NewPointG2()
		err := uPoints[i].UnmarshalBinary(p)
		if err != nil {
			return nil, err
		}
	}

	return uPoints, nil
}

func (bng2 *bn254G2) Add(p1, p2 []byte) ([]byte, error) {
	pointsSlice, err := bng2.unmarshalPointsG2(p1, p2)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 2 {
		return nil, ErrInvalidPoints
	}

	res, err := pointsSlice[0].Add(pointsSlice[1])
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (bng2 *bn254G2) Mul(point, scalar []byte) ([]byte, error) {
	pointsSlice, err := bng2.unmarshalPointsG2(point)
	if err != nil {
		return nil, err
	}
	if len(pointsSlice) != 1 {
		return nil, ErrInvalidPoints
	}

	sc := bn254.NewScalar()
	err = sc.UnmarshalBinary(scalar)
	if err != nil {
		return nil, err
	}

	res, err := pointsSlice[0].Mul(sc)
	resBytes, err := res.MarshalBinary()
	if err != nil {
		return nil, err
	}

	return resBytes, nil
}

func (bng2 *bn254G2) MultiExp(points, scalars [][]byte) ([]byte, error) {
	if len(points) != len(scalars) {
		return nil, ErrPointsAndScalarsShouldMatch
	}

	underlyingP := make([]bn2542.G2Affine, len(points))
	underlyingS := make([]bn254fr.Element, len(scalars))
	for i := range points {
		p := bn2542.G2Affine{}
		err := p.Unmarshal(points[i])
		if err != nil {
			return nil, err
		}

		underlyingP[i] = p
		underlyingS[i] = *new(bn254fr.Element).SetBytes(scalars[i])
	}

	r := new(bn2542.G2Affine)
	r, err := r.MultiExp(underlyingP, underlyingS, ecc.MultiExpConfig{})
	if err != nil {
		return nil, err
	}

	return r.Marshal(), nil
}

func (bng2 *bn254G2) MapToCurve(element []byte) ([]byte, error) {
	if len(element) != 64 {
		return nil, ErrInvalidFpElement
	}

	fpEl0, err := bn254fp.BigEndian.Element((*[32]byte)(element[:32]))
	if err != nil {
		return nil, err
	}
	fpEl1, err := bn254fp.BigEndian.Element((*[32]byte)(element[33:]))
	if err != nil {
		return nil, err
	}

	point := bn2542.MapToG2(bn2542.E2{A0: fpEl0, A1: fpEl1})
	return point.Marshal(), nil
}

type bls12381Pairing struct{}

func (b12381 *bls12381Pairing) PairingCheck(pointsG1, pointsG2 [][]byte) (bool, error) {
	if len(pointsG1) != len(pointsG2) {
		return false, ErrPairingPointsLenShouldMatch
	}
	g1Points := make([]bls123812.G1Affine, len(pointsG1))
	g2Points := make([]bls123812.G2Affine, len(pointsG2))

	for i := range pointsG1 {
		pg1 := bls123812.G1Affine{}
		err := pg1.Unmarshal(pointsG1[i])
		if err != nil {
			return false, err
		}
		g1Points[i] = pg1

		pg2 := bls123812.G2Affine{}
		err = pg2.Unmarshal(pointsG2[i])
		if err != nil {
			return false, err
		}
		g2Points[i] = pg2
	}

	ok, err := bls123812.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, err
	}

	return ok, nil
}

type bls12377Pairing struct{}

func (b12377 *bls12377Pairing) PairingCheck(pointsG1, pointsG2 [][]byte) (bool, error) {
	if len(pointsG1) != len(pointsG2) {
		return false, ErrPairingPointsLenShouldMatch
	}
	g1Points := make([]bls123772.G1Affine, len(pointsG1))
	g2Points := make([]bls123772.G2Affine, len(pointsG2))

	for i := range pointsG1 {
		pg1 := bls123772.G1Affine{}
		err := pg1.Unmarshal(pointsG1[i])
		if err != nil {
			return false, err
		}
		g1Points[i] = pg1

		pg2 := bls123772.G2Affine{}
		err = pg2.Unmarshal(pointsG2[i])
		if err != nil {
			return false, err
		}
		g2Points[i] = pg2
	}

	ok, err := bls123772.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, err
	}

	return ok, nil
}

type bn254Pairing struct{}

func (bn254 *bn254Pairing) PairingCheck(pointsG1, pointsG2 [][]byte) (bool, error) {
	if len(pointsG1) != len(pointsG2) {
		return false, ErrPairingPointsLenShouldMatch
	}
	g1Points := make([]bn2542.G1Affine, len(pointsG1))
	g2Points := make([]bn2542.G2Affine, len(pointsG2))

	for i := range pointsG1 {
		pg1 := bn2542.G1Affine{}
		err := pg1.Unmarshal(pointsG1[i])
		if err != nil {
			return false, err
		}
		g1Points[i] = pg1

		pg2 := bn2542.G2Affine{}
		err = pg2.Unmarshal(pointsG2[i])
		if err != nil {
			return false, err
		}
		g2Points[i] = pg2
	}

	ok, err := bn2542.PairingCheck(g1Points, g2Points)
	if err != nil {
		return false, err
	}

	return ok, nil
}

var EcRegistry = map[ECParams]ECGroup{
	{BLS12_381, G1}: &bls12381G1{},
	{BLS12_381, G2}: &bls12381G2{},
	{BLS12_377, G1}: &bls12377G1{},
	{BLS12_377, G2}: &bls12377G2{},
	{BN254, G1}:     &bn254G1{},
	{BN254, G2}:     &bn254G2{},
}

var PairingRegistry = map[ID]PairingGroup{
	BLS12_381: &bls12381Pairing{},
	BLS12_377: &bls12377Pairing{},
	BN254:     &bn254Pairing{},
}
