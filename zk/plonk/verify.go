package plonk

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
	"github.com/multiversx/mx-chain-crypto-go/zk/lowLevelFeatures"
)

// VerifyPlonk verifies the plonk signature on the given curveID
func VerifyPlonk(curveID uint16, proofBytes, vkBytes, pubWitnessBytes []byte) (bool, error) {
	if len(proofBytes) == 0 || len(vkBytes) == 0 || len(pubWitnessBytes) == 0 {
		return false, lowLevelFeatures.ErrNilOrEmptyInput
	}

	_, ok := lowLevelFeatures.SupportedCurvesRegistry[ecc.ID(curveID)]
	if !ok {
		return false, lowLevelFeatures.ErrInvalidCurve
	}

	vk := plonk.NewVerifyingKey(ecc.ID(curveID))
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return false, err
	}

	proof := plonk.NewProof(ecc.ID(curveID))
	if _, err := proof.ReadFrom(bytes.NewReader(proofBytes)); err != nil {
		return false, err
	}

	w, err := witness.New(ecc.ID(curveID).ScalarField())
	if err != nil {
		return false, err
	}

	err = w.UnmarshalBinary(pubWitnessBytes)
	if err != nil {
		return false, err
	}

	err = plonk.Verify(proof, vk, w)
	if err != nil {
		return false, nil
	}

	return true, nil
}
