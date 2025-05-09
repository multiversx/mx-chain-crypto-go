package plonk

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/backend/witness"
)

func VerifyPlonk(curveID uint16, proofBytes, vkBytes, pubWitnessBytes []byte) (bool, error) {
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
