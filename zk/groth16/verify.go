package groth16

import (
	"bytes"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/multiversx/mx-chain-crypto-go/zk/lowLevelFeatures"
)

// VerifyGroth16 verifies the groth16 proof from the given input and curve id
func VerifyGroth16(curveID uint16, proofBytes, vkBytes, pubWitnessBytes []byte) (bool, error) {
	if len(proofBytes) == 0 || len(vkBytes) == 0 || len(pubWitnessBytes) == 0 {
		return false, lowLevelFeatures.ErrNilOrEmptyInput
	}

	_, ok := lowLevelFeatures.SupportedCurvesRegistry[ecc.ID(curveID)]
	if !ok {
		return false, lowLevelFeatures.ErrInvalidCurve
	}

	vk := groth16.NewVerifyingKey(ecc.ID(curveID))
	_, err := vk.ReadFrom(bytes.NewReader(vkBytes))
	if err != nil {
		return false, err
	}

	proof := groth16.NewProof(ecc.ID(curveID))
	_, err = proof.ReadFrom(bytes.NewReader(proofBytes))
	if err != nil {
		return false, err
	}

	pubWitness, err := witness.New(ecc.ID(curveID).ScalarField())
	if err != nil {
		return false, err
	}
	err = pubWitness.UnmarshalBinary(pubWitnessBytes)
	if err != nil {
		return false, err
	}

	err = groth16.Verify(proof, vk, pubWitness)
	if err != nil {
		return false, nil
	}

	return true, nil
}
