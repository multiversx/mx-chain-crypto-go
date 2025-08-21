package groth16

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
)

// CubicCircuit defines a simple circuit
type CubicCircuit struct {
	X frontend.Variable `gnark:"x"`
	Y frontend.Variable `gnark:"y,public"`
}

// Define defines the circuit constraints
func (circuit *CubicCircuit) Define(api frontend.API) error {
	x3 := api.Mul(circuit.X, circuit.X, circuit.X)
	api.AssertIsEqual(circuit.Y, api.Add(x3, circuit.X, 5))
	return nil
}

func TestVerifyGroth16(t *testing.T) {
	// 1. Compile the circuit
	var circuit CubicCircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	require.NoError(t, err)

	// 2. Run the setup
	pk, vk, err := groth16.Setup(ccs)
	require.NoError(t, err)

	// 3. Create a valid witness
	assignment := CubicCircuit{X: 3, Y: 35}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicW, err := w.Public()
	require.NoError(t, err)

	// 4. Generate a proof
	proof, err := groth16.Prove(ccs, pk, w)
	require.NoError(t, err)

	// 5. Convert vk, proof, and public witness to bytes
	var vkBuf bytes.Buffer
	_, err = vk.WriteTo(&vkBuf)
	require.NoError(t, err)
	vkBytes := vkBuf.Bytes()

	var proofBuf bytes.Buffer
	_, err = proof.WriteTo(&proofBuf)
	require.NoError(t, err)
	proofBytes := proofBuf.Bytes()

	pubWitnessBytes, err := publicW.MarshalBinary()
	require.NoError(t, err)

	// 6. Test success case
	ok, err := VerifyGroth16(uint16(ecc.BN254), proofBytes, vkBytes, pubWitnessBytes)
	require.NoError(t, err)
	require.True(t, ok)

	// 7. Test failure cases
	// Invalid proof
	invalidProofBytes := append([]byte(nil), proofBytes...)
	invalidProofBytes[0] ^= 0x01
	ok, err = VerifyGroth16(uint16(ecc.BN254), invalidProofBytes, vkBytes, pubWitnessBytes)
	require.Error(t, err)
	require.False(t, ok)

	// Invalid public witness
	invalidAssignment := CubicCircuit{X: 3, Y: 36} // Y is incorrect
	invalidW, err := frontend.NewWitness(&invalidAssignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	invalidPublicW, err := invalidW.Public()
	require.NoError(t, err)
	invalidPubWitnessBytes, err := invalidPublicW.MarshalBinary()
	require.NoError(t, err)
	ok, err = VerifyGroth16(uint16(ecc.BN254), proofBytes, vkBytes, invalidPubWitnessBytes)
	require.Error(t, err)
	require.False(t, ok)

	// Invalid vk
	invalidVkBytes := append([]byte(nil), vkBytes...)
	invalidVkBytes[0] ^= 0x01
	ok, err = VerifyGroth16(uint16(ecc.BN254), proofBytes, invalidVkBytes, pubWitnessBytes)
	require.Error(t, err)
	require.False(t, ok)

	// test error cases from my previous fix
	_, err = VerifyGroth16(uint16(ecc.BN254), []byte("invalid"), vkBytes, pubWitnessBytes)
	require.Error(t, err)

	// create a dummy witness for a different curve
	invalidWitness, err := witness.New(ecc.BLS12_381.ScalarField())
	require.NoError(t, err)
	invalidWitnessBytes, err := invalidWitness.MarshalBinary()
	require.NoError(t, err)
	ok, err = VerifyGroth16(uint16(ecc.BN254), proofBytes, vkBytes, invalidWitnessBytes)
	require.Error(t, err)
	require.False(t, ok)

	// test invalid curve
	TestVerifyGroth16_InvalidCurve(t)
}

func TestVerifyGroth16_InvalidCurve(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()
	_, _ = VerifyGroth16(uint16(ecc.UNKNOWN), nil, nil, nil)
}
