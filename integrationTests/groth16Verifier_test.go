package integrationTests

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkgroth16 "github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/examples/exponentiate"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/multiversx/mx-chain-crypto-go/zk/groth16"
	"github.com/stretchr/testify/require"
)

func TestGroth16Verifier(t *testing.T) {
	css, err := frontend.Compile(ecc.BLS12_381.ScalarField(), r1cs.NewBuilder, &exponentiate.Circuit{})
	require.Nil(t, err)

	// Setup on the prover side
	pk, vk, err := gnarkgroth16.Setup(css)
	homework := &exponentiate.Circuit{
		X: 2,
		Y: 16,

		E: 4,
	}

	witness, err := frontend.NewWitness(homework, ecc.BLS12_381.ScalarField())
	require.Nil(t, err)

	proof, err := gnarkgroth16.Prove(css, pk, witness)
	require.Nil(t, err)

	var serializedProof bytes.Buffer
	_, err = proof.WriteTo(&serializedProof)
	require.Nil(t, err)

	var serializedVK bytes.Buffer
	_, err = vk.WriteTo(&serializedVK)
	require.Nil(t, err)

	// There are two ways to generate the public witness - either from the prover full witness, either recreate
	//  using the circuit with only the public inputs into it
	pubW, err := witness.Public()
	require.Nil(t, err)
	pubWBytes, err := pubW.MarshalBinary()
	require.Nil(t, err)
	// Now a tx can do: verify@proof_bytes@pub_witness_bytes; the curve_id and vk should be in the contract state

	verified, err := groth16.VerifyGroth16(uint16(ecc.BLS12_381), serializedProof.Bytes(), serializedVK.Bytes(), pubWBytes)
	require.True(t, verified)
	require.Nil(t, err)
}
