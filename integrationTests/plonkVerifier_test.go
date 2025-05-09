package integrationTests

import (
	"bytes"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	gnarkplonk "github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/examples/exponentiate"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
	"github.com/multiversx/mx-chain-crypto-go/zk/plonk"
	"github.com/stretchr/testify/require"
)

func TestPlonkVerifier(t *testing.T) {
	css, err := frontend.Compile(ecc.BLS12_381.ScalarField(), scs.NewBuilder, &exponentiate.Circuit{})
	require.Nil(t, err)

	srs, srsLagrange, err := unsafekzg.NewSRS(css)

	// Setup on the prover side
	pk, vk, err := gnarkplonk.Setup(css, srs, srsLagrange)
	homework := &exponentiate.Circuit{
		X: 2,
		Y: 16,

		E: 4,
	}

	witness, err := frontend.NewWitness(homework, ecc.BLS12_381.ScalarField())
	require.Nil(t, err)

	proof, err := gnarkplonk.Prove(css, pk, witness)
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
	verified, err := plonk.VerifyPlonk(uint16(ecc.BLS12_381), serializedProof.Bytes(), serializedVK.Bytes(), pubWBytes)
	require.True(t, verified)
	require.Nil(t, err)
}
