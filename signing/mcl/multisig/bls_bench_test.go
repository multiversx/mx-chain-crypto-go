package multisig_test

import (
	"testing"

	crypto "github.com/ElrondNetwork/elrond-go-crypto"
	"github.com/ElrondNetwork/elrond-go-crypto/mock"
	"github.com/ElrondNetwork/elrond-go-crypto/signing"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/mcl"
	"github.com/ElrondNetwork/elrond-go-crypto/signing/mcl/multisig"
	"github.com/herumi/bls-go-binary/bls"
	"github.com/stretchr/testify/require"
)

func Benchmark_PreparePublicKeys(b *testing.B) {
	hasher := &mock.HasherSpongeMock{}

	pubKeys := createBLSPubKeys(400)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prepPubKeys, err := multisig.PreparePublicKeys(pubKeys, hasher, pubKeys[0].Suite())
		require.Nil(b, err)
		require.NotNil(b, prepPubKeys)
	}
}

func Benchmark_VerifyAggregatedSig(b *testing.B) {
	msg := []byte("testMessage")

	hasher := &mock.HasherSpongeMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	pubKeys, sigShares := createSigSharesBLS(400, msg)
	aggSigBytes, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = llSig.VerifyAggregatedSig(pubKeys[0].Suite(), pubKeys, aggSigBytes, msg)
		require.Nil(b, err)
	}
}

func Benchmark_VerifyAggregatedSigWithoutPrepare(b *testing.B) {
	msg := []byte("testMessage")

	hasher := &mock.HasherSpongeMock{}
	llSig := &multisig.BlsMultiSigner{Hasher: hasher}
	pubKeys, sigShares := createSigSharesBLS(400, msg)
	aggSigBytes, err := llSig.AggregateSignatures(pubKeys[0].Suite(), sigShares, pubKeys)
	require.Nil(b, err)

	prepPubKeys, err := multisig.PreparePublicKeys(pubKeys, hasher, pubKeys[0].Suite())
	require.Nil(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		aggSig := &bls.Sign{}
		err = aggSig.Deserialize(aggSigBytes)
		require.Nil(b, err)

		res := aggSig.FastAggregateVerify(prepPubKeys, msg)
		require.True(b, res)
	}
}

func createBLSPubKeys(
	nPubKeys uint16,
) (pubKeys []crypto.PublicKey) {
	suite := mcl.NewSuiteBLS12()
	kg := signing.NewKeyGenerator(suite)

	pubKeys = make([]crypto.PublicKey, nPubKeys)

	for i := uint16(0); i < nPubKeys; i++ {
		_, pk := kg.GeneratePair()
		pubKeys[i] = pk
	}

	return pubKeys
}
