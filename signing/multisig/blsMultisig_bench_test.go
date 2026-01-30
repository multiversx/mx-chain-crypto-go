package multisig_test

import (
	"testing"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	mclMultisig "github.com/multiversx/mx-chain-crypto-go/signing/mcl/multisig"
	"github.com/multiversx/mx-chain-crypto-go/signing/multisig"
	"github.com/stretchr/testify/require"
)

const testMessage = "message"

func Benchmark_AggregatedSigKOSK270(b *testing.B) {
	llSig := &mclMultisig.BlsMultiSignerKOSK{}

	benchmarkAggregatedSig(270, llSig, b)
}

func Benchmark_AggregatedSigKOSK400(b *testing.B) {
	llSig := &mclMultisig.BlsMultiSignerKOSK{}

	benchmarkAggregatedSig(400, llSig, b)
}

func benchmarkAggregatedSig(nPubKeys uint16, llSig crypto.LowLevelSignerBLS, b *testing.B) {
	msg := []byte(testMessage)
	multiSigner, pubKeys, sigShares := createSigSharesBLS(nPubKeys, msg, llSig)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := multiSigner.AggregateSigs(pubKeys, sigShares)
		require.Nil(b, err)
	}
}

func Benchmark_ConvertBytesToPubKeys_400(b *testing.B) {
	benchmarkConvertBytesToPubKeys(400, b)
}

func Benchmark_ConvertBytesToPubKeys_270(b *testing.B) {
	benchmarkConvertBytesToPubKeys(270, b)
}

func benchmarkConvertBytesToPubKeys(nPubKeys uint16, b *testing.B) {
	pubKeysBytes, kg := generateMultiSigParamsBLS(int(nPubKeys))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := multisig.ConvertBytesToPubKeys(pubKeysBytes, kg)
		require.Nil(b, err)
	}
}

func Benchmark_ConvertBytesToPrivKeys_400(b *testing.B) {
	benchmarkConvertBytesToPrivKeys(400, b)
}

func Benchmark_ConvertBytesToPrivKeys_270(b *testing.B) {
	benchmarkConvertBytesToPrivKeys(270, b)
}

func Benchmark_ConvertBytesToPrivKeys_1(b *testing.B) {
	benchmarkConvertBytesToPrivKeys(1, b)
}

func benchmarkConvertBytesToPrivKeys(nbSigners uint16, b *testing.B) {
	privKeys, _, kg := generateMultiSigParamsBLSWithPrivateKeys(int(nbSigners))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, privKeyBytes := range privKeys {
			_, err := multisig.ConvertBytesToPrivateKey(privKeyBytes, kg)
			require.Nil(b, err)
		}
	}
}
