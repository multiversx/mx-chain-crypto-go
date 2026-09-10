package testData

import (
	"encoding/hex"
	"encoding/json"
	"os"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
)

const numKeys = 5

func createKeyPairs(grSize uint16, suite crypto.Suite) []Key {
	kg := signing.NewKeyGenerator(suite)
	keys := make([]Key, 0, grSize)

	for i := uint16(0); i < grSize; i++ {
		sk, pk := kg.GeneratePair()
		keys = append(keys, Key{
			PubKey:     pk,
			PrivateKey: sk,
		})
	}
	return keys
}

// GenerateJSONFileKOSKForAggregateSignaturesTests for KOSK AggregateSignaturesTests
func GenerateJSONFileKOSKForAggregateSignaturesTests(signer crypto.LowLevelSignerBLS) error {
	return generateJSONFile(signer, predefinedAggregateSignaturesTests, "testData/multisigKOSKAggSig.json")
}

// GenerateJSONFileKOSKForVerifyAggregatedSigTests for KOSK VerifyAggregatedSigTests
func GenerateJSONFileKOSKForVerifyAggregatedSigTests(signer crypto.LowLevelSignerBLS) error {
	return generateJSONFile(signer, predefinedAggregateSignaturesTests, "testData/multisigKOSKVerifyAggSig.json")
}

// GenerateJSONFileNonKOSKForAggregateSignaturesTests for NonKOSK AggregateSignaturesTests
func GenerateJSONFileNonKOSKForAggregateSignaturesTests(signer crypto.LowLevelSignerBLS) error {
	return generateJSONFile(signer, predefinedAggregateSignaturesTests, "testData/multisigNonKOSKAggSig.json")
}

// GenerateJSONFileNonKOSKForVerifyAggregatedSigTests for NonKOSK VerifyAggregatedSigTests
func GenerateJSONFileNonKOSKForVerifyAggregatedSigTests(signer crypto.LowLevelSignerBLS) error {
	return generateJSONFile(signer, predefinedAggregateSignaturesTests, "testData/multisigNonKOSKVerifyAggSig.json")
}

// generateJSONFile generates the JSON file for KOSK/NonKOSK, should be used only once
func generateJSONFile(lls crypto.LowLevelSignerBLS, predefinedTests []PredefinedTest, filename string) error {
	suite := mcl.NewSuiteBLS12()

	mapKeys := createKeyPairs(numKeys, suite)

	var jsonFileContent JSONFileContent

	var sigShares [][]byte
	var pubKeys []crypto.PublicKey

	for _, key := range mapKeys {
		pk, _ := key.PubKey.ToByteArray()
		sk, _ := key.PubKey.ToByteArray()

		jsonFileContent.Keys = append(jsonFileContent.Keys, KeyPair{
			PublicKey:  hex.EncodeToString(pk),
			PrivateKey: hex.EncodeToString(sk),
		})

		pubKeys = append(pubKeys, key.PubKey)
	}

	sigPairs := make([]SignaturePair, 0, numKeys*len(predefinedTests))
	for _, predefinedTest := range predefinedTests {
		for _, key := range mapKeys {
			pk, _ := key.PubKey.ToByteArray()

			sig, err := lls.SignShare(key.PrivateKey, []byte(predefinedTest.Message))
			if err != nil {
				return err
			}

			sigShares = append(sigShares, sig)
			sigPairs = append(sigPairs, SignaturePair{
				Signature: hex.EncodeToString(sig),
				PublicKey: hex.EncodeToString(pk),
			})
		}

		aggregatedSig, _ := lls.AggregateSignatures(suite, sigShares, pubKeys)
		sigShares = sigShares[:0]

		jsonFileContent.TestVectors = append(jsonFileContent.TestVectors, TestVectorElement{
			Signatures:          sigPairs,
			Message:             hex.EncodeToString([]byte(predefinedTest.Message)),
			AggregatedSignature: hex.EncodeToString(aggregatedSig),
			ErrorMessage:        predefinedTest.ExpectedError,
			TestName:            predefinedTest.TestName,
		})
		sigPairs = sigPairs[:0]
	}

	marshalledJsonFileContent, err := json.MarshalIndent(jsonFileContent, "", " ")
	if err != nil {
		return err
	}

	err = os.WriteFile(filename, marshalledJsonFileContent, os.ModeAppend)
	return err

}
