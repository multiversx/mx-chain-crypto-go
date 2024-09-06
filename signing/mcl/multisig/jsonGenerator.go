package multisig

import (
	"encoding/hex"
	"encoding/json"
	"os"

	"github.com/multiversx/mx-chain-core-go/hashing"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
)

const blsHashSize = 16

// PredefinedTest defines the data used for testing
type PredefinedTest struct {
	TestName      string
	Message       string
	ExpectedError string
}

// predefinedKOSKAggregateSignaturesTests defines the scenarios for testing the AggregateSignatures for KOSK
var predefinedKOSKAggregateSignaturesTests = []PredefinedTest{
	{
		TestName:      "TestShouldWork",
		Message:       "a predefined message to sign",
		ExpectedError: "noError",
	},
	{
		TestName:      "TestShouldErr",
		Message:       "",
		ExpectedError: "signature is nil",
	},
}

// predefinedKOSKVerifyAggregatedSigTests defines the scenarios for testing the VerifyAggregatedSig for KOSK
var predefinedKOSKVerifyAggregatedSigTests = []PredefinedTest{
	{
		TestName:      "TestShouldWork",
		Message:       "a predefined message to sign",
		ExpectedError: "noError",
	},
	{
		TestName:      "TestShouldErr",
		Message:       "",
		ExpectedError: "signature is nil",
	},
}

// predefinedNonKOSKAggregateSignaturesTests defines the scenarios for testing the AggregateSignatures for KOSK
var predefinedNonKOSKAggregateSignaturesTests = []PredefinedTest{
	{
		TestName:      "TestShouldWork",
		Message:       "a predefined message to sign",
		ExpectedError: "noError",
	},
	{
		TestName:      "TestShouldErr",
		Message:       "",
		ExpectedError: "signature is nil",
	},
}

// predefinedNonKOSKVerifyAggregatedSigTests defines the scenarios for testing the VerifyAggregatedSig for KOSK
var predefinedNonKOSKVerifyAggregatedSigTests = []PredefinedTest{
	{
		TestName:      "TestShouldWork",
		Message:       "a predefined message to sign",
		ExpectedError: "noError",
	},
	{
		TestName:      "TestShouldErr",
		Message:       "",
		ExpectedError: "signature is nil",
	},
}

// KeyPair defines a pair of public key and private key
type KeyPair struct {
	PublicKey  string `json:"publicKey"`
	PrivateKey string `json:"privateKey"`
}

// SignaturePair defines a pair of signature and public key
type SignaturePair struct {
	Signature string `json:"signature"`
	PublicKey string `json:"publicKey"`
}

// TestVectorElement defines the data for a test vector
type TestVectorElement struct {
	Signatures          []SignaturePair `json:"signatures"`
	Message             string          `json:"message"`
	AggregatedSignature string          `json:"aggregatedSignature"`
	ErrorMessage        string          `json:"errorMessage"`
	TestName            string          `json:"testName"`
}

// JSONFileContent defines the data for generating the json file
type JSONFileContent struct {
	Keys        []KeyPair           `json:"keys"`
	TestVectors []TestVectorElement `json:"testVectors"`
}

// Key defines a tuple of public key and private key
type Key struct {
	PubKey     crypto.PublicKey
	PrivateKey crypto.PrivateKey
}

func createKeyPairs(grSize uint16, suite crypto.Suite) []Key {
	kg := signing.NewKeyGenerator(suite)
	var keys []Key

	for i := uint16(0); i < grSize; i++ {
		sk, pk := kg.GeneratePair()
		keys = append(keys, Key{
			PubKey:     pk,
			PrivateKey: sk,
		})
	}
	return keys
}

// generateJSONFileKOSKForAggregateSignaturesTests for KOSK AggregateSignaturesTests
func generateJSONFileKOSKForAggregateSignaturesTests() error {
	return generateJSONFileKOSK(predefinedKOSKAggregateSignaturesTests, "multisigKOSKAggSig.json")
}

// generateJSONFileKOSKForVerifyAggregatedSigTests for KOSK VerifyAggregatedSigTests
func generateJSONFileKOSKForVerifyAggregatedSigTests() error {
	return generateJSONFileKOSK(predefinedKOSKVerifyAggregatedSigTests, "multisigKOSKVerifyAggSig.json")
}

// generateJSONFileNonKOSKForAggregateSignaturesTests for NonKOSK AggregateSignaturesTests
func generateJSONFileNonKOSKForAggregateSignaturesTests(hasher hashing.Hasher) error {
	return generateJSONFileNonKOSK(hasher, predefinedNonKOSKAggregateSignaturesTests, "multisigNonKOSKAggSig.json")
}

// generateJSONFileNonKOSKForAggregateSignaturesTests for NonKOSK VerifyAggregatedSigTests
func generateJSONFileNonKOSKForVerifyAggregatedSig(hasher hashing.Hasher) error {
	return generateJSONFileNonKOSK(hasher, predefinedNonKOSKVerifyAggregatedSigTests, "multisigNonKOSKVerifyAggSig.json")
}

// generateJSONFileKOSK generates the JSON file for knowledge of secret key, should be used only once
func generateJSONFileKOSK(predefinedTests []PredefinedTest, filename string) error {
	suite := mcl.NewSuiteBLS12()
	mapKeys := createKeyPairs(uint16(5), suite)
	lls := &BlsMultiSignerKOSK{}

	var keyPairs []KeyPair
	var testVectors []TestVectorElement
	var jsonFileContent JSONFileContent

	var sigShares [][]byte
	var pubKeys []crypto.PublicKey

	for _, key := range mapKeys {
		pk, _ := key.PubKey.ToByteArray()
		sk, _ := key.PrivateKey.ToByteArray()

		keyPairs = append(keyPairs, KeyPair{
			PublicKey:  hex.EncodeToString(pk),
			PrivateKey: hex.EncodeToString(sk),
		})

		pubKeys = append(pubKeys, key.PubKey)
	}
	jsonFileContent.Keys = keyPairs

	var sigPairs []SignaturePair
	for _, predefinedTest := range predefinedTests {
		for _, key := range mapKeys {
			pk, _ := key.PubKey.ToByteArray()
			sig, _ := lls.SignShare(key.PrivateKey, []byte(predefinedTest.Message))

			sigShares = append(sigShares, sig)
			sigPairs = append(sigPairs, SignaturePair{
				Signature: hex.EncodeToString(sig),
				PublicKey: hex.EncodeToString(pk),
			})
		}

		aggregatedSig, _ := lls.AggregateSignatures(suite, sigShares, pubKeys)
		sigShares = sigShares[:0]

		testVectors = append(testVectors, TestVectorElement{
			Signatures:          sigPairs,
			Message:             hex.EncodeToString([]byte(predefinedTest.Message)),
			AggregatedSignature: hex.EncodeToString(aggregatedSig),
			ErrorMessage:        predefinedTest.ExpectedError,
			TestName:            predefinedTest.TestName,
		})
		sigPairs = sigPairs[:0]

	}

	jsonFileContent.TestVectors = testVectors

	b, _ := json.MarshalIndent(jsonFileContent, "", " ")

	err := os.WriteFile(filename, b, 0644)
	return err

}

// generateJSONFileNonKOSK generates the JSON file for non knowledge of secret key, should be used only once
func generateJSONFileNonKOSK(hasher hashing.Hasher, predefinedTests []PredefinedTest, filename string) error {
	suite := mcl.NewSuiteBLS12()
	kg := signing.NewKeyGenerator(suite)

	mapKeys := createKeyPairs(uint16(5), suite)
	lls := &BlsMultiSigner{}

	lls.Hasher = hasher

	var keyPairs []KeyPair
	var testVectors []TestVectorElement
	var jsonFileContent JSONFileContent

	var sigShares [][]byte
	var pubKeys []crypto.PublicKey

	for _, key := range mapKeys {
		pk, _ := key.PubKey.ToByteArray()
		sk, _ := key.PubKey.ToByteArray()

		keyPairs = append(keyPairs, KeyPair{
			PublicKey:  hex.EncodeToString(pk),
			PrivateKey: hex.EncodeToString(sk),
		})

		pubKeys = append(pubKeys, key.PubKey)
	}

	jsonFileContent.Keys = keyPairs

	var sigPairs []SignaturePair
	for _, predefinedTest := range predefinedTests {
		for _, keyPair := range keyPairs {
			pk := keyPair.PublicKey
			decodedPvKey, _ := hex.DecodeString(keyPair.PrivateKey)
			sk, _ := kg.PrivateKeyFromByteArray(decodedPvKey)
			sig, _ := lls.SignShare(sk, []byte(predefinedTest.Message))

			sigShares = append(sigShares, sig)
			sigPairs = append(sigPairs, SignaturePair{
				Signature: hex.EncodeToString(sig),
				PublicKey: pk,
			})
		}

		aggregatedSig, _ := lls.AggregateSignatures(suite, sigShares, pubKeys)
		sigShares = sigShares[:0]

		testVectors = append(testVectors, TestVectorElement{
			Signatures:          sigPairs,
			Message:             hex.EncodeToString([]byte(predefinedTest.Message)),
			AggregatedSignature: hex.EncodeToString(aggregatedSig),
			ErrorMessage:        predefinedTest.ExpectedError,
			TestName:            predefinedTest.TestName,
		})
		sigPairs = sigPairs[:0]
	}

	jsonFileContent.TestVectors = testVectors

	b, _ := json.MarshalIndent(jsonFileContent, "", " ")

	err := os.WriteFile(filename, b, 0644)
	return err

}
