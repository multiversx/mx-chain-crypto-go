package multisig

import (
	"encoding/hex"
	"encoding/json"
	"os"

	crypto "github.com/multiversx/mx-chain-crypto-go"
	"github.com/multiversx/mx-chain-crypto-go/signing"
	"github.com/multiversx/mx-chain-crypto-go/signing/mcl"
)

// PredefinedTest defines the data used for testing
type PredefinedTest struct {
	TestName      string
	Message       string
	ExpectedError string
}

// predefinedTests defines the scenarios
var predefinedTests = []PredefinedTest{{
	TestName:      "TestShouldWork",
	Message:       "a predefined message to sign",
	ExpectedError: "noError",
}}

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

func createKeyPairs(grSize uint16, suite crypto.Suite) map[crypto.PublicKey]crypto.PrivateKey {
	kg := signing.NewKeyGenerator(suite)
	mapKeys := make(map[crypto.PublicKey]crypto.PrivateKey)

	for i := uint16(0); i < grSize; i++ {
		sk, pk := kg.GeneratePair()
		mapKeys[pk] = sk
	}
	return mapKeys
}

// generateJSONFileKOSK generates the JSON file, should be used only once
func generateJSONFileKOSK() error {
	suite := mcl.NewSuiteBLS12()
	mapKeys := createKeyPairs(uint16(400), suite)
	lls := &BlsMultiSignerKOSK{}

	var keyPairs []KeyPair
	var testVectors []TestVectorElement
	var jsonFileContent JSONFileContent

	var sigShares [][]byte
	var pubKeys []crypto.PublicKey

	for pbKey, pvKey := range mapKeys {
		pk, _ := pbKey.ToByteArray()
		sk, _ := pvKey.ToByteArray()

		keyPairs = append(keyPairs, KeyPair{
			PublicKey:  hex.EncodeToString(pk),
			PrivateKey: hex.EncodeToString(sk),
		})

		pubKeys = append(pubKeys, pbKey)
	}
	jsonFileContent.Keys = keyPairs

	var sigPairs []SignaturePair
	for _, predefinedTest := range predefinedTests {
		for pbKey, pvKey := range mapKeys {
			pk, _ := pbKey.ToByteArray()
			sig, _ := lls.SignShare(pvKey, []byte(predefinedTest.Message))

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
	}

	jsonFileContent.TestVectors = testVectors

	b, _ := json.MarshalIndent(jsonFileContent, "", " ")

	err := os.WriteFile("KOSKmultisig.json", b, 0644)
	return err

}
