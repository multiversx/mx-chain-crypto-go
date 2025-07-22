package testData

import (
	crypto "github.com/multiversx/mx-chain-crypto-go"
)

// PredefinedTest defines the data used for testing
type PredefinedTest struct {
	TestName      string
	Message       string
	ExpectedError string
}

// predefinedAggregateSignaturesTests defines the scenarios for testing the AggregateSignatures
var predefinedAggregateSignaturesTests = []PredefinedTest{
	{
		TestName:      "TestShouldWork",
		Message:       "a predefined message to sign",
		ExpectedError: "noError",
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
