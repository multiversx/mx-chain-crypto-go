package singlesig_test

// TestVector defines the structure used for testing in testData directory
type TestVector struct {
	TestName     string `json:"testName"`
	SecretKeyHex string `json:"secretKeyHex"`
	PublicKeyHex string `json:"publicKeyHex"`
	Message      string `json:"message"`
	Signature    string `json:"signature"`
	Error        string `json:"error"`
}

// TestVectors defines the array of TestVector objects
type TestVectors struct {
	TestVectors []TestVector `json:"testVectors"`
	G1str       string       `json:"g1Str"`
	G2str       string       `json:"g2Str"`
	Dst         string       `json:"dst"`
}
