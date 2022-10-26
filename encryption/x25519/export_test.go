package x25519

func NewScalar(key PrivateKey) *x25519Scalar {
	return &x25519Scalar{key}
}

func IsKeyValid(key PrivateKey) error {
	return isKeyValid(key)
}
