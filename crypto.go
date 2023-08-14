package crypto

type PrivKey interface {
	Sign(msg []byte) ([]byte, error)
	PubKey() PubKey
	Equals(PrivKey) bool
}

type PubKey interface {
	Verify(msg []byte, sig []byte) bool
	Equals(PubKey) bool
}
