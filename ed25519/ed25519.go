package ed25519

import (
	"bytes"
	"crypto/ed25519"
	"crypto/subtle"
	"io"

	"github.com/eybase/crypto"
)

type PrivKey [ed25519.PrivateKeySize]byte

var _ crypto.PrivKey = PrivKey{}

func GenPrivKey() PrivKey {
	seed := make([]byte, ed25519.SeedSize)
	_, err := io.ReadFull(crypto.CReader(), seed)
	if err != nil {
		panic(err)
	}

	privKeyED25519 := ed25519.NewKeyFromSeed(seed)
	var privKey PrivKey
	copy(privKey[:], privKeyED25519)
	return privKey
}

func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	signatureBytes := ed25519.Sign(privKey[:], msg)
	return signatureBytes, nil
}

func (privKey PrivKey) PubKey() crypto.PubKey {
	privKeyED25519 := ed25519.PrivateKey(privKey[:])
	pubKeyED25519 := privKeyED25519.Public().(ed25519.PublicKey)
	var pubKey PubKey
	copy(pubKey[:], pubKeyED25519)
	return pubKey
}

func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherPrivKey, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherPrivKey[:]) == 1
	} else {
		return false
	}
}

type PubKey [ed25519.PublicKeySize]byte

var _ crypto.PubKey = PubKey{}

func (pubKey PubKey) Verify(msg []byte, sig []byte) bool {
	if len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pubKey[:], msg, sig)
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherPubKey, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherPubKey[:])
	} else {
		return false
	}
}
