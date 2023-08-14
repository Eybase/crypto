package secp256k1

import (
	"bytes"
	"crypto/subtle"
	"io"
	"math/big"

	"github.com/eybase/crypto"
)

var secp256k1halfN = new(big.Int).Rsh(S256().N, 1)

const PrivKeySize = 32

type PrivKey [PrivKeySize]byte

var _ crypto.PrivKey = PrivKey{}

func GenPrivKey() PrivKey {
	var privKeyBytes [PrivKeySize]byte
	d := new(big.Int)
	for {
		privKeyBytes = [PrivKeySize]byte{}
		_, err := io.ReadFull(crypto.CReader(), privKeyBytes[:])
		if err != nil {
			panic(err)
		}

		d.SetBytes(privKeyBytes[:])
		isValidFieldElement := 0 < d.Sign() && d.Cmp(S256().N) < 0
		if isValidFieldElement {
			break
		}
	}

	return PrivKey(privKeyBytes)
}

func (privKey PrivKey) Sign(msg []byte) ([]byte, error) {
	priv, _ := PrivKeyFromBytes(S256(), privKey[:])
	sig, err := priv.Sign(crypto.Sha256(msg))
	if err != nil {
		return nil, err
	}
	sigBytes := serializeSig(sig)
	return sigBytes, nil
}

func (privKey PrivKey) PubKey() crypto.PubKey {
	_, pubkeyObject := PrivKeyFromBytes(S256(), privKey[:])
	var pubKey PubKey
	copy(pubKey[:], pubkeyObject.SerializeCompressed())
	return pubKey
}

func (privKey PrivKey) Equals(other crypto.PrivKey) bool {
	if otherPrivKey, ok := other.(PrivKey); ok {
		return subtle.ConstantTimeCompare(privKey[:], otherPrivKey[:]) == 1
	} else {
		return false
	}
}

const PubKeySize = 33
const SignSize = 64

type PubKey [PubKeySize]byte

var _ crypto.PubKey = PubKey{}

func (pubKey PubKey) Verify(msg []byte, sig []byte) bool {
	if len(sig) != SignSize {
		return false
	}
	pub, err := ParsePubKey(pubKey[:], S256())
	if err != nil {
		return false
	}
	signature := signatureFromBytes(sig)
	if signature.S.Cmp(secp256k1halfN) > 0 {
		return false
	}
	return signature.Verify(crypto.Sha256(msg), pub)
}

func (pubKey PubKey) Equals(other crypto.PubKey) bool {
	if otherPubKey, ok := other.(PubKey); ok {
		return bytes.Equal(pubKey[:], otherPubKey[:])
	} else {
		return false
	}
}

func serializeSig(sig *Signature) []byte {
	rBytes := sig.R.Bytes()
	sBytes := sig.S.Bytes()
	sigBytes := make([]byte, 64)
	copy(sigBytes[32-len(rBytes):32], rBytes)
	copy(sigBytes[64-len(sBytes):64], sBytes)
	return sigBytes
}

func signatureFromBytes(sigStr []byte) *Signature {
	return &Signature{
		R: new(big.Int).SetBytes(sigStr[:32]),
		S: new(big.Int).SetBytes(sigStr[32:64]),
	}
}
