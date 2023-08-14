package sm2

import (
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
)

const PrivKeyBytesLen = 32

var one = new(big.Int).SetInt64(1)

type PrivateKey struct {
	PublicKey
	D *big.Int
}

func GenerateKey() (*PrivateKey, error) {
	c := P256Sm2()
	k, err := randFieldElement(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	priv := new(PrivateKey)
	priv.PublicKey.Curve = c
	priv.D = k
	priv.PublicKey.X, priv.PublicKey.Y = c.ScalarBaseMult(k.Bytes())
	return priv, nil
}

func randFieldElement(c elliptic.Curve, rand io.Reader) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(rand, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func PrivKeyFromBytes(curve elliptic.Curve, pk []byte) (*PrivateKey, *PublicKey) {
	x, y := curve.ScalarBaseMult(pk)

	priv := &PrivateKey{
		PublicKey: PublicKey{
			Curve: curve,
			X:     x,
			Y:     y,
		},
		D: new(big.Int).SetBytes(pk),
	}

	return (*PrivateKey)(priv), (*PublicKey)(&priv.PublicKey)
}

func (p *PrivateKey) GetRawBytes() []byte {
	dBytes := p.D.Bytes()
	dl := len(dBytes)
	if dl > PrivKeyBytesLen {
		raw := make([]byte, PrivKeyBytesLen)
		copy(raw, dBytes[dl-PrivKeyBytesLen:])
		return raw
	} else if dl < PrivKeyBytesLen {
		raw := make([]byte, PrivKeyBytesLen)
		copy(raw[PrivKeyBytesLen-dl:], dBytes)
		return raw
	} else {
		return dBytes
	}
}

func (p *PrivateKey) Sign(hash []byte) (*Signature, error) {
	return sm2Sign(p, hash)
}
