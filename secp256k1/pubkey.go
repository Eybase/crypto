package secp256k1

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"math/big"
)

const (
	PubKeyBytesLenCompressed   = 33
	PubKeyBytesLenUncompressed = 65
	PubKeyBytesLenHybrid       = 65
)

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

func decompressPoint(curve *KoblitzCurve, bigX *big.Int, ybit bool) (*big.Int, error) {
	var x fieldVal
	x.SetByteSlice(bigX.Bytes())

	var x3 fieldVal
	x3.SquareVal(&x).Mul(&x)
	x3.Add(curve.fieldB).Normalize()

	var y fieldVal
	y.SqrtVal(&x3).Normalize()
	if ybit != y.IsOdd() {
		y.Negate(1).Normalize()
	}

	var y2 fieldVal
	y2.SquareVal(&y).Normalize()
	if !y2.Equals(&x3) {
		return nil, fmt.Errorf("invalid square root")
	}

	if ybit != y.IsOdd() {
		return nil, fmt.Errorf("ybit doesn't match oddness")
	}

	return new(big.Int).SetBytes(y.Bytes()[:]), nil
}

const (
	pubkeyCompressed   byte = 0x2
	pubkeyUncompressed byte = 0x4
	pubkeyHybrid       byte = 0x6
)

func IsCompressedPubKey(pubKey []byte) bool {
	return len(pubKey) == PubKeyBytesLenCompressed &&
		(pubKey[0]&^byte(0x1) == pubkeyCompressed)
}

func ParsePubKey(pubKeyStr []byte, curve *KoblitzCurve) (key *PublicKey, err error) {
	pubkey := PublicKey{}
	pubkey.Curve = curve

	if len(pubKeyStr) == 0 {
		return nil, errors.New("pubkey string is empty")
	}

	format := pubKeyStr[0]
	ybit := (format & 0x1) == 0x1
	format &= ^byte(0x1)

	switch len(pubKeyStr) {
	case PubKeyBytesLenUncompressed:
		if format != pubkeyUncompressed && format != pubkeyHybrid {
			return nil, fmt.Errorf("invalid magic in pubkey str: "+
				"%d", pubKeyStr[0])
		}

		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y = new(big.Int).SetBytes(pubKeyStr[33:])
		if format == pubkeyHybrid && ybit != isOdd(pubkey.Y) {
			return nil, fmt.Errorf("ybit doesn't match oddness")
		}

		if pubkey.X.Cmp(pubkey.Curve.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey X parameter is >= to P")
		}
		if pubkey.Y.Cmp(pubkey.Curve.Params().P) >= 0 {
			return nil, fmt.Errorf("pubkey Y parameter is >= to P")
		}
		if !pubkey.Curve.IsOnCurve(pubkey.X, pubkey.Y) {
			return nil, fmt.Errorf("pubkey isn't on secp256k1 curve")
		}

	case PubKeyBytesLenCompressed:
		if format != pubkeyCompressed {
			return nil, fmt.Errorf("invalid magic in compressed "+
				"pubkey string: %d", pubKeyStr[0])
		}
		pubkey.X = new(big.Int).SetBytes(pubKeyStr[1:33])
		pubkey.Y, err = decompressPoint(curve, pubkey.X, ybit)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("invalid pub key length %d",
			len(pubKeyStr))
	}

	return &pubkey, nil
}

type PublicKey ecdsa.PublicKey

func (p *PublicKey) ToECDSA() *ecdsa.PublicKey {
	return (*ecdsa.PublicKey)(p)
}

func (p *PublicKey) SerializeUncompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenUncompressed)
	b = append(b, pubkeyUncompressed)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

func (p *PublicKey) SerializeCompressed() []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubkeyCompressed
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(32, b, p.X.Bytes())
}

func (p *PublicKey) SerializeHybrid() []byte {
	b := make([]byte, 0, PubKeyBytesLenHybrid)
	format := pubkeyHybrid
	if isOdd(p.Y) {
		format |= 0x1
	}
	b = append(b, format)
	b = paddedAppend(32, b, p.X.Bytes())
	return paddedAppend(32, b, p.Y.Bytes())
}

func (p *PublicKey) IsEqual(otherPubKey *PublicKey) bool {
	return p.X.Cmp(otherPubKey.X) == 0 &&
		p.Y.Cmp(otherPubKey.Y) == 0
}

func paddedAppend(size uint, dst, src []byte) []byte {
	for i := 0; i < int(size)-len(src); i++ {
		dst = append(dst, 0)
	}
	return append(dst, src...)
}
