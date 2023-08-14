package sm2

import (
	"crypto/rand"
	"errors"
	"math/big"
)

type Signature struct {
	R *big.Int
	S *big.Int
}

func (sig *Signature) Verify(hash []byte, pubKey *PublicKey) bool {
	return sm2Verify(pubKey, hash, sig.R, sig.S)
}

func sm2Sign(privateKey *PrivateKey, hash []byte) (*Signature, error) {
	var r, s *big.Int
	var err error

	c := privateKey.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errors.New("zero parameter")
	}

	e := new(big.Int).SetBytes(hash)
	var k *big.Int
	for {
		for {
			k, err = randFieldElement(c, rand.Reader)
			if err != nil {
				return nil, err
			}
			r, _ = privateKey.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		rD := new(big.Int).Mul(privateKey.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(privateKey.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return &Signature{R: r, S: s}, nil
}

func sm2Verify(pub *PublicKey, hash []byte, r, s *big.Int) bool {
	c := pub.Curve
	N := c.Params().N

	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false
	}
	if r.Cmp(N) >= 0 || s.Cmp(N) >= 0 {
		return false
	}

	t := new(big.Int).Add(r, s)
	t.Mod(t, N)
	if t.Sign() == 0 {
		return false
	}

	var x *big.Int
	x1, y1 := c.ScalarBaseMult(s.Bytes())
	x2, y2 := c.ScalarMult(pub.X, pub.Y, t.Bytes())
	x, _ = c.Add(x1, y1, x2, y2)

	e := new(big.Int).SetBytes(hash)
	x.Add(x, e)
	x.Mod(x, N)
	return x.Cmp(r)==0
}
