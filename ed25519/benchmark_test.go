package ed25519_test

import (
	"testing"

	"github.com/eybase/crypto"
	"github.com/eybase/crypto/ed25519"
	"github.com/eybase/crypto/internal/benchmark"
)

func BenchmarkGenPrivKey(b *testing.B) {
	wrapperGenPrivKey := func() crypto.PrivKey {
		return ed25519.GenPrivKey()
	}
	benchmark.BenchmarkGenPrivKey(b, wrapperGenPrivKey)
}

func BenchmarkGenPrivKeyParallel(b *testing.B) {
	wrapperGenPrivKey := func() crypto.PrivKey {
		return ed25519.GenPrivKey()
	}
	benchmark.BenchmarkGenPrivKeyParallel(b, wrapperGenPrivKey)
}

func BenchmarkSign(b *testing.B) {
	priv := ed25519.GenPrivKey()
	benchmark.BenchmarkSign(b, priv)
}

func BenchmarkSignParallel(b *testing.B) {
	priv := ed25519.GenPrivKey()
	benchmark.BenchmarkSignParallel(b, priv)
}

func BenchmarkVerify(b *testing.B) {
	priv := ed25519.GenPrivKey()
	benchmark.BenchmarkVerify(b, priv)
}

func BenchmarkVerifyParallel(b *testing.B) {
	priv := ed25519.GenPrivKey()
	benchmark.BenchmarkVerifyParallel(b, priv)
}
