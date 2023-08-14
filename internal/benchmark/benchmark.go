package benchmark

import (
	"testing"

	"github.com/eybase/crypto"
)

func BenchmarkGenPrivKey(b *testing.B, genPrivKey func() crypto.PrivKey) {
	for i := 0; i < b.N; i++ {
		genPrivKey()
	}
}

func BenchmarkGenPrivKeyParallel(b *testing.B, genPrivKey func() crypto.PrivKey) {
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			genPrivKey()
		}
	})
}

func BenchmarkSign(b *testing.B, priv crypto.PrivKey) {
	message := []byte("Hello, world!")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = priv.Sign(message)
	}
}

func BenchmarkSignParallel(b *testing.B, priv crypto.PrivKey) {
	message := []byte("Hello, world!")
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = priv.Sign(message)
		}
	})
}

func BenchmarkVerify(b *testing.B, priv crypto.PrivKey) {
	pub := priv.PubKey()
	message := []byte("Hello, world!")
	signature, err := priv.Sign(message)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pub.Verify(message, signature)
	}
}

func BenchmarkVerifyParallel(b *testing.B, priv crypto.PrivKey) {
	pub := priv.PubKey()
	message := []byte("Hello, world!")
	signature, err := priv.Sign(message)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			pub.Verify(message, signature)
		}
	})
}
