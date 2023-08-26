package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"

	"golang.org/x/crypto/curve25519"
)

// NewCurve25519Key generate rand [32]byte
func NewCurve25519Key() (key []byte) {
	randomBytes := make([]byte, 32)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return
	}
	return randomBytes
}

// DeriveCurve25519PubKey .
func DeriveCurve25519PubKey(priKey []byte) ([]byte, error) {
	return curve25519.X25519(priKey, curve25519.Basepoint)
}

// SharedKeyByEd25519 generate shared key based on `ed25519` keys
func SharedKeyByEd25519(priKey ed25519.PrivateKey, pubKey ed25519.PublicKey) ([]byte, error) {
	priX := PrivateKeyToCurve25519(priKey)
	pubX, err := PublicKeyToCurve25519(pubKey)
	if err != nil {
		return nil, err
	}

	return SharedKeyByCurve25519(priX, pubX)
}

// SharedKeyByCurve25519 generate shared key based on `curve25519` keys
func SharedKeyByCurve25519(priKey, pubKey []byte) ([]byte, error) {
	return curve25519.X25519(priKey, pubKey)
}
