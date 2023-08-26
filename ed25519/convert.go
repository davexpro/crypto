package ed25519

import (
	"crypto/ed25519"
	"crypto/sha512"

	"filippo.io/edwards25519"
)

// functions below adapted from:
// https://github.com/cryptoscope/secretstream/blob/master/secrethandshake/internal/extra25519/convert.go

// PrivateKeyToCurve25519 converts an ed25519 private key into a corresponding
// curve25519 private key such that the resulting curve25519 public key will
// equal the result from PublicKeyToCurve25519.
func PrivateKeyToCurve25519(privateKey ed25519.PrivateKey) []byte {
	h := sha512.New()
	h.Write(privateKey[:32])
	digest := h.Sum(nil)

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	return digest[:32]
	//copy(curve25519Private[:], digest)
}

// PublicKeyToCurve25519 converts an Ed25519 public key into the curve25519
// public key that would be generated from the same private key.
func PublicKeyToCurve25519(edBytes ed25519.PublicKey) ([]byte, error) {
	edPoint, err := (&edwards25519.Point{}).SetBytes(edBytes)
	if err != nil {
		return nil, err
	}
	return edPoint.BytesMontgomery(), nil
}
