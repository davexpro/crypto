package ed25519

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/bytedance/mockey"
	"github.com/smartystreets/goconvey/convey"
)

func TestSharedKeyByCurve25519(t *testing.T) {
	alicePri, bobPri := NewCurve25519Key(), NewCurve25519Key()
	mockey.PatchConvey("SharedKeyByCurve25519", t, func() {
		alicePub, err := DeriveCurve25519PubKey(alicePri)
		if err != nil {
			t.Errorf("func `DeriveCurve25519PubKey` failed, detail: %s", err)
		}
		bobPub, err := DeriveCurve25519PubKey(bobPri)
		if err != nil {
			t.Errorf("func `DeriveCurve25519PubKey` failed, detail: %s", err)
		}

		sharedKeyA, err := SharedKeyByCurve25519(alicePri, bobPub)
		if err != nil {
			t.Errorf("func `SharedKeyByCurve25519` failed, detail: %s", err)
		}
		sharedKeyB, err := SharedKeyByCurve25519(bobPri, alicePub)
		if err != nil {
			t.Errorf("func `SharedKeyByCurve25519` failed, detail: %s", err)
		}
		convey.So(sharedKeyA, convey.ShouldEqual, sharedKeyB)
	})
}

func TestSharedKeyByEd25519(t *testing.T) {
	bobPub, bobPri, _ := ed25519.GenerateKey(rand.Reader)
	alicePub, alicePri, _ := ed25519.GenerateKey(rand.Reader)
	mockey.PatchConvey("SharedKeyByEd25519", t, func() {
		sharedKeyA, err := SharedKeyByEd25519(alicePri, bobPub)
		if err != nil {
			t.Errorf("func `SharedKeyByEd25519` failed, detail: %s", err)
		}
		sharedKeyB, err := SharedKeyByEd25519(bobPri, alicePub)
		if err != nil {
			t.Errorf("func `SharedKeyByEd25519` failed, detail: %s", err)
		}
		convey.So(sharedKeyA, convey.ShouldEqual, sharedKeyB)
	})
}
