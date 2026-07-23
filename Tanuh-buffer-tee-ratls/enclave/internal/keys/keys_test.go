package keys

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestGenerate(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if k.BindingPriv == nil || k.BindingPub == nil || k.BindingSPKI == nil {
		t.Fatal("binding key fields must not be nil")
	}
	if k.HPKEPriv == nil || k.HPKEPub == nil {
		t.Fatal("HPKE key fields must not be nil")
	}
}

// Test 1: SPKI round-trip — parse back and compare X/Y coordinates.
func TestSPKIRoundTrip(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	pub, err := x509.ParsePKIXPublicKey(k.BindingSPKI)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey: %v", err)
	}
	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatal("parsed key is not *ecdsa.PublicKey")
	}
	if ecPub.X.Cmp(k.BindingPub.X) != 0 || ecPub.Y.Cmp(k.BindingPub.Y) != 0 {
		t.Fatal("X/Y coordinates do not match after SPKI round-trip")
	}
}

// Test 2: BindingFingerprintB64URL decodes to sha256(BindingSPKI).
func TestBindingFingerprint(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(k.BindingFingerprintB64URL())
	if err != nil {
		t.Fatalf("DecodeString: %v", err)
	}
	expected := sha256.Sum256(k.BindingSPKI)
	if !bytes.Equal(decoded, expected[:]) {
		t.Fatal("fingerprint does not match sha256(BindingSPKI)")
	}
}

// Test 3: SignNonce round-trip — verify with ecdsa.VerifyASN1.
func TestSignNonce(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	nonce := []byte("test-nonce-32-bytes-padded-xxxxx!")
	sig, err := k.SignNonce(nonce)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	digest := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(k.BindingPub, digest[:], sig) {
		t.Fatal("signature verification failed")
	}
}

// Test 4: Wrong nonce fails verification.
func TestSignNonceWrongNonce(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	nonce := []byte("original-nonce")
	sig, err := k.SignNonce(nonce)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}
	wrongDigest := sha256.Sum256([]byte("different-nonce"))
	if ecdsa.VerifyASN1(k.BindingPub, wrongDigest[:], sig) {
		t.Fatal("verification should have failed for wrong nonce")
	}
}

// Test 5: X25519 DH symmetry — X25519(priv1, pub2) == X25519(priv2, pub1).
func TestX25519DHSymmetry(t *testing.T) {
	k1, err := Generate()
	if err != nil {
		t.Fatalf("Generate k1: %v", err)
	}
	k2, err := Generate()
	if err != nil {
		t.Fatalf("Generate k2: %v", err)
	}

	ss1, err := k1.HPKEPriv.ECDH(k2.HPKEPub)
	if err != nil {
		t.Fatalf("ECDH(k1.priv, k2.pub): %v", err)
	}
	ss2, err := k2.HPKEPriv.ECDH(k1.HPKEPub)
	if err != nil {
		t.Fatalf("ECDH(k2.priv, k1.pub): %v", err)
	}
	if !bytes.Equal(ss1, ss2) {
		t.Fatal("DH shared secrets do not match")
	}
}
