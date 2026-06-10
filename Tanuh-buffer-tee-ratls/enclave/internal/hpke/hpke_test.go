package hpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"testing"
)

// generateTestKeypair returns a fresh X25519 keypair for testing.
func generateTestKeypair(t *testing.T) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return priv
}

// Test 1: Browser→Enclave round-trip.
func TestOpenFromBrowserRoundTrip(t *testing.T) {
	enclavePriv := generateTestKeypair(t)
	enclavePubBytes := enclavePriv.PublicKey().Bytes()

	browserPriv := generateTestKeypair(t)
	browserPubBytes := browserPriv.PublicKey().Bytes()

	info := ContextInfo(enclavePubBytes, browserPubBytes)
	aad := []byte("test-aad")
	plaintext := []byte("hello from browser")

	// Browser seals to enclave.
	seal, err := SealToBrowser(enclavePubBytes, info, aad, plaintext)
	if err != nil {
		t.Fatalf("SealToBrowser: %v", err)
	}

	// Enclave opens.
	got, err := OpenFromBrowser(enclavePriv, seal.Enc, info, aad, seal.Ciphertext)
	if err != nil {
		t.Fatalf("OpenFromBrowser: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", got, plaintext)
	}
}

// Test 2: Enclave→Browser round-trip.
func TestSealToBrowserRoundTrip(t *testing.T) {
	enclavePriv := generateTestKeypair(t)
	enclavePubBytes := enclavePriv.PublicKey().Bytes()

	browserPriv := generateTestKeypair(t)
	browserPubBytes := browserPriv.PublicKey().Bytes()

	info := ContextInfo(enclavePubBytes, browserPubBytes)
	aad := []byte("response-aad")
	plaintext := []byte("hello from enclave")

	seal, err := SealToBrowser(browserPubBytes, info, aad, plaintext)
	if err != nil {
		t.Fatalf("SealToBrowser: %v", err)
	}

	// Browser opens using its own private key.
	pt, err := OpenFromBrowser(browserPriv, seal.Enc, info, aad, seal.Ciphertext)
	if err != nil {
		t.Fatalf("OpenFromBrowser: %v", err)
	}
	if !bytes.Equal(pt, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", pt, plaintext)
	}
}

// Test 3: Wrong info string → decryption error.
func TestWrongInfoFails(t *testing.T) {
	enclavePriv := generateTestKeypair(t)
	enclavePubBytes := enclavePriv.PublicKey().Bytes()

	browserPriv := generateTestKeypair(t)
	browserPubBytes := browserPriv.PublicKey().Bytes()

	correctInfo := ContextInfo(enclavePubBytes, browserPubBytes)
	wrongInfo := append([]byte(nil), correctInfo...)
	wrongInfo[0] ^= 0xFF // flip a byte

	aad := []byte("aad")
	plaintext := []byte("secret")

	seal, err := SealToBrowser(enclavePubBytes, correctInfo, aad, plaintext)
	if err != nil {
		t.Fatalf("SealToBrowser: %v", err)
	}

	_, err = OpenFromBrowser(enclavePriv, seal.Enc, wrongInfo, aad, seal.Ciphertext)
	if err == nil {
		t.Fatal("expected error with wrong info, got nil")
	}
}

// Test 4: Tampered ciphertext → decryption error.
func TestTamperedCiphertextFails(t *testing.T) {
	enclavePriv := generateTestKeypair(t)
	enclavePubBytes := enclavePriv.PublicKey().Bytes()

	browserPubBytes := generateTestKeypair(t).PublicKey().Bytes()

	info := ContextInfo(enclavePubBytes, browserPubBytes)
	aad := []byte("aad")
	plaintext := []byte("secret")

	seal, err := SealToBrowser(enclavePubBytes, info, aad, plaintext)
	if err != nil {
		t.Fatalf("SealToBrowser: %v", err)
	}

	// Tamper with the ciphertext.
	tampered := append([]byte(nil), seal.Ciphertext...)
	tampered[len(tampered)-1] ^= 0xFF

	_, err = OpenFromBrowser(enclavePriv, seal.Enc, info, aad, tampered)
	if err == nil {
		t.Fatal("expected error with tampered ciphertext, got nil")
	}
}
