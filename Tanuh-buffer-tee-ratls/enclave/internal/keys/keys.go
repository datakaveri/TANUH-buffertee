package keys

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
)

// EnclaveKeys holds the binding (ECDSA P-256) and HPKE (X25519) keypairs
// generated fresh on startup. Never serialize or log this struct.
type EnclaveKeys struct {
	BindingPriv *ecdsa.PrivateKey
	BindingPub  *ecdsa.PublicKey
	BindingSPKI []byte          // DER SubjectPublicKeyInfo, cached
	HPKEPriv    *ecdh.PrivateKey // X25519, generated via ecdh.X25519().GenerateKey
	HPKEPub     *ecdh.PublicKey  // HPKEPriv.PublicKey()
}

// Generate creates a fresh set of enclave keys.
func Generate() (*EnclaveKeys, error) {
	bindingPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	spki, err := x509.MarshalPKIXPublicKey(&bindingPriv.PublicKey)
	if err != nil {
		return nil, err
	}

	hpkePriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	return &EnclaveKeys{
		BindingPriv: bindingPriv,
		BindingPub:  &bindingPriv.PublicKey,
		BindingSPKI: spki,
		HPKEPriv:    hpkePriv,
		HPKEPub:     hpkePriv.PublicKey(),
	}, nil
}

// HPKEPubBytes returns the raw 32-byte X25519 public key.
func (k *EnclaveKeys) HPKEPubBytes() []byte {
	return k.HPKEPub.Bytes()
}

// BindingFingerprintB64URL returns base64url(sha256(BindingSPKI)) with no padding.
// This value goes into eat_nonce[0].
func (k *EnclaveKeys) BindingFingerprintB64URL() string {
	h := sha256.Sum256(k.BindingSPKI)
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// HPKEPubB64URL returns base64url(HPKEPub) with no padding.
// This value goes into eat_nonce[1].
func (k *EnclaveKeys) HPKEPubB64URL() string {
	return base64.RawURLEncoding.EncodeToString(k.HPKEPub.Bytes())
}

// SignNonce signs sha256(nonce) with the binding private key and returns
// an ASN.1 DER-encoded ECDSA signature.
func (k *EnclaveKeys) SignNonce(nonce []byte) ([]byte, error) {
	digest := sha256.Sum256(nonce)
	return ecdsa.SignASN1(rand.Reader, k.BindingPriv, digest[:])
}
