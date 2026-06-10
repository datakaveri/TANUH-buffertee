package hpke

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"fmt"
)

var (
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// ResponseSeal holds the HPKE encapsulated key and ciphertext for a sealed response.
type ResponseSeal struct {
	Enc        []byte
	Ciphertext []byte
}

// ContextInfo builds the HPKE info string binding both parties' public keys
// to the protocol name, preventing cross-protocol key reuse.
// Format: "ratls-cs-v1|" || sha256(enclavePub) || sha256(browserPub)  — 76 bytes total.
func ContextInfo(enclaveHPKEPub, browserHPKEPub []byte) []byte {
	prefix := []byte("ratls-cs-v1|")
	eHash := sha256.Sum256(enclaveHPKEPub)
	bHash := sha256.Sum256(browserHPKEPub)
	info := make([]byte, len(prefix)+32+32)
	copy(info, prefix)
	copy(info[len(prefix):], eHash[:])
	copy(info[len(prefix)+32:], bHash[:])
	return info
}

// OpenFromBrowser decrypts a browser-originated HPKE ciphertext.
// A fresh recipient context is constructed per call — never reused.
func OpenFromBrowser(enclavePriv *ecdh.PrivateKey, enc, info, aad, ct []byte) ([]byte, error) {
	privKey, err := hpke.NewDHKEMPrivateKey(enclavePriv)
	if err != nil {
		return nil, fmt.Errorf("wrap enclave private key: %w", err)
	}
	recipient, err := hpke.NewRecipient(enc, privKey, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("hpke NewRecipient: %w", err)
	}
	pt, err := recipient.Open(aad, ct)
	if err != nil {
		return nil, fmt.Errorf("hpke Open: %w", err)
	}
	return pt, nil
}

// SealToBrowser encrypts plaintext for the browser using its ephemeral X25519 public key.
// A fresh sender context is constructed per call — never reused.
func SealToBrowser(browserPubBytes, info, aad, plaintext []byte) (*ResponseSeal, error) {
	browserECDH, err := ecdh.X25519().NewPublicKey(browserPubBytes)
	if err != nil {
		return nil, fmt.Errorf("parse browser pub: %w", err)
	}
	browserPub, err := hpke.NewDHKEMPublicKey(browserECDH)
	if err != nil {
		return nil, fmt.Errorf("wrap browser public key: %w", err)
	}
	enc, sender, err := hpke.NewSender(browserPub, kdf, aead, info)
	if err != nil {
		return nil, fmt.Errorf("hpke NewSender: %w", err)
	}
	ct, err := sender.Seal(aad, plaintext)
	if err != nil {
		return nil, fmt.Errorf("hpke Seal: %w", err)
	}
	return &ResponseSeal{Enc: enc, Ciphertext: ct}, nil
}
