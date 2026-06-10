package bundle

// AttestBundle is the JSON payload served from /v1/attest.
// All binary fields use standard base64 (with padding).
type AttestBundle struct {
	OIDCToken        string `json:"oidc_token"`          // Google-signed JWT
	BindingPubkeyB64 string `json:"binding_pubkey_b64"`  // SPKI DER, std base64
	HPKEPubkeyB64    string `json:"hpke_pubkey_b64"`     // X25519 raw 32B, std base64
	NonceSigB64      string `json:"nonce_sig_b64"`       // ASN.1 DER ECDSA sig, std base64
	IssuedAt         int64  `json:"issued_at"`           // Unix timestamp
}

// EncryptedRequest is the JSON body for /v1/submit from the browser.
// All binary fields use standard base64 (with padding).
type EncryptedRequest struct {
	Enc        string `json:"enc"`        // HPKE encapsulated key
	Ciphertext string `json:"ciphertext"` // HPKE ciphertext
	AAD        string `json:"aad"`        // additional authenticated data
}

// EncryptedResponse mirrors EncryptedRequest for the reply.
type EncryptedResponse = EncryptedRequest
