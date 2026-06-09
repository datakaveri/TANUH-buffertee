package bundle

// AttestBundle is the JSON payload served from /v1/attest.
// All binary fields use standard base64 (with padding).
type AttestBundle struct {
    BundleVersion    string `json:"bundle_version"`    // "ratls-cs-v1"
    OIDCToken        string `json:"oidc_token"`         // Google-signed JWT
    BindingPubkeyB64 string `json:"binding_pubkey_b64"` // SPKI DER, std base64
    HPKEPubkeyB64    string `json:"hpke_pubkey_b64"`    // X25519 raw 32B, std base64
    NonceSigB64      string `json:"nonce_sig_b64"`      // ASN.1 DER ECDSA sig, std base64
    IssuedAt         int64  `json:"issued_at"`          // Unix timestamp
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

// EncryptedModelRequest is the payload sent to POST /v1/submit/model.
// The browser encrypts the model with a symmetric key received from KMS.
// The Buffer TEE does NOT decrypt this — it queues it for the Processing TEE.
// The Processing TEE fetches the decryption key from Secrets Manager after attestation.
type EncryptedModelRequest struct {
    JobID          string `json:"job_id"`          // unique job identifier
    WrappedKey     string `json:"wrapped_key"`     // RSA-OAEP wrapped symmetric key, std base64
    EncryptedModel string `json:"encrypted_model"` // Fernet/AES encrypted model bytes, std base64
    DatasetID      int    `json:"dataset_id"`      // which dataset to evaluate against (1, 2, or 3)
    SubmittedBy    string `json:"submitted_by"`    // user identifier
}

// JobQueuedResponse is returned after successfully queuing a job.
type JobQueuedResponse struct {
    JobID    string `json:"job_id"`
    Status   string `json:"status"`    // "queued"
    IssuedAt int64  `json:"issued_at"` // Unix timestamp
}
