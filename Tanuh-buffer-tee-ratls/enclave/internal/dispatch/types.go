// Package dispatch implements the Buffer TEE's RA-TLS client side: it
// connects to a Processing TEE (gpu-cs/cpu-cs), verifies the server's
// Confidential Space attestation (OIDC token + EKM channel binding), and
// delivers the secure job payload over the verified session.
//
// This package is the client counterpart of the Processing TEE's RA-TLS
// server. It has a single external dependency (golang-jwt, for attestation
// token verification); the enclave's crypto packages (hpke, keys, bundle,
// attest) stay dependency-free.
package dispatch

import "time"

const (
	EKMLabel    = "EXPORTER-ratls/v1"
	EKMLength   = 32
	ConnectPath = "/ratls/connect"
	GCPCSIssuer = "https://confidentialcomputing.googleapis.com"
	// GCPCSJwksURL is the stable JWKS URI for GCP Confidential Space OIDC tokens.
	// Hardcoded to avoid fetching .well-known/openid-configuration, which may be
	// blocked by VPC Service Controls (restricted.googleapis.com DNS routing).
	GCPCSJwksURL     = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com"
	TDXHWModelPrefix = "GCP_INTEL_TDX"
	SEVHWModelPrefix = "GCP_AMD_SEV"
	CSSwName         = "CONFIDENTIAL_SPACE"
)

// AttestationBundle is what the Processing TEE returns over /ratls/connect.
//
// Flow on the server (Processing TEE):
//  1. TLS handshake already complete
//  2. ekm = ExportKeyingMaterial("EXPORTER-ratls/v1", nil, 32)
//  3. nonce = base64url(sha256(ekm))
//  4. OIDC token: POST localhost/v1/token {audience, nonces:[nonce], token_type:"OIDC"}
//  5. Return this bundle: { oidc_token }
//
// Verification on the client (Buffer TEE):
//  1. ekm = ExportKeyingMaterial("EXPORTER-ratls/v1", nil, 32)  ← same session
//  2. Verify OIDC token via Google JWKS: iss, aud, exp, hwmodel, image_digest, swname
//  3. Cross-check: eat_nonce == base64url(sha256(ekm))  ← EKM channel binding
type AttestationBundle struct {
	OIDCToken string `json:"oidc_token"`
}

// VerificationOptions holds pinned values the Buffer TEE uses during verification.
type VerificationOptions struct {
	Audience            string
	ExpectedImageDigest string
	TokenLeeway         time.Duration
}
