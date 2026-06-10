package ratls

import "time"

const (
	EKMLabel              = "EXPORTER-ratls/v1"
	EKMLength             = 32
	ConnectPath           = "/ratls/connect"
	// MetadataTokenEndpoint is served by the CS launcher via Unix socket.
	// The socket is mounted at /run/container_launcher/teeserver.sock inside the container.
	MetadataTokenEndpoint    = "http://localhost/v1/token"
	MetadataTokenSocketPath  = "/run/container_launcher/teeserver.sock"
	GCPCSIssuer           = "https://confidentialcomputing.googleapis.com"
	WellKnownPath         = "/.well-known/openid-configuration"
	TDXHWModelPrefix      = "GCP_INTEL_TDX"
	SEVHWModelPrefix      = "GCP_AMD_SEV"
	CSSwName              = "CONFIDENTIAL_SPACE"
)

// AttestationBundle is what GPU CS returns to Buffer TEE over /ratls/connect.
//
// Flow on the server (GPU CS):
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
	OIDCToken      string          `json:"oidc_token"`
	TestModeClaims *TestModeClaims `json:"test_mode_claims,omitempty"`
}

// TestModeClaims is returned only when RATLS_TEST_MODE=true for local validation.
type TestModeClaims struct {
	EatNonce    string `json:"eat_nonce"`
	HWModel     string `json:"hwmodel"`
	ImageDigest string `json:"image_digest"`
	SwName      string `json:"swname"`
	Issuer      string `json:"iss"`
	Audience    string `json:"aud"`
}

// VerificationOptions holds pinned values Buffer TEE uses during verification.
type VerificationOptions struct {
	Audience            string
	ExpectedImageDigest string
	TokenLeeway         time.Duration
}

// TokenRequestBody is the JSON body for POST to MetadataTokenEndpoint.
type TokenRequestBody struct {
	Audience  string   `json:"audience"`
	Nonces    []string `json:"nonces"`
	TokenType string   `json:"token_type"`
}
