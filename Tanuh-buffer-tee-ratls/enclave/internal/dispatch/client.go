package dispatch

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

// VerifiedSession is returned after successful RA-TLS verification.
type VerifiedSession struct {
	ContainerImageDigest string
	HWModel              string
	Client               *http.Client
}

// Connect establishes an RA-TLS-verified connection to a Processing TEE.
//
// Flow: dial TLS 1.3 → extract EKM → call /ratls/connect → verify OIDC token
// → check eat_nonce == base64url(sha256(EKM)) → return VerifiedSession.
//
// addr: "host:port"
func Connect(ctx context.Context, addr string, opts *VerificationOptions) (*VerifiedSession, error) {
	if opts == nil {
		return nil, fmt.Errorf("dispatch/client: opts required")
	}

	leeway := opts.TokenLeeway
	if leeway == 0 {
		leeway = 30 * time.Second
	}

	// InsecureSkipVerify is intentional — TLS cert CA is irrelevant because
	// RA-TLS provides authentication via attestation + EKM channel binding.
	tlsCfg := &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		MinVersion:         tls.VersionTLS13,
	}

	dialer := &tls.Dialer{Config: tlsCfg}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dispatch/client: TLS dial %s: %w", addr, err)
	}
	tlsConn := rawConn.(*tls.Conn)
	state := tlsConn.ConnectionState()

	ekm, err := ExtractEKM(&state)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: extract EKM: %w", err)
	}
	expectedNonce := EKMNonce(ekm)
	log.Printf("dispatch/client: EKM nonce = %s", expectedNonce)

	// Reuse the exact TLS connection — EKM is session-specific.
	httpClient := newPinnedClient(tlsConn)
	connectURL := "https://" + addr + ConnectPath

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, connectURL, nil)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: build connect request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: GET %s: %w", ConnectPath, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: connect endpoint returned %d", resp.StatusCode)
	}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: read bundle: %w", err)
	}

	var bundle AttestationBundle
	if err := json.Unmarshal(bodyBytes, &bundle); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: parse bundle: %w", err)
	}

	oidcClaims, err := VerifyOIDCToken(bundle.OIDCToken, opts.Audience, leeway)
	if err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: OIDC verification failed: %w", err)
	}

	// Verify OIDC token claims — iss, aud, exp, hwmodel, image_digest, swname.

	if oidcClaims.EatNonce != expectedNonce {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: OIDC eat_nonce mismatch — relay attack detected")
	}

	if !strings.HasPrefix(oidcClaims.HWModel, TDXHWModelPrefix) &&
		!strings.HasPrefix(oidcClaims.HWModel, SEVHWModelPrefix) {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: hwmodel %q is not TDX or SEV", oidcClaims.HWModel)
	}

	if oidcClaims.SwName != CSSwName {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: swname %q != %q", oidcClaims.SwName, CSSwName)
	}

	if oidcClaims.Audience != "" && oidcClaims.Audience != opts.Audience {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: audience mismatch: got %q want %q",
			oidcClaims.Audience, opts.Audience)
	}

	if oidcClaims.ImageDigest != opts.ExpectedImageDigest {
		tlsConn.Close()
		return nil, fmt.Errorf("dispatch/client: image digest mismatch: got %q want %q",
			oidcClaims.ImageDigest, opts.ExpectedImageDigest)
	}

	// EKM cross-check: eat_nonce == base64url(sha256(ekm)). The Buffer TEE
	// independently derives expectedNonce from the same TLS session's EKM; the
	// equality check above proves the token is bound to THIS session per the
	// RA-TLS spec — both sides computed the same sha256(EKM).
	log.Printf("dispatch/client: EKM cross-check passed — eat_nonce == base64url(sha256(EKM)) ✓")

	log.Printf("dispatch/client: RA-TLS verified — hwmodel=%s digest=%s",
		oidcClaims.HWModel, oidcClaims.ImageDigest)

	return &VerifiedSession{
		ContainerImageDigest: oidcClaims.ImageDigest,
		HWModel:              oidcClaims.HWModel,
		Client:               httpClient,
	}, nil
}

// newPinnedClient returns an *http.Client that reuses the existing tlsConn,
// ensuring all requests use the same TLS session whose EKM was verified.
func newPinnedClient(tlsConn *tls.Conn) *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialTLSContext: func(_ context.Context, _, _ string) (net.Conn, error) {
				return tlsConn, nil
			},
		},
	}
}

// Base64DecodeURLNoPad decodes a base64url no-padding string. Exported for testing.
func Base64DecodeURLNoPad(s string) ([]byte, error) {
	return base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(s)
}
