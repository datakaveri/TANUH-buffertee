package attest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/datakaveri/tanuh-buffer-tee/internal/keys"
)

const (
	socketPath    = "/run/container_launcher/teeserver.sock"
	tokenEndpoint = "http://localhost/v1/token"
)

// NewUnixClient returns an HTTP client that dials the TEE server unix socket.
func NewUnixClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
}

// FetchOIDC requests a Google-signed OIDC token from the Confidential Space
// TEE launcher, embedding the key fingerprints as eat_nonce values.
// The caller must verify that eat_nonce matches the keys after this returns.
func FetchOIDC(ctx context.Context, k *keys.EnclaveKeys, audience string) (string, error) {
	return fetchOIDCWithClient(ctx, k, audience, NewUnixClient())
}

// fetchOIDCWithClient is the testable inner implementation that accepts an injected client.
func fetchOIDCWithClient(ctx context.Context, k *keys.EnclaveKeys, audience string, client *http.Client) (string, error) {
	reqBody := struct {
		Audience  string   `json:"audience"`
		Nonces    []string `json:"nonces"`
		TokenType string   `json:"token_type"`
	}{
		Audience:  audience,
		Nonces:    []string{k.BindingFingerprintB64URL(), k.HPKEPubB64URL()},
		TokenType: "OIDC",
	}

	bodyBytes, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint returned %d", resp.StatusCode)
	}

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	token := extractToken(raw)
	if !strings.HasPrefix(token, "eyJ") {
		return "", fmt.Errorf("response does not look like a JWT (got %q)", truncate(token, 64))
	}

	return token, nil
}

// extractToken handles both:
//   - raw JWT response body
//   - JSON envelope: {"oidc_token":"<jwt>"}
func extractToken(raw []byte) string {
	var envelope struct {
		OIDCToken string `json:"oidc_token"`
	}
	if err := json.Unmarshal(raw, &envelope); err == nil && envelope.OIDCToken != "" {
		return strings.TrimSpace(envelope.OIDCToken)
	}
	return strings.TrimSpace(string(raw))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
