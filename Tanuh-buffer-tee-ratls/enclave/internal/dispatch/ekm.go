package dispatch

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"fmt"
)

// ExtractEKM derives 32 bytes of Exported Keying Material from the TLS session.
// Both sides of the same TLS 1.3 session derive the identical value.
// Must be called after TLS handshake is complete.
func ExtractEKM(state *tls.ConnectionState) ([]byte, error) {
	if state == nil {
		return nil, fmt.Errorf("dispatch/ekm: TLS state is nil — handshake not complete")
	}
	ekm, err := state.ExportKeyingMaterial(EKMLabel, nil, EKMLength)
	if err != nil {
		return nil, fmt.Errorf("dispatch/ekm: ExportKeyingMaterial: %w", err)
	}
	return ekm, nil
}

// EKMNonce returns base64url(sha256(ekm)) — the value that goes into
// the OIDC token's eat_nonce. 43 characters, within GCP's nonce size limits.
func EKMNonce(ekm []byte) string {
	hash := sha256.Sum256(ekm)
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:])
}
