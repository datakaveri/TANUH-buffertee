package server

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
)

// HandleAttest serves GET /v1/attest.
// The browser provides a 32-byte liveness nonce in X-RATLS-Nonce (base64url, no padding).
// The response is an AttestBundle JSON containing the OIDC token, public keys, and a
// signature over the nonce — all sufficient for the browser to verify the enclave identity.
func (s *Server) HandleAttest(w http.ResponseWriter, r *http.Request) {
	nonceB64u := r.Header.Get("X-RATLS-Nonce")
	if nonceB64u == "" {
		http.Error(w, "missing X-RATLS-Nonce header", http.StatusBadRequest)
		return
	}

	nonce, err := base64.RawURLEncoding.DecodeString(nonceB64u)
	if err != nil {
		http.Error(w, "bad X-RATLS-Nonce encoding", http.StatusBadRequest)
		return
	}
	if len(nonce) != 32 {
		http.Error(w, "X-RATLS-Nonce must be exactly 32 bytes", http.StatusBadRequest)
		return
	}

	bndl, err := s.builder.Build(nonce)
	if err != nil {
		http.Error(w, "failed to build attestation bundle", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(bndl)
}
