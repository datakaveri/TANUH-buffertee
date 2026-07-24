package server

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// AuthConfig configures optional Keycloak JWT validation.
// When JWKSUrl is empty auth is disabled and all requests pass through.
type AuthConfig struct {
	JWKSUrl string // e.g. "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"
	Issuer  string // expected "iss" claim, e.g. "https://keycloak.example.com/realms/myrealm"
}

type jwksKey struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwksDocument struct {
	Keys []jwksKey `json:"keys"`
}

// jwksCache holds parsed RSA public keys and a fetch timestamp.
type jwksCache struct {
	mu        sync.RWMutex
	keys      map[string]*rsa.PublicKey
	fetchedAt time.Time
}

var globalJWKSCache = &jwksCache{}

const jwksCacheTTL = time.Hour

// getPublicKey returns the RSA public key for kid, fetching the JWKS when
// the cache is empty or stale. On a kid miss it re-fetches once (handles
// Keycloak key rotation).
func getPublicKey(jwksURL, kid string) (*rsa.PublicKey, error) {
	// fast path — read lock
	globalJWKSCache.mu.RLock()
	fresh := time.Since(globalJWKSCache.fetchedAt) < jwksCacheTTL
	if fresh {
		k, ok := globalJWKSCache.keys[kid]
		globalJWKSCache.mu.RUnlock()
		if ok {
			return k, nil
		}
	} else {
		globalJWKSCache.mu.RUnlock()
	}

	// slow path — write lock, re-check, then fetch
	globalJWKSCache.mu.Lock()
	defer globalJWKSCache.mu.Unlock()

	if time.Since(globalJWKSCache.fetchedAt) < jwksCacheTTL {
		if k, ok := globalJWKSCache.keys[kid]; ok {
			return k, nil
		}
	}

	keys, err := fetchJWKS(jwksURL)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	globalJWKSCache.keys = keys
	globalJWKSCache.fetchedAt = time.Now()

	k, ok := keys[kid]
	if !ok {
		return nil, fmt.Errorf("key id %q not found in JWKS", kid)
	}
	return k, nil
}

// fetchJWKS downloads the JWKS document and returns a map of kid → *rsa.PublicKey.
func fetchJWKS(jwksURL string) (map[string]*rsa.PublicKey, error) {
	resp, err := http.Get(jwksURL) //nolint:noctx
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	var doc jwksDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w", err)
	}

	result := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		pub, err := rsaPubKeyFromJWK(k)
		if err != nil {
			continue // skip malformed keys
		}
		result[k.Kid] = pub
	}
	return result, nil
}

// rsaPubKeyFromJWK builds an *rsa.PublicKey from base64url-encoded n and e fields.
func rsaPubKeyFromJWK(k jwksKey) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = (e << 8) | int(b)
	}
	if e == 0 {
		return nil, fmt.Errorf("invalid public exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// validateKeycloakJWT validates an RS256 JWT: signature, expiry, and issuer.
func validateKeycloakJWT(tokenStr, jwksURL, issuer string) error {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return fmt.Errorf("malformed JWT")
	}

	// parse header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return fmt.Errorf("decode JWT header: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return fmt.Errorf("parse JWT header: %w", err)
	}
	if header.Alg != "RS256" {
		return fmt.Errorf("unsupported algorithm %q", header.Alg)
	}
	if header.Kid == "" {
		return fmt.Errorf("missing kid in JWT header")
	}

	// verify signature
	pubKey, err := getPublicKey(jwksURL, header.Kid)
	if err != nil {
		return fmt.Errorf("get signing key: %w", err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return fmt.Errorf("decode JWT signature: %w", err)
	}
	if err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest[:], sig); err != nil {
		return fmt.Errorf("invalid JWT signature")
	}

	// verify claims
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fmt.Errorf("decode JWT payload: %w", err)
	}
	var payload struct {
		Exp int64  `json:"exp"`
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return fmt.Errorf("parse JWT payload: %w", err)
	}
	if payload.Exp == 0 || time.Now().Unix() > payload.Exp {
		return fmt.Errorf("JWT expired")
	}
	if payload.Iss != issuer {
		return fmt.Errorf("JWT issuer mismatch")
	}
	return nil
}

// jwtRealmRoles decodes the payload of an already-validated JWT and returns
// the roles listed under realm_access.roles (Keycloak standard claim).
// The signature is NOT re-verified — call only after keycloakAuthMiddleware.
func jwtRealmRoles(tokenStr string) []string {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil
	}
	var claims struct {
		RealmAccess struct {
			Roles []string `json:"roles"`
		} `json:"realm_access"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil
	}
	return claims.RealmAccess.Roles
}

// requireRole wraps a handler and returns 403 if the caller's JWT does not
// carry the given Keycloak realm role. Must sit inside keycloakAuthMiddleware
// so the token is already signature-verified.
func requireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		for _, realmRole := range jwtRealmRoles(token) {
			if realmRole == role {
				next.ServeHTTP(w, req)
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
	})
}

// isCompletionCallback matches POST /v1/jobs/{id}/complete — the Processing
// TEE's machine-to-machine callback, which authenticates with a CS
// attestation token instead of a Keycloak user JWT (see HandleComplete).
func isCompletionCallback(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		strings.HasPrefix(r.URL.Path, "/v1/jobs/") &&
		strings.HasSuffix(r.URL.Path, "/complete")
}

// keycloakAuthMiddleware enforces Keycloak JWT auth on all routes except
// OPTIONS (CORS preflight), /healthz, and the completion callback (which
// carries its own attestation-based auth).
func keycloakAuthMiddleware(jwksURL, issuer string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions || r.URL.Path == "/healthz" || isCompletionCallback(r) {
			next.ServeHTTP(w, r)
			return
		}
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"missing Authorization header"}`, http.StatusUnauthorized)
			return
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		if err := validateKeycloakJWT(token, jwksURL, issuer); err != nil {
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
