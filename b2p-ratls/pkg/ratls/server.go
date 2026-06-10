package ratls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"time"
)

// Server holds GPU CS server-side state.
type Server struct {
	audience string
	tlsCert  tls.Certificate
}

// NewServer initialises the GPU CS RATLS server.
func NewServer(audience string) (*Server, error) {
	cert, err := generateSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("ratls/server: generate TLS cert: %w", err)
	}
	return &Server{audience: audience, tlsCert: cert}, nil
}

// TLSConfig returns the tls.Config for the GPU CS HTTPS server.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{s.tlsCert},
		MinVersion:   tls.VersionTLS13,
	}
}

// ConnectHandler returns the http.Handler for ConnectPath ("/ratls/connect").
func (s *Server) ConnectHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "ratls: requires TLS", http.StatusBadRequest)
			return
		}

		ekm, err := ExtractEKM(r.TLS)
		if err != nil {
			log.Printf("ratls/server: EKM extraction failed: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}

		nonce := EKMNonce(ekm)
		log.Printf("ratls/server: EKM nonce = %s", nonce)

		var oidcToken string
		var testModeClaims *TestModeClaims
		if os.Getenv("RATLS_TEST_MODE") == "true" {
			oidcToken = "TEST_MODE_TOKEN_NOT_VALID"
			testModeClaims = &TestModeClaims{
				EatNonce:    nonce,
				HWModel:     getEnv("RATLS_TEST_HW_MODEL", "GCP_AMD_SEV_LOCAL_TEST"),
				ImageDigest: getEnv("RATLS_TEST_IMAGE_DIGEST", "local-test-image-digest"),
				SwName:      CSSwName,
				Issuer:      "local-test-ratls",
				Audience:    s.audience,
			}
			log.Printf("ratls/server: TEST MODE enabled for audience=%s", s.audience)
		} else {
			oidcToken, err = requestOIDCToken(r.Context(), s.audience, nonce)
			if err != nil {
				log.Printf("ratls/server: request OIDC token: %v", err)
				http.Error(w, "attestation error", http.StatusInternalServerError)
				return
			}
		}

		bundle := AttestationBundle{
			OIDCToken:      oidcToken,
			TestModeClaims: testModeClaims,
		}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(bundle); err != nil {
			log.Printf("ratls/server: encode bundle: %v", err)
		}
		log.Printf("ratls/server: RATLS bundle sent to %s", r.RemoteAddr)
	})
}

func requestOIDCToken(ctx context.Context, audience, nonce string) (string, error) {
	body := TokenRequestBody{
		Audience:  audience,
		Nonces:    []string{nonce},
		TokenType: "OIDC",
	}
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return "", fmt.Errorf("marshal token request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, MetadataTokenEndpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	socketClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", MetadataTokenSocketPath)
			},
		},
	}

	resp, err := socketClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("POST %s (via unix socket): %w", MetadataTokenEndpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("token endpoint: status %d", resp.StatusCode)
	}

	var buf bytes.Buffer
	if _, err := buf.ReadFrom(resp.Body); err != nil {
		return "", fmt.Errorf("read token response: %w", err)
	}

	token := buf.String()
	if token == "" {
		return "", fmt.Errorf("token endpoint returned empty response")
	}
	return token, nil
}

func generateSelfSignedCert() (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{Organization: []string{"GPU-CS-RATLS"}},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
