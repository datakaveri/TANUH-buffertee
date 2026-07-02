package ratls

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type jwksFile struct {
	Keys []jwk `json:"keys"`
}

type jwk struct {
	N   string `json:"n"`
	E   string `json:"e"`
	Kid string `json:"kid"`
}

type wellKnown struct {
	JwksURI string `json:"jwks_uri"`
}

// OIDCClaims holds the verified claims from the attestation token.
type OIDCClaims struct {
	EatNonce    string
	HWModel     string
	ImageDigest string
	SwName      string
	Issuer      string
	Audience    string
}

// VerifyOIDCToken verifies a GCP Confidential Space OIDC attestation token.
func VerifyOIDCToken(tokenString, expectedAudience string, leeway time.Duration) (*OIDCClaims, error) {
	keyFunc := func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return getRSAPublicKeyFromJWKS(t)
	}

	// Parse without built-in exp check so we can apply leeway ourselves.
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithoutClaimsValidation(),
	)

	token, err := parser.ParseWithClaims(tokenString, jwt.MapClaims{}, keyFunc)
	if err != nil {
		return nil, fmt.Errorf("ratls/verify_oidc: parse token: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("ratls/verify_oidc: token not valid")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("ratls/verify_oidc: unexpected claims type")
	}

	// Manual exp check with leeway (jwt/v4 has no WithLeeway option).
	if !claims.VerifyExpiresAt(time.Now().Add(-leeway).Unix(), true) {
		return nil, fmt.Errorf("ratls/verify_oidc: token expired")
	}

	iss, _ := claims["iss"].(string)
	if iss != GCPCSIssuer {
		return nil, fmt.Errorf("ratls/verify_oidc: iss %q != expected %q", iss, GCPCSIssuer)
	}

	switch aud := claims["aud"].(type) {
	case string:
		if aud != expectedAudience {
			return nil, fmt.Errorf("ratls/verify_oidc: aud %q != expected %q", aud, expectedAudience)
		}
	case []any:
		found := false
		for _, a := range aud {
			if s, _ := a.(string); s == expectedAudience {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("ratls/verify_oidc: aud does not contain %q", expectedAudience)
		}
	default:
		return nil, fmt.Errorf("ratls/verify_oidc: aud claim missing or wrong type")
	}

	eatNonce, err := extractEatNonce(claims)
	if err != nil {
		return nil, fmt.Errorf("ratls/verify_oidc: %w", err)
	}

	hwmodel, _ := claims["hwmodel"].(string)
	if hwmodel == "" {
		return nil, fmt.Errorf("ratls/verify_oidc: hwmodel claim missing")
	}

	swname, _ := claims["swname"].(string)

	imageDigest, err := extractImageDigest(claims)
	if err != nil {
		return nil, fmt.Errorf("ratls/verify_oidc: %w", err)
	}

	return &OIDCClaims{
		EatNonce:    eatNonce,
		HWModel:     hwmodel,
		ImageDigest: imageDigest,
		SwName:      swname,
		Issuer:      iss,
		Audience:    expectedAudience,
	}, nil
}

func getRSAPublicKeyFromJWKS(t *jwt.Token) (any, error) {
	resp, err := http.Get(GCPCSJwksURL) //nolint:noctx
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	jwksBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	var keysFile jwksFile
	if err := json.Unmarshal(jwksBytes, &keysFile); err != nil {
		return nil, fmt.Errorf("unmarshal JWKS: %w", err)
	}

	kid, _ := t.Header["kid"].(string)
	for _, key := range keysFile.Keys {
		if key.Kid != kid {
			continue
		}
		return buildRSAPublicKey(key.N, key.E)
	}

	return nil, fmt.Errorf("key with kid=%q not found in JWKS", kid)
}

func getWellKnown() (wellKnown, error) {
	resp, err := http.Get(GCPCSIssuer + WellKnownPath) //nolint:noctx
	if err != nil {
		return wellKnown{}, fmt.Errorf("fetch well-known: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return wellKnown{}, fmt.Errorf("read well-known: %w", err)
	}

	var wk wellKnown
	if err := json.Unmarshal(b, &wk); err != nil {
		return wellKnown{}, fmt.Errorf("unmarshal well-known: %w", err)
	}

	if wk.JwksURI == "" {
		return wellKnown{}, fmt.Errorf("well-known missing jwks_uri")
	}
	return wk, nil
}

func buildRSAPublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("decode N: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("decode E: %w", err)
	}
	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

func extractEatNonce(claims jwt.MapClaims) (string, error) {
	raw, ok := claims["eat_nonce"]
	if !ok {
		return "", fmt.Errorf("eat_nonce claim missing")
	}
	switch v := raw.(type) {
	case string:
		return v, nil
	case []any:
		if len(v) == 0 {
			return "", fmt.Errorf("eat_nonce array is empty")
		}
		s, ok := v[0].(string)
		if !ok {
			return "", fmt.Errorf("eat_nonce[0] is not a string")
		}
		return s, nil
	default:
		return "", fmt.Errorf("eat_nonce has unexpected type %T", raw)
	}
}

func extractImageDigest(claims jwt.MapClaims) (string, error) {
	submods, ok := claims["submods"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("submods claim missing or wrong type")
	}
	container, ok := submods["container"].(map[string]any)
	if !ok {
		return "", fmt.Errorf("submods.container missing or wrong type")
	}
	digest, _ := container["image_digest"].(string)
	if digest == "" {
		return "", fmt.Errorf("submods.container.image_digest missing")
	}
	return digest, nil
}
