package dispatch

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
)

func TestEKMNonce(t *testing.T) {
	ekm := make([]byte, EKMLength)
	for i := range ekm {
		ekm[i] = byte(i)
	}
	nonce := EKMNonce(ekm)
	// base64url(sha256) with no padding is always 43 chars — within GCP's
	// 10–74 char nonce limits.
	if len(nonce) != 43 {
		t.Fatalf("nonce length = %d, want 43 (%q)", len(nonce), nonce)
	}
	decoded, err := Base64DecodeURLNoPad(nonce)
	if err != nil {
		t.Fatalf("nonce is not valid base64url: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded nonce length = %d, want 32", len(decoded))
	}
	if again := EKMNonce(ekm); again != nonce {
		t.Fatalf("EKMNonce not deterministic: %q vs %q", nonce, again)
	}
}

func TestExtractEatNonce(t *testing.T) {
	cases := []struct {
		name    string
		claims  jwt.MapClaims
		want    string
		wantErr bool
	}{
		{"string form", jwt.MapClaims{"eat_nonce": "abc"}, "abc", false},
		{"array form", jwt.MapClaims{"eat_nonce": []any{"first", "second"}}, "first", false},
		{"missing", jwt.MapClaims{}, "", true},
		{"empty array", jwt.MapClaims{"eat_nonce": []any{}}, "", true},
		{"wrong type", jwt.MapClaims{"eat_nonce": 42}, "", true},
		{"non-string element", jwt.MapClaims{"eat_nonce": []any{42}}, "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractEatNonce(tc.claims)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestExtractImageDigest(t *testing.T) {
	cases := []struct {
		name    string
		claims  jwt.MapClaims
		want    string
		wantErr bool
	}{
		{
			"valid",
			jwt.MapClaims{"submods": map[string]any{"container": map[string]any{"image_digest": "sha256:abc"}}},
			"sha256:abc", false,
		},
		{"missing submods", jwt.MapClaims{}, "", true},
		{"missing container", jwt.MapClaims{"submods": map[string]any{}}, "", true},
		{
			"empty digest",
			jwt.MapClaims{"submods": map[string]any{"container": map[string]any{"image_digest": ""}}},
			"", true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractImageDigest(tc.claims)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr = %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
