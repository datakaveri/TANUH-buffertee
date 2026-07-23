package bundle

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/keys"
)

// testKeys generates a fresh EnclaveKeys for use in a test.
func testKeys(t *testing.T) *keys.EnclaveKeys {
	t.Helper()
	k, err := keys.Generate()
	if err != nil {
		t.Fatalf("keys.Generate: %v", err)
	}
	return k
}

func randomNonce(t *testing.T) []byte {
	t.Helper()
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	return nonce
}

// ---------------------------------------------------------------------------
// Build()
// ---------------------------------------------------------------------------

func TestBuild_ProducesExpectedBundleFields(t *testing.T) {
	k := testKeys(t)
	b := &Builder{keys: k, oidcToken: "test-oidc-token", issuedAt: time.Now().Unix()}

	nonce := randomNonce(t)
	bndl, err := b.Build(nonce)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	if bndl.OIDCToken != "test-oidc-token" {
		t.Errorf("OIDCToken = %q, want %q", bndl.OIDCToken, "test-oidc-token")
	}
	if bndl.IssuedAt != b.issuedAt {
		t.Errorf("IssuedAt = %d, want %d", bndl.IssuedAt, b.issuedAt)
	}

	gotSPKI, err := base64.StdEncoding.DecodeString(bndl.BindingPubkeyB64)
	if err != nil {
		t.Fatalf("decode BindingPubkeyB64: %v", err)
	}
	if string(gotSPKI) != string(k.BindingSPKI) {
		t.Error("BindingPubkeyB64 does not match key's BindingSPKI")
	}

	gotHPKE, err := base64.StdEncoding.DecodeString(bndl.HPKEPubkeyB64)
	if err != nil {
		t.Fatalf("decode HPKEPubkeyB64: %v", err)
	}
	if string(gotHPKE) != string(k.HPKEPubBytes()) {
		t.Error("HPKEPubkeyB64 does not match key's HPKEPubBytes")
	}
}

// TestBuild_SignatureVerifiesWithECDSA is an end-to-end crypto check: decode the
// SPKI pubkey and DER signature exactly as the browser verifier would, and
// confirm the signature is a valid ECDSA signature over sha256(nonce).
func TestBuild_SignatureVerifiesWithECDSA(t *testing.T) {
	k := testKeys(t)
	b := &Builder{keys: k, oidcToken: "tok", issuedAt: time.Now().Unix()}

	nonce := randomNonce(t)
	bndl, err := b.Build(nonce)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	pubDER, err := base64.StdEncoding.DecodeString(bndl.BindingPubkeyB64)
	if err != nil {
		t.Fatalf("decode pubkey: %v", err)
	}
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("parse SPKI pubkey: %v", err)
	}
	pub, ok := pubAny.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("binding pubkey is not ECDSA, got %T", pubAny)
	}

	sig, err := base64.StdEncoding.DecodeString(bndl.NonceSigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}

	digest := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		t.Fatal("signature does not verify against sha256(nonce)")
	}
}

func TestBuild_TamperedNonceFailsVerification(t *testing.T) {
	k := testKeys(t)
	b := &Builder{keys: k, oidcToken: "tok", issuedAt: time.Now().Unix()}

	nonceA := randomNonce(t)
	nonceB := randomNonce(t)

	bndl, err := b.Build(nonceA)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	pubDER, _ := base64.StdEncoding.DecodeString(bndl.BindingPubkeyB64)
	pubAny, err := x509.ParsePKIXPublicKey(pubDER)
	if err != nil {
		t.Fatalf("parse pubkey: %v", err)
	}
	pub := pubAny.(*ecdsa.PublicKey)
	sig, _ := base64.StdEncoding.DecodeString(bndl.NonceSigB64)

	digestWrong := sha256.Sum256(nonceB)
	if ecdsa.VerifyASN1(pub, digestWrong[:], sig) {
		t.Fatal("signature unexpectedly verified against a different nonce")
	}
}

func TestBuild_DifferentNoncesProduceDifferentSignatures(t *testing.T) {
	k := testKeys(t)
	b := &Builder{keys: k, oidcToken: "tok", issuedAt: time.Now().Unix()}

	b1, err := b.Build(randomNonce(t))
	if err != nil {
		t.Fatalf("Build 1: %v", err)
	}
	b2, err := b.Build(randomNonce(t))
	if err != nil {
		t.Fatalf("Build 2: %v", err)
	}
	if b1.NonceSigB64 == b2.NonceSigB64 {
		t.Error("expected different signatures for different nonces")
	}
}

// ---------------------------------------------------------------------------
// HPKEKeys()
// ---------------------------------------------------------------------------

func TestHPKEKeys_ReturnsCurrentKeypair(t *testing.T) {
	k := testKeys(t)
	b := &Builder{keys: k}

	priv, pub := b.HPKEKeys()
	if priv != k.HPKEPriv {
		t.Error("HPKEKeys returned a different private key than the builder holds")
	}
	if pub != k.HPKEPub {
		t.Error("HPKEKeys returned a different public key than the builder holds")
	}
}

// ---------------------------------------------------------------------------
// verifyEatNonce()
// ---------------------------------------------------------------------------

// fakeJWT builds a syntactically valid 3-part token whose middle segment is
// the raw-url-base64 encoding of claims. verifyEatNonce never checks the
// signature, only the payload, so header/signature segments are placeholders.
func fakeJWT(t *testing.T, claims interface{}) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return "header." + base64.RawURLEncoding.EncodeToString(payload) + ".signature"
}

func TestVerifyEatNonce_ValidArrayPasses(t *testing.T) {
	k := testKeys(t)
	token := fakeJWT(t, map[string]interface{}{
		"eat_nonce": []string{k.BindingFingerprintB64URL(), k.HPKEPubB64URL()},
	})
	if err := verifyEatNonce(token, k); err != nil {
		t.Fatalf("expected valid eat_nonce to pass, got: %v", err)
	}
}

func TestVerifyEatNonce_SingleStringTooFewElements(t *testing.T) {
	k := testKeys(t)
	token := fakeJWT(t, map[string]interface{}{
		"eat_nonce": k.BindingFingerprintB64URL(), // string, not array — coerces to len-1 slice
	})
	if err := verifyEatNonce(token, k); err == nil {
		t.Fatal("expected error when eat_nonce has fewer than 2 elements")
	}
}

func TestVerifyEatNonce_MismatchFingerprint0(t *testing.T) {
	k := testKeys(t)
	token := fakeJWT(t, map[string]interface{}{
		"eat_nonce": []string{"wrong-fingerprint", k.HPKEPubB64URL()},
	})
	if err := verifyEatNonce(token, k); err == nil {
		t.Fatal("expected error for eat_nonce[0] mismatch")
	}
}

func TestVerifyEatNonce_MismatchFingerprint1(t *testing.T) {
	k := testKeys(t)
	token := fakeJWT(t, map[string]interface{}{
		"eat_nonce": []string{k.BindingFingerprintB64URL(), "wrong-hpke-pub"},
	})
	if err := verifyEatNonce(token, k); err == nil {
		t.Fatal("expected error for eat_nonce[1] mismatch")
	}
}

func TestVerifyEatNonce_MissingField(t *testing.T) {
	k := testKeys(t)
	token := fakeJWT(t, map[string]interface{}{"sub": "irrelevant"})
	if err := verifyEatNonce(token, k); err == nil {
		t.Fatal("expected error when eat_nonce is missing")
	}
}

func TestVerifyEatNonce_NonStringElement(t *testing.T) {
	k := testKeys(t)
	token := fakeJWT(t, map[string]interface{}{
		"eat_nonce": []interface{}{123, k.HPKEPubB64URL()},
	})
	if err := verifyEatNonce(token, k); err == nil {
		t.Fatal("expected error when eat_nonce[0] is not a string")
	}
}

func TestVerifyEatNonce_NotThreePartJWT(t *testing.T) {
	k := testKeys(t)
	if err := verifyEatNonce("only.two", k); err == nil {
		t.Fatal("expected error for a non-three-part token")
	}
}

func TestVerifyEatNonce_InvalidBase64Payload(t *testing.T) {
	k := testKeys(t)
	if err := verifyEatNonce("header.!!!not-valid-base64!!!.sig", k); err == nil {
		t.Fatal("expected error for undecodable payload")
	}
}

func TestVerifyEatNonce_InvalidJSONPayload(t *testing.T) {
	k := testKeys(t)
	notJSON := base64.RawURLEncoding.EncodeToString([]byte("this is not json"))
	if err := verifyEatNonce("header."+notJSON+".sig", k); err == nil {
		t.Fatal("expected error for payload that decodes but isn't valid JSON")
	}
}

// ---------------------------------------------------------------------------
// toStringSlice()
// ---------------------------------------------------------------------------

func TestToStringSlice(t *testing.T) {
	t.Run("array of strings", func(t *testing.T) {
		got, err := toStringSlice([]interface{}{"a", "b"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Fatalf("got %v, want [a b]", got)
		}
	})

	t.Run("single string", func(t *testing.T) {
		got, err := toStringSlice("solo")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0] != "solo" {
			t.Fatalf("got %v, want [solo]", got)
		}
	})

	t.Run("array with non-string element", func(t *testing.T) {
		if _, err := toStringSlice([]interface{}{"a", 42}); err == nil {
			t.Fatal("expected error for non-string array element")
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		if _, err := toStringSlice(42); err == nil {
			t.Fatal("expected error for unsupported type")
		}
	})

	t.Run("nil value", func(t *testing.T) {
		if _, err := toStringSlice(nil); err == nil {
			t.Fatal("expected error for nil value")
		}
	})
}

// ---------------------------------------------------------------------------
// RefreshOIDC() / FullRotate() — outside GCP Confidential Space, the
// teeserver unix socket does not exist, so attest.FetchOIDC is expected to
// fail here. These tests assert the required invariant from CONTEXT.md:
// "on error, log and continue — in-flight requests keep serving with the
// previous valid state."
//
// NOTE: if these tests are ever run *inside* an actual Confidential Space VM
// (where the socket is present), they will behave differently. That's fine —
// they document/enforce the fallback behavior for the far more common case
// of running in a dev machine or CI.
// ---------------------------------------------------------------------------

func TestRefreshOIDC_PreservesOldTokenOnFailure(t *testing.T) {
	k := testKeys(t)
	b := &Builder{
		audience:  "test-audience",
		keys:      k,
		oidcToken: "original-token",
		issuedAt:  1000,
	}

	err := b.RefreshOIDC(context.Background())
	if err == nil {
		t.Skip("teeserver socket appears to be present in this environment; skipping fallback test")
	}

	if b.oidcToken != "original-token" {
		t.Errorf("oidcToken changed after failed refresh: got %q, want %q", b.oidcToken, "original-token")
	}
	if b.issuedAt != 1000 {
		t.Errorf("issuedAt changed after failed refresh: got %d, want %d", b.issuedAt, 1000)
	}
}

func TestFullRotate_PreservesOldKeysOnFailure(t *testing.T) {
	k := testKeys(t)
	originalFP := k.BindingFingerprintB64URL()
	b := &Builder{
		audience:  "test-audience",
		keys:      k,
		oidcToken: "original-token",
		issuedAt:  1000,
	}

	err := b.FullRotate(context.Background())
	if err == nil {
		t.Skip("teeserver socket appears to be present in this environment; skipping fallback test")
	}

	if b.keys.BindingFingerprintB64URL() != originalFP {
		t.Error("keys changed after failed full rotation")
	}
	if b.oidcToken != "original-token" {
		t.Errorf("oidcToken changed after failed full rotation: got %q", b.oidcToken)
	}
}