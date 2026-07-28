package server

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/datakaveri/tanuh-buffer-tee/internal/config"
	"github.com/datakaveri/tanuh-buffer-tee/internal/jobs"
)

// ─────────────────────────────────────────────────────────────────────────────
// COVERAGE NOTE
//
// Server.builder is a concrete *bundle.Builder. The only public constructor,
// bundle.NewBuilder, dials the GCP Confidential Space launcher's Unix socket
// to fetch a real OIDC token — that only exists on a live CS VM, and there is
// no injectable seam from this package. So HandleAttest, HandleSubmit, and the
// three HandleUpload* handlers (all of which call s.builder.HPKEKeys()) are
// NOT covered here — they cannot be constructed in a hermetic unit test.
//
// Similarly, HandleComplete's real verification logic calls
// dispatch.VerifyOIDCToken, which fetches Google's JWKS from a hardcoded URL
// with no override. Only its very first guard (missing bearer token) returns
// before that network call, so that's the only branch of HandleComplete
// tested here.
//
// auth.go's JWT/JWKS crypto internals (validateKeycloakJWT, JWKS caching, RSA
// key reconstruction, the alg=none attack) are assumed covered by an existing
// auth_test.go in this package (per project notes) and are deliberately not
// re-tested here to avoid duplicate coverage / name collisions — every helper
// and test in this file is prefixed "Srv" for that reason. If no such file
// exists, those internals remain untested and should be added separately.
// ─────────────────────────────────────────────────────────────────────────────

// ── test helpers ────────────────────────────────────────────────────────────

// newServerForTests builds a Server backed by a real, temp-dir jobs.Store and
// a nil *bundle.Builder. This is safe as long as tests never exercise a route
// that touches s.builder (attest/submit/upload).
func newServerForTests(t *testing.T, auth AuthConfig) (*Server, *jobs.Store) {
	t.Helper()
	store, err := jobs.Open(t.TempDir())
	if err != nil {
		t.Fatalf("jobs.Open: %v", err)
	}
	srv := New(nil, auth, store, config.Config{})
	return srv, store
}

// sha256Hex returns the lowercase hex SHA-256 digest of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// queueAJob creates a job and uploads matching model+weights so it
// transitions to StatusQueued, mirroring what /v1/submit + /v1/upload would
// do in production.
func queueAJob(t *testing.T, store *jobs.Store) *jobs.Job {
	t.Helper()
	modelBytes := []byte("model-bytes-for-server-tests")
	weightsBytes := []byte("weights-bytes-for-server-tests")
	job, err := store.Create(jobs.NewJobRequest{
		DatasetID:     1,
		ModelSHA256:   sha256Hex(modelBytes),
		WeightsSHA256: sha256Hex(weightsBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := store.ReceiveArtifact(job.JobID, jobs.ModelFileName, modelBytes); err != nil {
		t.Fatalf("ReceiveArtifact(model): %v", err)
	}
	got, err := store.ReceiveArtifact(job.JobID, jobs.WeightsFileName, weightsBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(weights): %v", err)
	}
	return got
}

// buildUnverifiedJWT builds a syntactically valid JWT (header.payload.signature)
// whose signature is never actually verified by the code paths under test
// here — jwtRealmRoles never checks it, and validateKeycloakJWT rejects
// non-RS256 tokens before it would ever fetch a verification key. This lets
// us drive both requireRole and keycloakAuthMiddleware's early-exit paths
// without a real Keycloak/JWKS endpoint.
func buildUnverifiedJWT(t *testing.T, alg string, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": alg, "kid": "test-kid"}
	hb, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	pb, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hb) + "." + enc.EncodeToString(pb) + "." +
		enc.EncodeToString([]byte("unverified-signature-not-checked-by-these-tests"))
}

// decodeJSONBody unmarshals a recorder's body into a generic map for
// field-by-field assertions.
func decodeJSONBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("decode response body: %v (body=%s)", err, rec.Body.String())
	}
	return m
}

// ── isCompletionCallback ─────────────────────────────────────────────────────

func TestSrvIsCompletionCallback(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
		want   bool
	}{
		{"matches POST .../complete", http.MethodPost, "/v1/jobs/job-abc123/complete", true},
		{"wrong method", http.MethodGet, "/v1/jobs/job-abc123/complete", false},
		{"wrong suffix", http.MethodPost, "/v1/jobs/job-abc123/status", false},
		{"wrong prefix", http.MethodPost, "/v1/status/job-abc123", false},
		{"no job id segment still matches (prefix+suffix only)", http.MethodPost, "/v1/jobs/complete", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, nil)
			if got := isCompletionCallback(r); got != tc.want {
				t.Errorf("isCompletionCallback(%s %s) = %v, want %v", tc.method, tc.path, got, tc.want)
			}
		})
	}
}

// ── corsMiddleware ───────────────────────────────────────────────────────────

func TestSrvCorsMiddleware_OptionsPreflightShortCircuits(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := corsMiddleware(next)

	req := httptest.NewRequest(http.MethodOptions, "/v1/anything", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusNoContent)
	}
	if called {
		t.Error("next handler should not be called for OPTIONS preflight")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
	if rec.Header().Get("Access-Control-Allow-Methods") == "" {
		t.Error("Access-Control-Allow-Methods header missing")
	}
	if rec.Header().Get("Access-Control-Max-Age") == "" {
		t.Error("Access-Control-Max-Age header missing")
	}
}

func TestSrvCorsMiddleware_PassesThroughOtherMethodsAndStillSetsHeaders(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusTeapot)
	})
	h := corsMiddleware(next)

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if !called {
		t.Error("next handler should be called for non-OPTIONS requests")
	}
	if rec.Code != http.StatusTeapot {
		t.Errorf("status = %d, want %d (next's status must be preserved)", rec.Code, http.StatusTeapot)
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}

// ── keycloakAuthMiddleware ───────────────────────────────────────────────────

func TestSrvKeycloakAuthMiddleware_BypassesExemptRoutes(t *testing.T) {
	cases := []struct {
		name   string
		method string
		path   string
	}{
		{"OPTIONS preflight on a protected route", http.MethodOptions, "/v1/submit"},
		{"healthz", http.MethodGet, "/healthz"},
		{"completion callback", http.MethodPost, "/v1/jobs/job-1/complete"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				called = true
				w.WriteHeader(http.StatusOK)
			})
			h := keycloakAuthMiddleware("https://example.invalid/jwks", "https://example.invalid/issuer", next)

			// Deliberately NO Authorization header — these routes must bypass
			// auth entirely regardless.
			req := httptest.NewRequest(tc.method, tc.path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if !called {
				t.Errorf("next handler was not called for exempt route %s %s", tc.method, tc.path)
			}
			if rec.Code != http.StatusOK {
				t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
			}
		})
	}
}

func TestSrvKeycloakAuthMiddleware_RequiresBearerToken(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := keycloakAuthMiddleware("https://example.invalid/jwks", "https://example.invalid/issuer", next)

	req := httptest.NewRequest(http.MethodGet, "/v1/status/job-1", nil) // no Authorization header
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not be called without a bearer token")
	}
}

func TestSrvKeycloakAuthMiddleware_RejectsNonBearerScheme(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := keycloakAuthMiddleware("https://example.invalid/jwks", "https://example.invalid/issuer", next)

	req := httptest.NewRequest(http.MethodGet, "/v1/status/job-1", nil)
	req.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not be called for a non-Bearer Authorization scheme")
	}
}

func TestSrvKeycloakAuthMiddleware_RejectsUnsupportedAlgWithoutNetworkCall(t *testing.T) {
	// validateKeycloakJWT decodes the header and checks alg == "RS256" BEFORE
	// it ever calls getPublicKey/fetchJWKS. An HS256 header should therefore
	// be rejected with no attempt to reach the (bogus, unreachable) JWKS URL
	// below — this test would hang/fail on a real network call if that
	// ordering ever regressed.
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })
	h := keycloakAuthMiddleware("https://example.invalid/jwks-does-not-exist", "https://example.invalid/issuer", next)

	token := buildUnverifiedJWT(t, "HS256", map[string]any{"sub": "someone"})
	req := httptest.NewRequest(http.MethodGet, "/v1/status/job-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
	}
	if called {
		t.Error("next handler should not be called for an unsupported alg")
	}
}

// ── RBAC on GET /v1/queue (requireRole, wired in New regardless of Keycloak) ─

func TestSrvQueueEndpoint_RequiresOrgAdminRole(t *testing.T) {
	// requireRole is wrapped around /v1/queue inside New() unconditionally —
	// it applies even when Keycloak signature verification (AuthConfig) is
	// disabled, because jwtRealmRoles reads the JWT payload without
	// verifying its signature. That lets us exercise the full 403/200
	// decision purely with unverified tokens.
	srv, _ := newServerForTests(t, AuthConfig{})

	cases := []struct {
		name       string
		roles      []string
		sendHeader bool
		wantStatus int
	}{
		{"no Authorization header at all", nil, false, http.StatusForbidden},
		{"authenticated but wrong role", []string{"viewer"}, true, http.StatusForbidden},
		{"org_admin role present", []string{"org_admin"}, true, http.StatusOK},
		{"org_admin among several roles", []string{"viewer", "org_admin", "billing"}, true, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
			if tc.sendHeader {
				token := buildUnverifiedJWT(t, "RS256", map[string]any{
					"realm_access": map[string]any{"roles": tc.roles},
				})
				req.Header.Set("Authorization", "Bearer "+token)
			}
			rec := httptest.NewRecorder()
			srv.Handler().ServeHTTP(rec, req)
			if rec.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d (body=%s)", rec.Code, tc.wantStatus, rec.Body.String())
			}
		})
	}
}

// ── HandleStatus ─────────────────────────────────────────────────────────────

func TestSrvHandleStatus_UnknownJob(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{})
	req := httptest.NewRequest(http.MethodGet, "/v1/status/job-ghost", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
	body := decodeJSONBody(t, rec)
	if body["status"] != "error" {
		t.Errorf("status field = %v, want %q", body["status"], "error")
	}
	if body["message"] != "Unknown job_id" {
		t.Errorf("message = %v, want %q", body["message"], "Unknown job_id")
	}
}

func TestSrvHandleStatus_KnownJob(t *testing.T) {
	srv, store := newServerForTests(t, AuthConfig{})
	job, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status/"+job.JobID, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	body := decodeJSONBody(t, rec)
	if body["status"] != "success" {
		t.Errorf("status field = %v, want %q", body["status"], "success")
	}
	nested, ok := body["job"].(map[string]any)
	if !ok {
		t.Fatalf("job field missing or wrong type: %+v", body)
	}
	if nested["job_id"] != job.JobID {
		t.Errorf("job.job_id = %v, want %q", nested["job_id"], job.JobID)
	}
	if nested["status"] != jobs.StatusPendingUpload {
		t.Errorf("job.status = %v, want %q", nested["status"], jobs.StatusPendingUpload)
	}
}

// ── HandleQueue (called directly — no requireRole wrapper) ──────────────────

func TestSrvHandleQueue_EmptyStore(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{})
	req := httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
	rec := httptest.NewRecorder()
	srv.HandleQueue(rec, req) // calling the handler directly bypasses requireRole

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := decodeJSONBody(t, rec)
	if body["queued_count"] != float64(0) {
		t.Errorf("queued_count = %v, want 0", body["queued_count"])
	}
	queuedIDs, ok := body["queued_job_ids"].([]any)
	if !ok || len(queuedIDs) != 0 {
		t.Errorf("queued_job_ids = %v, want empty array (not null)", body["queued_job_ids"])
	}
	allJobs, ok := body["jobs"].([]any)
	if !ok || len(allJobs) != 0 {
		t.Errorf("jobs = %v, want empty array", body["jobs"])
	}
}

func TestSrvHandleQueue_WithMixedJobStatuses(t *testing.T) {
	srv, store := newServerForTests(t, AuthConfig{})
	pending, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	queued := queueAJob(t, store)

	req := httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
	rec := httptest.NewRecorder()
	srv.HandleQueue(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	body := decodeJSONBody(t, rec)
	if body["queued_count"] != float64(1) {
		t.Errorf("queued_count = %v, want 1 (only the queued job counts)", body["queued_count"])
	}
	allJobs, ok := body["jobs"].([]any)
	if !ok || len(allJobs) != 2 {
		t.Fatalf("jobs = %v, want 2 entries (pending %s + queued %s)", body["jobs"], pending.JobID, queued.JobID)
	}
}

// ── HandleResults ────────────────────────────────────────────────────────────

func TestSrvHandleResults_UnknownJob(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{})
	req := httptest.NewRequest(http.MethodGet, "/v1/results/job-ghost", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusNotFound)
	}
}

func TestSrvHandleResults_NoResultsFileYet(t *testing.T) {
	// Results live on the external leaderboard; this endpoint only ever
	// passes through a local results.json if one happens to exist. A job
	// that exists but has no such file must report 404 + its current
	// status, NOT a 200 with empty/placeholder content.
	srv, store := newServerForTests(t, AuthConfig{})
	job, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/results/"+job.JobID, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	body := decodeJSONBody(t, rec)
	if body["status"] != jobs.StatusPendingUpload {
		t.Errorf("status field = %v, want current job status %q", body["status"], jobs.StatusPendingUpload)
	}
}

func TestSrvHandleResults_WithResultsFile(t *testing.T) {
	srv, store := newServerForTests(t, AuthConfig{})
	job, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	raw := []byte(`{"metrics":{"accuracy":0.93},"num_samples":500}`)
	resultsPath := store.ResultsPath(job.JobID)
	if err := os.MkdirAll(filepath.Dir(resultsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(resultsPath, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/results/"+job.JobID, nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusOK, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}
	// The handler streams the file straight through — it must NOT
	// re-encode or reshape it.
	if rec.Body.String() != string(raw) {
		t.Errorf("body = %q, want exact passthrough of %q", rec.Body.String(), raw)
	}
}

// ── HandleComplete (only the pre-attestation guard is unit-testable) ────────

func TestSrvHandleComplete_MissingBearerToken(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{})
	body := strings.NewReader(`{"job_id":"job-abc","status":"succeeded"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/jobs/job-abc/complete", body)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req) // no Authorization header at all

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d (body=%s)", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}
	got := decodeJSONBody(t, rec)
	if got["message"] != "missing attestation token" {
		t.Errorf("message = %v, want %q", got["message"], "missing attestation token")
	}
}

// ── Server.Handler() dispatch logic ──────────────────────────────────────────

func TestSrvHandlerDispatch_NoAuthWrappingWhenJWKSUrlEmpty(t *testing.T) {
	srv, store := newServerForTests(t, AuthConfig{}) // JWKSUrl == "" -> auth disabled
	job, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status/"+job.JobID, nil) // no Authorization header
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d — request should not be blocked when auth is disabled", rec.Code, http.StatusOK)
	}
}

func TestSrvHandlerDispatch_WrapsKeycloakAuthWhenConfigured(t *testing.T) {
	srv, store := newServerForTests(t, AuthConfig{
		JWKSUrl: "https://example.invalid/jwks",
		Issuer:  "https://example.invalid/issuer",
	})
	job, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/v1/status/"+job.JobID, nil) // no Authorization header
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d — request should be blocked once auth is configured", rec.Code, http.StatusUnauthorized)
	}
}

func TestSrvHealthzBypassesAuthEvenWhenConfigured(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{
		JWKSUrl: "https://example.invalid/jwks",
		Issuer:  "https://example.invalid/issuer",
	})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ── extractKeycloakSub ───────────────────────────────────────────────────────

func TestSrvExtractKeycloakSub_ValidToken(t *testing.T) {
	token := buildUnverifiedJWT(t, "RS256", map[string]any{"sub": "user-123"})
	if got := extractKeycloakSub(token); got != "user-123" {
		t.Errorf("extractKeycloakSub = %q, want %q", got, "user-123")
	}
}

func TestSrvExtractKeycloakSub_MalformedToken(t *testing.T) {
	if got := extractKeycloakSub("not-a-jwt-at-all"); got != "" {
		t.Errorf("extractKeycloakSub = %q, want empty string for a malformed token", got)
	}
}

func TestSrvExtractKeycloakSub_MissingSubClaim(t *testing.T) {
	token := buildUnverifiedJWT(t, "RS256", map[string]any{"other_claim": "value"})
	if got := extractKeycloakSub(token); got != "" {
		t.Errorf("extractKeycloakSub = %q, want empty string when sub is absent", got)
	}
}

// ── processJob ───────────────────────────────────────────────────────────────

func TestSrvProcessJob_Success(t *testing.T) {
	srv, store := newServerForTests(t, AuthConfig{})
	plaintext, err := json.Marshal(JobRequest{
		DatasetID:     2,
		ModelSHA256:   "abc123",
		WeightsSHA256: "def456",
	})
	if err != nil {
		t.Fatalf("marshal JobRequest: %v", err)
	}

	respBytes := srv.processJob(plaintext, "keycloak-user-1", "keycloak-token-xyz")

	var resp map[string]any
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v (raw=%s)", err, respBytes)
	}
	if resp["status"] != jobs.StatusPendingUpload {
		t.Errorf("status = %v, want %q", resp["status"], jobs.StatusPendingUpload)
	}
	jobID, _ := resp["job_id"].(string)
	if !strings.HasPrefix(jobID, "job-") {
		t.Errorf("job_id = %q, want it to start with 'job-'", jobID)
	}
	if resp["dataset_id"] != float64(2) {
		t.Errorf("dataset_id = %v, want 2", resp["dataset_id"])
	}

	// Confirm it was actually persisted with the identity fields threaded
	// through from the caller (not just echoed in the response).
	persisted, err := store.Get(jobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if persisted.SubmittedBy != "keycloak-user-1" {
		t.Errorf("SubmittedBy = %q, want %q", persisted.SubmittedBy, "keycloak-user-1")
	}
	if persisted.KeycloakToken != "keycloak-token-xyz" {
		t.Errorf("KeycloakToken = %q, want %q", persisted.KeycloakToken, "keycloak-token-xyz")
	}
}

func TestSrvProcessJob_InvalidJSONPayload(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{})
	respBytes := srv.processJob([]byte("this is not json"), "user-1", "token")

	var resp map[string]any
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "error" {
		t.Errorf("status = %v, want %q", resp["status"], "error")
	}
	msg, _ := resp["message"].(string)
	if !strings.Contains(msg, "invalid job payload") {
		t.Errorf("message = %q, want it to mention 'invalid job payload'", msg)
	}
}

func TestSrvProcessJob_InvalidDatasetIDBubblesStoreError(t *testing.T) {
	srv, _ := newServerForTests(t, AuthConfig{})
	plaintext, err := json.Marshal(JobRequest{DatasetID: 99})
	if err != nil {
		t.Fatalf("marshal JobRequest: %v", err)
	}

	respBytes := srv.processJob(plaintext, "user-1", "token")

	var resp map[string]any
	if err := json.Unmarshal(respBytes, &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if resp["status"] != "error" {
		t.Errorf("status = %v, want %q", resp["status"], "error")
	}
	// This message comes straight from jobs.Store.Create's validation —
	// processJob must surface it verbatim rather than swallowing it.
	if resp["message"] != "dataset_id must be 1, 2, or 3" {
		t.Errorf("message = %v, want the store's validation error to pass through", resp["message"])
	}
}

// ── jsonErr ──────────────────────────────────────────────────────────────────

func TestSrvJsonErr_Shape(t *testing.T) {
	raw := jsonErr("something broke")
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if m["status"] != "error" || m["message"] != "something broke" {
		t.Errorf("jsonErr shape = %+v, want {status:error, message:'something broke'}", m)
	}
}