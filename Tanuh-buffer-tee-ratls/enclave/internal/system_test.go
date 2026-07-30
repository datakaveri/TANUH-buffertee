// Package buffertee_test holds whole-module system scenarios for the
// Buffer TEE (module github.com/datakaveri/tanuh-buffer-tee).
//
// SCOPE: this file lives at the module root specifically so it can import
// every internal/* package (Go's "internal" visibility rule allows any
// package rooted at the parent of an internal/ directory to import it — and
// here that parent is the module root itself). It exercises multiple
// packages together through PUBLIC APIs ONLY, simulating realistic
// end-to-end flows. It is a complement to, not a replacement for, the
// per-package test files (jobs_test.go, server_test.go, keys_test.go,
// hpke_test.go, provision_test.go, auth_test.go, bundle_test.go,
// dispatch_test.go), which are the only place unexported internals get
// exercised — a single file cannot reach into the unexported internals of
// more than one package at a time in Go.
//
// EXCLUDED, AND WHY:
//   - internal/bundle (Builder), internal/rotation (Rotator): the only
//     public constructor performs a live GCP Confidential Space attestation
//     exchange over a Unix socket that only exists on a real CS VM.
//   - internal/gcp: every function makes a real network call to the GCP
//     metadata server or Compute/Secret Manager REST APIs.
//   - cmd/buffer-tee: package main. Go cannot import a main package at all,
//     from anywhere, so its unexported helpers (cert generation, the
//     Compute/health-probe adapters) are untestable from any external file;
//     they'd need their own internal test file in that directory.
//   - server.HandleAttest / HandleSubmit / HandleUpload*: all require a
//     live *bundle.Builder for the same reason as above.
//   - server.HandleComplete's verification body: depends on
//     dispatch.VerifyOIDCToken fetching Google's real JWKS from a hardcoded,
//     non-injectable URL.
package buffertee_test

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/config"
	"github.com/datakaveri/tanuh-buffer-tee/internal/dispatch"
	"github.com/datakaveri/tanuh-buffer-tee/internal/gcp"
	"github.com/datakaveri/tanuh-buffer-tee/internal/hpke"
	"github.com/datakaveri/tanuh-buffer-tee/internal/jobs"
	"github.com/datakaveri/tanuh-buffer-tee/internal/keys"
	"github.com/datakaveri/tanuh-buffer-tee/internal/provision"
	"github.com/datakaveri/tanuh-buffer-tee/internal/server"
)

// ── shared test helpers (prefixed "sys" to avoid clashing with helpers in
//    the per-package test files, which live in different packages anyway
//    but keep naming distinct for readability when grepping across the repo) ──

func sysSha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// sysQueueJob creates a job and uploads matching model+weights bytes so it
// naturally reaches jobs.StatusQueued via the store's real API.
func sysQueueJob(t *testing.T, store *jobs.Store) *jobs.Job {
	t.Helper()
	modelBytes := []byte("system-scenario-model-bytes")
	weightsBytes := []byte("system-scenario-weights-bytes")
	job, err := store.Create(jobs.NewJobRequest{
		DatasetID:     1,
		ModelSHA256:   sysSha256Hex(modelBytes),
		WeightsSHA256: sysSha256Hex(weightsBytes),
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

// sysBuildRoleJWT builds a syntactically valid but UNSIGNED JWT carrying the
// given realm roles. requireRole (exercised only indirectly here, through
// the real /v1/queue route) reads realm_access.roles from the payload
// without verifying the signature, so this is sufficient to drive the RBAC
// decision without a live Keycloak/JWKS endpoint.
func sysBuildRoleJWT(t *testing.T, roles []string) string {
	t.Helper()
	header := map[string]any{"alg": "RS256", "kid": "system-test-kid"}
	payload := map[string]any{"realm_access": map[string]any{"roles": roles}}
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
		enc.EncodeToString([]byte("unverified-signature"))
}

// ── fakes for internal/provision's Compute/Health/Clock interfaces ─────────

type sysFakeCompute struct {
	startErr map[string]error // keyed by Target.Name
	starts   []string
	stops    []string
}

func (f *sysFakeCompute) Start(_ context.Context, t config.Target) error {
	f.starts = append(f.starts, t.Name)
	return f.startErr[t.Name]
}

func (f *sysFakeCompute) Stop(_ context.Context, t config.Target) error {
	f.stops = append(f.stops, t.Name)
	return nil
}

type sysFakeHealth struct {
	healthy map[string]bool // keyed by health URL
}

func (f *sysFakeHealth) Healthy(_ context.Context, url string) bool {
	return f.healthy[url]
}

// sysFakeClock advances instantly on Sleep so boot-timeout loops in
// provision.Engine.Provision resolve without real wall-clock waiting.
type sysFakeClock struct{ now time.Time }

func (c *sysFakeClock) Now() time.Time { return c.now }
func (c *sysFakeClock) Sleep(_ context.Context, d time.Duration) {
	c.now = c.now.Add(d)
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 1 — key generation, attestation signing, and fingerprint binding
// ═════════════════════════════════════════════════════════════════════════
//
// Why: every other scenario in this file (and the real /v1/attest endpoint)
// depends on internal/keys producing a keypair that (a) is unique per
// enclave instance, (b) can sign a liveness nonce such that ONLY the
// matching public key verifies it, and (c) exposes fingerprints that
// round-trip correctly — this is the eat_nonce binding contract in
// miniature, without needing a live OIDC token.
func TestScenario_KeyGenerationAndAttestationSigning(t *testing.T) {
	k1, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate k1: %v", err)
	}
	k2, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate k2: %v", err)
	}
	if bytes.Equal(k1.BindingSPKI, k2.BindingSPKI) {
		t.Fatal("two independently generated keypairs produced identical SPKI bytes")
	}

	nonce := []byte("liveness-nonce-supplied-by-a-browser")
	sig, err := k1.SignNonce(nonce)
	if err != nil {
		t.Fatalf("SignNonce: %v", err)
	}

	digest := sha256.Sum256(nonce)
	if !ecdsa.VerifyASN1(k1.BindingPub, digest[:], sig) {
		t.Fatal("signature did not verify against the signing key's own public key")
	}
	if ecdsa.VerifyASN1(k2.BindingPub, digest[:], sig) {
		t.Fatal("signature verified against an unrelated keypair — binding is broken")
	}

	// eat_nonce[0] is base64url(sha256(BindingSPKI)); confirm the round trip.
	decodedFP, err := base64.RawURLEncoding.DecodeString(k1.BindingFingerprintB64URL())
	if err != nil {
		t.Fatalf("decode fingerprint: %v", err)
	}
	wantFP := sha256.Sum256(k1.BindingSPKI)
	if !bytes.Equal(decodedFP, wantFP[:]) {
		t.Fatal("BindingFingerprintB64URL does not decode to sha256(BindingSPKI)")
	}

	// eat_nonce[1] is base64url(HPKE pubkey bytes); confirm the round trip.
	decodedHP, err := base64.RawURLEncoding.DecodeString(k1.HPKEPubB64URL())
	if err != nil {
		t.Fatalf("decode HPKE pub: %v", err)
	}
	if !bytes.Equal(decodedHP, k1.HPKEPubBytes()) {
		t.Fatal("HPKEPubB64URL does not decode to HPKEPubBytes()")
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 2 — the full HPKE envelope, both directions, as /v1/submit uses it
// ═════════════════════════════════════════════════════════════════════════
//
// Why: server.HandleSubmit itself can't be unit-tested (it needs a live
// *bundle.Builder), but everything it delegates to for the actual
// encryption/decryption work — internal/hpke plus an internal/keys keypair
// standing in for the enclave's real one — is fully public. This scenario
// proves that crypto envelope round-trips correctly in BOTH directions
// (browser→enclave request, enclave→browser response) using the exact
// context-binding info string the real handler builds, which is the piece
// that actually matters for security (it's what stops a ciphertext meant
// for one session from being replayed into another).
func TestScenario_HPKEBrowserEnclaveSubmitRoundTrip(t *testing.T) {
	enclaveKeys, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	browserPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate browser ephemeral key: %v", err)
	}
	browserPubBytes := browserPriv.PublicKey().Bytes()

	info := hpke.ContextInfo(enclaveKeys.HPKEPubBytes(), browserPubBytes)

	// Request direction: browser seals the job metadata to the enclave's
	// long-lived HPKE public key.
	reqAAD := []byte(`{"rid":"req-1"}`)
	reqPlain := []byte(`{"dataset_id":1,"model_sha256":"aa","weights_sha256":"bb"}`)
	reqSeal, err := hpke.SealToBrowser(enclaveKeys.HPKEPubBytes(), info, reqAAD, reqPlain)
	if err != nil {
		t.Fatalf("seal request: %v", err)
	}
	gotReq, err := hpke.OpenFromBrowser(enclaveKeys.HPKEPriv, reqSeal.Enc, info, reqAAD, reqSeal.Ciphertext)
	if err != nil {
		t.Fatalf("open request: %v", err)
	}
	if !bytes.Equal(gotReq, reqPlain) {
		t.Fatalf("request plaintext mismatch: got %q want %q", gotReq, reqPlain)
	}

	// Response direction: enclave seals {status, job_id} back to the
	// browser's ephemeral public key.
	respAAD := []byte(`{"rid":"req-1","ts":1234567890}`)
	respPlain := []byte(`{"status":"pending_upload","job_id":"job-abc123"}`)
	respSeal, err := hpke.SealToBrowser(browserPubBytes, info, respAAD, respPlain)
	if err != nil {
		t.Fatalf("seal response: %v", err)
	}
	gotResp, err := hpke.OpenFromBrowser(browserPriv, respSeal.Enc, info, respAAD, respSeal.Ciphertext)
	if err != nil {
		t.Fatalf("open response: %v", err)
	}
	if !bytes.Equal(gotResp, respPlain) {
		t.Fatalf("response plaintext mismatch: got %q want %q", gotResp, respPlain)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 3 — the negative case: tampering must fail, in both directions
// ═════════════════════════════════════════════════════════════════════════
//
// Why: a round-trip test alone doesn't prove the AEAD tag or the info
// binding are actually load-bearing — an implementation that ignored both
// would also "round-trip" successfully. This scenario proves the envelope
// actually rejects (a) a flipped ciphertext byte and (b) a mismatched
// context-info string, which is what stops tampering and cross-session
// replay respectively.
func TestScenario_HPKETamperedCiphertextAndWrongInfoRejected(t *testing.T) {
	enclaveKeys, err := keys.Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	browserPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate browser ephemeral key: %v", err)
	}
	browserPubBytes := browserPriv.PublicKey().Bytes()
	info := hpke.ContextInfo(enclaveKeys.HPKEPubBytes(), browserPubBytes)
	aad := []byte("aad")
	plaintext := []byte("secret job metadata")

	seal, err := hpke.SealToBrowser(enclaveKeys.HPKEPubBytes(), info, aad, plaintext)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}

	t.Run("tampered ciphertext", func(t *testing.T) {
		tampered := append([]byte(nil), seal.Ciphertext...)
		tampered[len(tampered)-1] ^= 0xFF
		if _, err := hpke.OpenFromBrowser(enclaveKeys.HPKEPriv, seal.Enc, info, aad, tampered); err == nil {
			t.Fatal("expected an error opening a tampered ciphertext")
		}
	})

	t.Run("wrong context info", func(t *testing.T) {
		wrongInfo := append([]byte(nil), info...)
		wrongInfo[0] ^= 0xFF
		if _, err := hpke.OpenFromBrowser(enclaveKeys.HPKEPriv, seal.Enc, wrongInfo, aad, seal.Ciphertext); err == nil {
			t.Fatal("expected an error opening with mismatched context info")
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 4 — config.FromEnv: defaults and operator overrides
// ═════════════════════════════════════════════════════════════════════════
//
// Why: this had no dedicated test file yet. FromEnv is the single source of
// truth for every runtime knob (rotation cadence, provisioning attempts,
// dispatch timeouts) and the Dockerfile's LABEL allow_env_override list is
// only meaningful if the parsing actually respects operator-supplied
// values while falling back sanely when they're absent.
func TestScenario_ConfigFromEnvDefaultsAndOverrides(t *testing.T) {
	relevantKeys := []string{
		"LISTEN_ADDR", "RATLS_SERVER_AUDIENCE", "MAX_GPU_PROVISION_ATTEMPTS",
		"GPU_CS_INSTANCE", "GPU_CS_ZONE", "CALLBACK_AUDIENCE",
	}

	t.Run("defaults when unset", func(t *testing.T) {
		for _, k := range relevantKeys {
			t.Setenv(k, "") // getEnv treats "" the same as unset
		}
		cfg := config.FromEnv()
		if cfg.ListenAddr != ":8443" {
			t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":8443")
		}
		if cfg.ServerAudience != "ratls-browser" {
			t.Errorf("ServerAudience = %q, want %q", cfg.ServerAudience, "ratls-browser")
		}
		if cfg.MaxGPUAttempts != 3 {
			t.Errorf("MaxGPUAttempts = %d, want 3", cfg.MaxGPUAttempts)
		}
		if cfg.GPU.Instance != "gpu-cs-tdx-h100" {
			t.Errorf("GPU.Instance = %q, want %q", cfg.GPU.Instance, "gpu-cs-tdx-h100")
		}
		if cfg.GPU.Zone != "us-central1-a" {
			t.Errorf("GPU.Zone = %q, want %q", cfg.GPU.Zone, "us-central1-a")
		}
		if cfg.CallbackAudience != "tanuh-buffer-callback" {
			t.Errorf("CallbackAudience = %q, want %q", cfg.CallbackAudience, "tanuh-buffer-callback")
		}
	})

	t.Run("operator overrides applied", func(t *testing.T) {
		t.Setenv("LISTEN_ADDR", ":9443")
		t.Setenv("MAX_GPU_PROVISION_ATTEMPTS", "5")
		t.Setenv("GPU_CS_INSTANCE", "custom-gpu-vm")

		cfg := config.FromEnv()
		if cfg.ListenAddr != ":9443" {
			t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":9443")
		}
		if cfg.MaxGPUAttempts != 5 {
			t.Errorf("MaxGPUAttempts = %d, want 5", cfg.MaxGPUAttempts)
		}
		if cfg.GPU.Instance != "custom-gpu-vm" {
			t.Errorf("GPU.Instance = %q, want %q", cfg.GPU.Instance, "custom-gpu-vm")
		}
	})
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 5 — config.Target derived helpers and BufferDir path composition
// ═════════════════════════════════════════════════════════════════════════
//
// Why: Configured() gates whether provision.Engine will even attempt a
// target, and HealthURL() is what the scheduler polls — both are small but
// safety-critical (an unconfigured target must never look "ready").
func TestScenario_ConfigTargetHelpers(t *testing.T) {
	unconfigured := config.Target{}
	if unconfigured.Configured() {
		t.Error("zero-value Target reports Configured() == true")
	}
	if unconfigured.HealthURL() != "" {
		t.Errorf("HealthURL() on an empty target = %q, want empty string", unconfigured.HealthURL())
	}

	configured := config.Target{Addr: "10.0.0.5:443", ImageDigest: "sha256:abc"}
	if !configured.Configured() {
		t.Error("target with Addr and ImageDigest set reports Configured() == false")
	}
	wantURL := "https://10.0.0.5:443/healthz"
	if got := configured.HealthURL(); got != wantURL {
		t.Errorf("HealthURL() = %q, want %q", got, wantURL)
	}

	cfg := config.Config{BaseDir: "/custom"}
	wantDir := filepath.Join("/custom", "cvm_workflow", "buffer")
	if got := cfg.BufferDir(); got != wantDir {
		t.Errorf("BufferDir() = %q, want %q", got, wantDir)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 6 — full happy-path job lifecycle end to end
// ═════════════════════════════════════════════════════════════════════════
//
// Why: this is the story the whole system exists to tell — a job walks
// pending_upload → queued → dispatched → complete, and every store method
// that a real submit/upload/scheduler/callback cycle would call is
// exercised in the order production actually calls them.
func TestScenario_JobFullHappyPathLifecycle(t *testing.T) {
	store, err := jobs.Open(t.TempDir())
	if err != nil {
		t.Fatalf("jobs.Open: %v", err)
	}

	modelBytes := []byte("model-bytes")
	weightsBytes := []byte("weights-bytes")
	job, err := store.Create(jobs.NewJobRequest{
		DatasetID:     1,
		ModelSHA256:   sysSha256Hex(modelBytes),
		WeightsSHA256: sysSha256Hex(weightsBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if job.Status != jobs.StatusPendingUpload {
		t.Fatalf("initial status = %q, want %q", job.Status, jobs.StatusPendingUpload)
	}

	if _, err := store.ReceiveArtifact(job.JobID, jobs.ModelFileName, modelBytes); err != nil {
		t.Fatalf("ReceiveArtifact(model): %v", err)
	}
	queued, err := store.ReceiveArtifact(job.JobID, jobs.WeightsFileName, weightsBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(weights): %v", err)
	}
	if queued.Status != jobs.StatusQueued {
		t.Fatalf("status after both artifacts = %q, want %q", queued.Status, jobs.StatusQueued)
	}

	next, err := store.NextQueued()
	if err != nil {
		t.Fatalf("NextQueued: %v", err)
	}
	if next == nil || next.JobID != job.JobID {
		t.Fatalf("NextQueued = %+v, want job %s", next, job.JobID)
	}

	dispatched, err := store.MarkDispatched(job.JobID, "/outgoing/"+job.JobID+".json", "10.0.0.9:443")
	if err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if dispatched.Status != jobs.StatusDispatched {
		t.Fatalf("status after dispatch = %q, want %q", dispatched.Status, jobs.StatusDispatched)
	}

	completed, err := store.Complete(job.JobID, true, nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if completed.Status != jobs.StatusComplete {
		t.Fatalf("final status = %q, want %q", completed.Status, jobs.StatusComplete)
	}

	final, err := store.Get(job.JobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if final.Status != jobs.StatusComplete {
		t.Fatalf("re-read status = %q, want %q", final.Status, jobs.StatusComplete)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 7 — tampered artifact is rejected fail-closed, end to end
// ═════════════════════════════════════════════════════════════════════════
//
// Why: this is the security-critical counterpart to Scenario 6. If an
// attacker (or a corrupted upload) swaps the model bytes after the browser
// committed to a SHA-256 hash, the system must refuse the artifact, leave
// the job's status unchanged, and — critically — never persist the bad
// bytes to disk where a later stage might pick them up.
func TestScenario_JobTamperedArtifactFailsClosed(t *testing.T) {
	store, err := jobs.Open(t.TempDir())
	if err != nil {
		t.Fatalf("jobs.Open: %v", err)
	}

	realBytes := []byte("the real model the browser hashed")
	job, err := store.Create(jobs.NewJobRequest{
		DatasetID:   1,
		ModelSHA256: sysSha256Hex(realBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := store.ReceiveArtifact(job.JobID, jobs.ModelFileName, []byte("swapped-in bytes")); err == nil {
		t.Fatal("expected SHA-256 mismatch to be rejected")
	}

	reloaded, err := store.Get(job.JobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.Status != jobs.StatusPendingUpload {
		t.Fatalf("status = %q after rejected upload, want unchanged %q", reloaded.Status, jobs.StatusPendingUpload)
	}
	if _, err := store.ArtifactBytes(job.JobID, jobs.ModelFileName); err == nil {
		t.Fatal("tampered artifact bytes were persisted to disk despite the hash mismatch")
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 8 — crash recovery: requeue budget exhausted then failed
// ═════════════════════════════════════════════════════════════════════════
//
// Why: this is the story scheduler.recoverStuckDispatched tells when a
// Processing TEE dies without calling back — bounded retries, then a
// terminal failure, never an infinite loop. It's exercised here purely
// through jobs.Store's public API (Requeue/Fail), mirroring exactly the
// state transitions the scheduler package drives.
func TestScenario_JobCrashRecoveryRequeueThenFail(t *testing.T) {
	store, err := jobs.Open(t.TempDir())
	if err != nil {
		t.Fatalf("jobs.Open: %v", err)
	}
	const maxRequeue = 2
	job := sysQueueJob(t, store)

	for attempt := 1; attempt <= maxRequeue; attempt++ {
		if _, err := store.MarkDispatched(job.JobID, "/outgoing/x.json", "10.0.0.9:443"); err != nil {
			t.Fatalf("MarkDispatched (attempt %d): %v", attempt, err)
		}
		// Simulate the Processing TEE dying silently: no Complete callback
		// arrives, so the scheduler's timeout path requeues instead.
		requeued, err := store.Requeue(job.JobID)
		if err != nil {
			t.Fatalf("Requeue (attempt %d): %v", attempt, err)
		}
		if requeued.RequeueCount != attempt {
			t.Fatalf("RequeueCount after attempt %d = %d, want %d", attempt, requeued.RequeueCount, attempt)
		}
	}

	// Budget exhausted: one more dispatch, still no callback, and the
	// scheduler would now call Fail instead of Requeue.
	if _, err := store.MarkDispatched(job.JobID, "/outgoing/x.json", "10.0.0.9:443"); err != nil {
		t.Fatalf("final MarkDispatched: %v", err)
	}
	failed, err := store.Fail(job.JobID, "requeue_exhausted", map[string]any{
		"error_type":    "DispatchLost",
		"error_message": "no completion callback after 3 dispatches",
	})
	if err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if failed.Status != jobs.StatusError {
		t.Fatalf("final status = %q, want %q", failed.Status, jobs.StatusError)
	}
	if failed.RequeueCount != maxRequeue {
		t.Fatalf("RequeueCount at failure = %d, want %d (unchanged by Fail)", failed.RequeueCount, maxRequeue)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 9 — GPU provisioning fails fast on a quota error, CPU picks up
// ═════════════════════════════════════════════════════════════════════════
//
// Why: this is the provisioning contract that keeps a failed H100 request
// from stalling every job behind a full boot-timeout wait per attempt —
// an *gcp.OpError (quota/stockout) must consume the attempt and move on
// immediately, and once the GPU budget is exhausted the CPU fallback must
// take over and succeed once it reports healthy.
func TestScenario_ProvisionGPUOpErrorFastFailsToHealthyCPU(t *testing.T) {
	cfg := config.Config{
		GPU: config.Target{
			Name: "GPU", Addr: "10.0.0.1:443", ImageDigest: "sha256:gpu",
			Instance: "gpu-vm", Zone: "z", BootTimeout: 30 * time.Second,
		},
		CPU: config.Target{
			Name: "CPU", Addr: "10.0.0.2:443", ImageDigest: "sha256:cpu",
			Instance: "cpu-vm", Zone: "z", BootTimeout: 30 * time.Second,
		},
		MaxGPUAttempts: 2,
		StartCooldown:  45 * time.Second,
		PollInterval:   5 * time.Second,
		VMStopWait:     10 * time.Second,
	}
	compute := &sysFakeCompute{startErr: map[string]error{
		"GPU": &gcp.OpError{Instance: "gpu-vm", Action: "start", Reason: "QUOTA_EXCEEDED"},
	}}
	health := &sysFakeHealth{healthy: map[string]bool{cfg.CPU.HealthURL(): true}}
	clock := &sysFakeClock{now: time.Unix(1_700_000_000, 0)}

	engine := &provision.Engine{
		Cfg:     cfg,
		Compute: compute,
		Health:  health,
		Clock:   clock,
		Persist: func(*jobs.Job) error { return nil },
		Note:    func(string, string) {},
	}
	job := &jobs.Job{JobID: "job-scenario-9"}

	res, err := engine.Provision(context.Background(), job)
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if res == nil || res.Target.Name != "CPU" {
		t.Fatalf("Provision result = %+v, want CPU fallback", res)
	}
	if job.GPUAttempts != cfg.MaxGPUAttempts {
		t.Fatalf("GPUAttempts = %d, want %d (op errors must consume the attempt budget)", job.GPUAttempts, cfg.MaxGPUAttempts)
	}
	if job.ProvisioningTarget != "cpu" {
		t.Fatalf("ProvisioningTarget = %q, want %q", job.ProvisioningTarget, "cpu")
	}
	gpuStarts := 0
	for _, s := range compute.starts {
		if s == "GPU" {
			gpuStarts++
		}
	}
	if gpuStarts != cfg.MaxGPUAttempts {
		t.Fatalf("GPU start calls = %d, want exactly %d (no wasted retries beyond the budget)", gpuStarts, cfg.MaxGPUAttempts)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 10 — server read endpoints reflect real store state end to end
// ═════════════════════════════════════════════════════════════════════════
//
// Why: HandleStatus/HandleQueue/HandleResults are the parts of the HTTP
// layer that don't need the attestation builder, so this scenario proves
// the whole read path — real jobs.Store, real server.New wiring, real
// httptest HTTP round trip — reflects a job's true lifecycle state at each
// stage, including the "results not yet available" contract (results live
// on the external leaderboard, not in this store).
func TestScenario_ServerReadEndpointsReflectStoreStateAcrossFullLifecycle(t *testing.T) {
	store, err := jobs.Open(t.TempDir())
	if err != nil {
		t.Fatalf("jobs.Open: %v", err)
	}
	// Server.builder is nil — safe here because none of the routes hit in
	// this scenario (status/results/queue) ever dereference it.
	srv := server.New(nil, server.AuthConfig{}, store, config.Config{})

	pending, err := store.Create(jobs.NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	completed := sysQueueJob(t, store)
	if _, err := store.MarkDispatched(completed.JobID, "/outgoing/x.json", "10.0.0.9:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if _, err := store.Complete(completed.JobID, true, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// 1. Status of the still-pending job.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/status/"+pending.JobID, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("status(pending) code = %d, want 200", rec.Code)
	}

	// 2. Results for the completed job, BEFORE any results.json exists —
	//    must be 404, not a false-positive 200.
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/results/"+completed.JobID, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("results(completed, no file) code = %d, want 404 (body=%s)", rec.Code, rec.Body.String())
	}

	// 3. Now write a results.json directly (standing in for whatever
	//    process would eventually populate it) and confirm passthrough.
	raw := []byte(`{"metrics":{"accuracy":0.91}}`)
	resultsPath := store.ResultsPath(completed.JobID)
	if err := os.MkdirAll(filepath.Dir(resultsPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(resultsPath, raw, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/results/"+completed.JobID, nil))
	if rec.Code != http.StatusOK || rec.Body.String() != string(raw) {
		t.Fatalf("results(completed, with file) = %d %q, want 200 %q", rec.Code, rec.Body.String(), raw)
	}

	// 4. Queue view, gated behind an org_admin-role token, must list both
	//    jobs while only counting the queued/dispatched one... here neither
	//    is queued any more (one pending, one complete), so queued_count
	//    must be 0 even though 2 jobs exist.
	token := sysBuildRoleJWT(t, []string{"org_admin"})
	req := httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("queue code = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode queue body: %v", err)
	}
	if body["queued_count"] != float64(0) {
		t.Errorf("queued_count = %v, want 0 (no job is currently queued)", body["queued_count"])
	}
	allJobs, _ := body["jobs"].([]any)
	if len(allJobs) != 2 {
		t.Errorf("jobs listed = %d, want 2", len(allJobs))
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 11 — /v1/queue RBAC holds even with Keycloak signature checking off
// ═════════════════════════════════════════════════════════════════════════
//
// Why: requireRole is wired around /v1/queue inside server.New()
// unconditionally — it is not gated behind AuthConfig at all. This is a
// defense-in-depth property worth pinning down explicitly: even in a
// deployment (or a misconfiguration) where Keycloak signature verification
// is off, the org_admin role check on this endpoint still applies.
func TestScenario_ServerQueueRBACHoldsIndependentOfKeycloakConfig(t *testing.T) {
	store, err := jobs.Open(t.TempDir())
	if err != nil {
		t.Fatalf("jobs.Open: %v", err)
	}
	srv := server.New(nil, server.AuthConfig{}, store, config.Config{}) // Keycloak verification OFF

	// No token at all.
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/queue", nil))
	if rec.Code != http.StatusForbidden {
		t.Errorf("no token: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// Token present but missing the required role.
	req := httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
	req.Header.Set("Authorization", "Bearer "+sysBuildRoleJWT(t, []string{"viewer"}))
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("wrong role: status = %d, want %d", rec.Code, http.StatusForbidden)
	}

	// Token with the required role succeeds.
	req = httptest.NewRequest(http.MethodGet, "/v1/queue", nil)
	req.Header.Set("Authorization", "Bearer "+sysBuildRoleJWT(t, []string{"org_admin"}))
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("org_admin role: status = %d, want %d", rec.Code, http.StatusOK)
	}
}

// ═════════════════════════════════════════════════════════════════════════
// Scenario 12 — RA-TLS EKM channel-binding nonce format contract
// ═════════════════════════════════════════════════════════════════════════
//
// Why: internal/dispatch is the Buffer TEE's RA-TLS client for outbound
// connections to the Processing TEE. The channel-binding nonce
// (base64url(sha256(EKM))) must be exactly 43 characters (GCP's OIDC nonce
// length limits are 10–74 chars) and must decode back to exactly 32 bytes,
// or the whole RA-TLS handshake verification in dispatch.Connect silently
// breaks. This is a pure-function contract check with no network involved.
func TestScenario_DispatchEKMNonceRoundTrip(t *testing.T) {
	ekm := make([]byte, dispatch.EKMLength)
	for i := range ekm {
		ekm[i] = byte(i)
	}
	nonce := dispatch.EKMNonce(ekm)
	if len(nonce) != 43 {
		t.Fatalf("nonce length = %d, want 43", len(nonce))
	}
	decoded, err := dispatch.Base64DecodeURLNoPad(nonce)
	if err != nil {
		t.Fatalf("decode nonce: %v", err)
	}
	if len(decoded) != 32 {
		t.Fatalf("decoded nonce length = %d, want 32", len(decoded))
	}
	if again := dispatch.EKMNonce(ekm); again != nonce {
		t.Fatalf("EKMNonce is not deterministic: %q vs %q", nonce, again)
	}

	otherEKM := make([]byte, dispatch.EKMLength)
	for i := range otherEKM {
		otherEKM[i] = byte(255 - i)
	}
	if dispatch.EKMNonce(otherEKM) == nonce {
		t.Fatal("two different EKMs produced the same nonce")
	}
}