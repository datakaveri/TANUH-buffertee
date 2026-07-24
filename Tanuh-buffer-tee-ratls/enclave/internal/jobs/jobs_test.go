package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ── test helpers ────────────────────────────────────────────────────────────

// newStore returns a Store rooted at a fresh temp directory, isolated per test.
func newStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return s
}

// sha256Hex returns the lowercase hex SHA-256 digest of data.
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// createJob is a shortcut for the common case: a valid dataset_id=1 job
// with no preprocessing commitment.
func createJob(t *testing.T, s *Store) *Job {
	t.Helper()
	job, err := s.Create(NewJobRequest{DatasetID: 1, ModelSHA256: "", WeightsSHA256: ""})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return job
}

// queueJob creates a job and uploads matching model+weights artifacts so it
// naturally transitions to StatusQueued, then returns the queued job.
func queueJob(t *testing.T, s *Store) *Job {
	t.Helper()
	modelBytes := []byte("model-bytes")
	weightsBytes := []byte("weights-bytes")
	job, err := s.Create(NewJobRequest{
		DatasetID:     1,
		ModelSHA256:   sha256Hex(modelBytes),
		WeightsSHA256: sha256Hex(weightsBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.ReceiveArtifact(job.JobID, ModelFileName, modelBytes); err != nil {
		t.Fatalf("ReceiveArtifact(model): %v", err)
	}
	got, err := s.ReceiveArtifact(job.JobID, WeightsFileName, weightsBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(weights): %v", err)
	}
	if got.Status != StatusQueued {
		t.Fatalf("job status = %q, want %q", got.Status, StatusQueued)
	}
	return got
}

// ── Open ─────────────────────────────────────────────────────────────────────

func TestOpenCreatesDirectoryLayout(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root); err != nil {
		t.Fatalf("Open: %v", err)
	}
	for _, d := range []string{
		root,
		filepath.Join(root, "jobs"),
		filepath.Join(root, "outgoing"),
		filepath.Join(root, "runtime"),
		filepath.Join(root, "shared_artifacts"),
	} {
		info, err := os.Stat(d)
		if err != nil {
			t.Fatalf("expected dir %s to exist: %v", d, err)
		}
		if !info.IsDir() {
			t.Fatalf("%s exists but is not a directory", d)
		}
	}
}

func TestOpenIsIdempotent(t *testing.T) {
	root := t.TempDir()
	if _, err := Open(root); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Re-opening the same root (e.g. process restart) must not error.
	if _, err := Open(root); err != nil {
		t.Fatalf("second Open: %v", err)
	}
}

// ── Create ───────────────────────────────────────────────────────────────────

func TestCreate_ValidatesDatasetID(t *testing.T) {
	s := newStore(t)
	cases := []struct {
		name      string
		datasetID int
		wantErr   bool
	}{
		{"below range", 0, true},
		{"above range", 4, true},
		{"valid 1", 1, false},
		{"valid 2", 2, false},
		{"valid 3", 3, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := s.Create(NewJobRequest{DatasetID: tc.datasetID})
			if tc.wantErr && err == nil {
				t.Fatalf("dataset_id=%d: expected error, got nil", tc.datasetID)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("dataset_id=%d: unexpected error: %v", tc.datasetID, err)
			}
		})
	}
}

func TestCreate_Defaults(t *testing.T) {
	s := newStore(t)
	job, err := s.Create(NewJobRequest{DatasetID: 2})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if job.Status != StatusPendingUpload {
		t.Errorf("Status = %q, want %q", job.Status, StatusPendingUpload)
	}
	if job.SubmittedBy != "unknown" {
		t.Errorf("SubmittedBy = %q, want %q (default)", job.SubmittedBy, "unknown")
	}
	if job.Hyperparameters == nil {
		t.Error("Hyperparameters should default to an empty map, not nil")
	}
	if job.ModelFile != ModelFileName || job.WeightsFile != WeightsFileName {
		t.Errorf("ModelFile/WeightsFile not set to package constants: %q / %q", job.ModelFile, job.WeightsFile)
	}
	if job.JobID == "" {
		t.Error("JobID should not be empty")
	}
	// The job must actually be persisted and re-readable.
	reloaded, err := s.Get(job.JobID)
	if err != nil {
		t.Fatalf("Get after Create: %v", err)
	}
	if reloaded.JobID != job.JobID {
		t.Errorf("reloaded JobID = %q, want %q", reloaded.JobID, job.JobID)
	}
}

func TestCreate_PreservesSubmittedByAndHyperparameters(t *testing.T) {
	s := newStore(t)
	hp := map[string]any{"lr": 0.01}
	job, err := s.Create(NewJobRequest{
		DatasetID:       1,
		SubmittedBy:     "alice",
		Hyperparameters: hp,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if job.SubmittedBy != "alice" {
		t.Errorf("SubmittedBy = %q, want %q", job.SubmittedBy, "alice")
	}
	if job.Hyperparameters["lr"] != 0.01 {
		t.Errorf("Hyperparameters not preserved: %+v", job.Hyperparameters)
	}
}

func TestCreate_GeneratesUniqueJobIDs(t *testing.T) {
	s := newStore(t)
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		job := createJob(t, s)
		if seen[job.JobID] {
			t.Fatalf("duplicate job id generated: %s", job.JobID)
		}
		seen[job.JobID] = true
	}
}

// ── ReceiveArtifact ──────────────────────────────────────────────────────────

func TestReceiveArtifact_UnknownArtifactName(t *testing.T) {
	s := newStore(t)
	job := createJob(t, s)
	if _, err := s.ReceiveArtifact(job.JobID, "not-a-real-file", []byte("x")); err == nil {
		t.Fatal("expected error for unknown artifact name")
	}
}

func TestReceiveArtifact_UnknownJobID(t *testing.T) {
	s := newStore(t)
	if _, err := s.ReceiveArtifact("job-doesnotexist", ModelFileName, []byte("x")); err == nil {
		t.Fatal("expected error for unknown job_id")
	}
}

func TestReceiveArtifact_WrongStatus(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s) // already queued, not pending_upload
	if _, err := s.ReceiveArtifact(job.JobID, ModelFileName, []byte("x")); err == nil {
		t.Fatal("expected error uploading to a job that is not pending_upload")
	}
}

func TestReceiveArtifact_SHA256MismatchFailsClosed(t *testing.T) {
	s := newStore(t)
	modelBytes := []byte("real model bytes")
	job, err := s.Create(NewJobRequest{
		DatasetID:   1,
		ModelSHA256: sha256Hex(modelBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	_, err = s.ReceiveArtifact(job.JobID, ModelFileName, []byte("tampered bytes"))
	if err == nil {
		t.Fatal("expected SHA-256 mismatch error")
	}

	// Fail-closed: the artifact must NOT be written to disk on mismatch.
	if _, statErr := os.Stat(filepath.Join(job.ArtifactDir, ModelFileName)); statErr == nil {
		t.Fatal("artifact file was written despite SHA-256 mismatch")
	}

	// And the job record must not have advanced past pending_upload.
	reloaded, err := s.Get(job.JobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.Status != StatusPendingUpload {
		t.Errorf("Status = %q after failed upload, want %q", reloaded.Status, StatusPendingUpload)
	}
}

func TestReceiveArtifact_CaseInsensitiveHashComparison(t *testing.T) {
	s := newStore(t)
	modelBytes := []byte("model bytes")
	job, err := s.Create(NewJobRequest{
		DatasetID:   1,
		ModelSHA256: sha256HexUpper(modelBytes), // committed as uppercase hex
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.ReceiveArtifact(job.JobID, ModelFileName, modelBytes); err != nil {
		t.Fatalf("expected uppercase-hex commitment to still match: %v", err)
	}
}

func TestReceiveArtifact_NoCommitmentSkipsHashCheck(t *testing.T) {
	s := newStore(t)
	// No ModelSHA256 given at submit time -> "" -> ReceiveArtifact must not
	// enforce a hash check for this artifact.
	job, err := s.Create(NewJobRequest{DatasetID: 1})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.ReceiveArtifact(job.JobID, ModelFileName, []byte("anything at all")); err != nil {
		t.Fatalf("expected no error when no SHA256 was committed: %v", err)
	}
}

func TestReceiveArtifact_QueuesOnlyAfterModelAndWeights(t *testing.T) {
	s := newStore(t)
	modelBytes := []byte("model")
	weightsBytes := []byte("weights")
	job, err := s.Create(NewJobRequest{
		DatasetID:     1,
		ModelSHA256:   sha256Hex(modelBytes),
		WeightsSHA256: sha256Hex(weightsBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	afterModel, err := s.ReceiveArtifact(job.JobID, ModelFileName, modelBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(model): %v", err)
	}
	if afterModel.Status != StatusPendingUpload {
		t.Fatalf("Status after model only = %q, want still %q", afterModel.Status, StatusPendingUpload)
	}

	afterWeights, err := s.ReceiveArtifact(job.JobID, WeightsFileName, weightsBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(weights): %v", err)
	}
	if afterWeights.Status != StatusQueued {
		t.Fatalf("Status after model+weights = %q, want %q", afterWeights.Status, StatusQueued)
	}

	// It must also have been appended to queue.json.
	_, queued, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsString(queued, job.JobID) {
		t.Fatalf("queue = %v, want it to contain %s", queued, job.JobID)
	}
}

func TestReceiveArtifact_RequiresPreprocessingWhenCommitted(t *testing.T) {
	s := newStore(t)
	modelBytes := []byte("model")
	weightsBytes := []byte("weights")
	ppBytes := []byte("def preprocess(): pass")
	job, err := s.Create(NewJobRequest{
		DatasetID:        2,
		ModelSHA256:      sha256Hex(modelBytes),
		WeightsSHA256:    sha256Hex(weightsBytes),
		PreprocessingSHA: sha256Hex(ppBytes),
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if _, err := s.ReceiveArtifact(job.JobID, ModelFileName, modelBytes); err != nil {
		t.Fatalf("ReceiveArtifact(model): %v", err)
	}
	afterWeights, err := s.ReceiveArtifact(job.JobID, WeightsFileName, weightsBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(weights): %v", err)
	}
	// Model + weights alone are NOT enough when a preprocessing hash was committed.
	if afterWeights.Status != StatusPendingUpload {
		t.Fatalf("Status = %q after model+weights (preprocessing still owed), want %q",
			afterWeights.Status, StatusPendingUpload)
	}

	afterPP, err := s.ReceiveArtifact(job.JobID, PreprocessingFileName, ppBytes)
	if err != nil {
		t.Fatalf("ReceiveArtifact(preprocessing): %v", err)
	}
	if afterPP.Status != StatusQueued {
		t.Fatalf("Status after all three artifacts = %q, want %q", afterPP.Status, StatusQueued)
	}
}

func TestReceiveArtifact_DoesNotDoubleQueue(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	_, queued, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	count := 0
	for _, id := range queued {
		if id == job.JobID {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("job appears %d times in queue, want exactly 1", count)
	}
}

// ── ArtifactBytes ────────────────────────────────────────────────────────────

func TestArtifactBytes_RoundTrip(t *testing.T) {
	s := newStore(t)
	modelBytes := []byte("model-content")
	job, err := s.Create(NewJobRequest{DatasetID: 1, ModelSHA256: sha256Hex(modelBytes)})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := s.ReceiveArtifact(job.JobID, ModelFileName, modelBytes); err != nil {
		t.Fatalf("ReceiveArtifact: %v", err)
	}
	got, err := s.ArtifactBytes(job.JobID, ModelFileName)
	if err != nil {
		t.Fatalf("ArtifactBytes: %v", err)
	}
	if string(got) != string(modelBytes) {
		t.Errorf("ArtifactBytes = %q, want %q", got, modelBytes)
	}
}

func TestArtifactBytes_UnknownArtifactName(t *testing.T) {
	s := newStore(t)
	job := createJob(t, s)
	if _, err := s.ArtifactBytes(job.JobID, "bogus.bin"); err == nil {
		t.Fatal("expected error for unknown artifact name")
	}
}

func TestArtifactBytes_MissingFile(t *testing.T) {
	s := newStore(t)
	job := createJob(t, s)
	// Valid artifact name, but nothing has been uploaded yet.
	if _, err := s.ArtifactBytes(job.JobID, ModelFileName); err == nil {
		t.Fatal("expected error reading an artifact that was never uploaded")
	}
}

// ── Get / List ───────────────────────────────────────────────────────────────

func TestGet_UnknownJobID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Get("job-nope"); err == nil {
		t.Fatal("expected error for unknown job_id")
	}
}

func TestList_ReturnsAllJobsAndQueue(t *testing.T) {
	s := newStore(t)
	pending := createJob(t, s)
	queued := queueJob(t, s)

	all, queuedIDs, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("len(all) = %d, want 2", len(all))
	}
	ids := map[string]bool{}
	for _, j := range all {
		ids[j.JobID] = true
	}
	if !ids[pending.JobID] || !ids[queued.JobID] {
		t.Fatalf("List missing expected jobs: %+v", ids)
	}
	if len(queuedIDs) != 1 || queuedIDs[0] != queued.JobID {
		t.Fatalf("queued ids = %v, want [%s]", queuedIDs, queued.JobID)
	}
}

func TestList_EmptyStore(t *testing.T) {
	s := newStore(t)
	all, queued, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("len(all) = %d, want 0", len(all))
	}
	if len(queued) != 0 {
		t.Fatalf("len(queued) = %d, want 0", len(queued))
	}
}

// ── Save ─────────────────────────────────────────────────────────────────────

func TestSave_PersistsMutationsAndBumpsTimestamp(t *testing.T) {
	s := newStore(t)
	job := createJob(t, s)
	job.UpdatedAtUnix = 111 // will be overwritten by Save
	job.GPUAttempts = 2
	job.ProvisioningTarget = "gpu"

	if err := s.Save(job); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if job.UpdatedAtUnix == 111 {
		t.Error("Save should overwrite UpdatedAtUnix with the current time")
	}

	reloaded, err := s.Get(job.JobID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if reloaded.GPUAttempts != 2 || reloaded.ProvisioningTarget != "gpu" {
		t.Fatalf("mutations not persisted: %+v", reloaded)
	}
}

// ── NextQueued ───────────────────────────────────────────────────────────────

func TestNextQueued_EmptyQueue(t *testing.T) {
	s := newStore(t)
	job, err := s.NextQueued()
	if err != nil {
		t.Fatalf("NextQueued: %v", err)
	}
	if job != nil {
		t.Fatalf("expected nil job on empty queue, got %+v", job)
	}
}

func TestNextQueued_ReturnsFIFOOrderAndSkipsNonQueued(t *testing.T) {
	s := newStore(t)
	first := queueJob(t, s)
	second := queueJob(t, s)

	// Manually flip `first` out of queued status without removing it from
	// queue.json, simulating a stale/partial queue entry.
	first.Status = StatusError
	if err := s.Save(first); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.NextQueued()
	if err != nil {
		t.Fatalf("NextQueued: %v", err)
	}
	if got == nil || got.JobID != second.JobID {
		t.Fatalf("NextQueued = %+v, want job %s (first skipped as non-queued)", got, second.JobID)
	}
}

// ── AnyDispatched / Dispatched ───────────────────────────────────────────────

func TestAnyDispatched_FalseWhenNoneDispatched(t *testing.T) {
	s := newStore(t)
	queueJob(t, s)
	any, err := s.AnyDispatched()
	if err != nil {
		t.Fatalf("AnyDispatched: %v", err)
	}
	if any {
		t.Error("AnyDispatched = true, want false (nothing dispatched yet)")
	}
}

func TestAnyDispatchedAndDispatched_TrueAfterMarkDispatched(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/tmp/payload.json", "10.0.0.5:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	any, err := s.AnyDispatched()
	if err != nil {
		t.Fatalf("AnyDispatched: %v", err)
	}
	if !any {
		t.Error("AnyDispatched = false, want true")
	}

	dispatched, err := s.Dispatched()
	if err != nil {
		t.Fatalf("Dispatched: %v", err)
	}
	if len(dispatched) != 1 || dispatched[0].JobID != job.JobID {
		t.Fatalf("Dispatched = %+v, want [%s]", dispatched, job.JobID)
	}
}

// ── MarkDispatched ───────────────────────────────────────────────────────────

func TestMarkDispatched_UpdatesFieldsAndRemovesFromQueue(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)

	got, err := s.MarkDispatched(job.JobID, "/outgoing/x.json", "10.0.0.7:443")
	if err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if got.Status != StatusDispatched {
		t.Errorf("Status = %q, want %q", got.Status, StatusDispatched)
	}
	if got.AssignedTEE != "10.0.0.7:443" {
		t.Errorf("AssignedTEE = %q, want %q", got.AssignedTEE, "10.0.0.7:443")
	}
	if got.Delivery == nil || got.Delivery.PayloadPath != "/outgoing/x.json" {
		t.Errorf("Delivery = %+v, want PayloadPath /outgoing/x.json", got.Delivery)
	}
	if got.DispatchedAtUnix == 0 {
		t.Error("DispatchedAtUnix should be set")
	}

	_, queued, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if containsString(queued, job.JobID) {
		t.Fatalf("job %s still in queue after MarkDispatched: %v", job.JobID, queued)
	}
}

func TestMarkDispatched_UnknownJobID(t *testing.T) {
	s := newStore(t)
	if _, err := s.MarkDispatched("job-ghost", "/x", "1.2.3.4:443"); err == nil {
		t.Fatal("expected error for unknown job_id")
	}
}

// ── Complete ─────────────────────────────────────────────────────────────────

func TestComplete_Succeeded(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	got, err := s.Complete(job.JobID, true, nil)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Status != StatusComplete {
		t.Errorf("Status = %q, want %q", got.Status, StatusComplete)
	}
	if got.CompletionSource != "processing_tee_callback" {
		t.Errorf("CompletionSource = %q, want %q", got.CompletionSource, "processing_tee_callback")
	}
	if got.CompletedAtUnix == 0 {
		t.Error("CompletedAtUnix should be set")
	}
}

func TestComplete_Failed(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	errInfo := map[string]any{"error_type": "EvalCrashed"}
	got, err := s.Complete(job.JobID, false, errInfo)
	if err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if got.Status != StatusError {
		t.Errorf("Status = %q, want %q", got.Status, StatusError)
	}
	if got.CompletionError["error_type"] != "EvalCrashed" {
		t.Errorf("CompletionError = %+v, want error_type=EvalCrashed", got.CompletionError)
	}
}

func TestComplete_RejectsNonDispatchedJob(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s) // status=queued, never dispatched

	got, err := s.Complete(job.JobID, true, nil)
	if err == nil {
		t.Fatal("expected error completing a job that is not dispatched")
	}
	// The job record is still returned (caller decides how to respond, e.g. 409).
	if got == nil || got.Status != StatusQueued {
		t.Fatalf("job status should be unchanged (%v), got %+v", err, got)
	}
}

func TestComplete_UnknownJobID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Complete("job-ghost", true, nil); err == nil {
		t.Fatal("expected error for unknown job_id")
	}
}

func TestComplete_RemovesFromQueueDefensively(t *testing.T) {
	// Belt-and-suspenders: even though MarkDispatched already removed the
	// job from the queue, Complete calls queueRemoveLocked again. Confirm
	// this is a no-op / does not error and the queue stays clean.
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if _, err := s.Complete(job.JobID, true, nil); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	_, queued, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(queued) != 0 {
		t.Fatalf("queue = %v, want empty after completion", queued)
	}
}

// ── Requeue ──────────────────────────────────────────────────────────────────

func TestRequeue_ResetsAttemptsAndReturnsToQueue(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	// Simulate GPU attempts burned during the failed dispatch.
	job.GPUAttempts = 3
	job.ProvisioningTarget = "gpu"
	if err := s.Save(job); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := s.Requeue(job.JobID)
	if err != nil {
		t.Fatalf("Requeue: %v", err)
	}
	if got.Status != StatusQueued {
		t.Errorf("Status = %q, want %q", got.Status, StatusQueued)
	}
	if got.GPUAttempts != 0 {
		t.Errorf("GPUAttempts = %d, want reset to 0", got.GPUAttempts)
	}
	if got.AssignedTEE != "" {
		t.Errorf("AssignedTEE = %q, want cleared", got.AssignedTEE)
	}
	if got.DispatchedAtUnix != 0 {
		t.Errorf("DispatchedAtUnix = %d, want reset to 0", got.DispatchedAtUnix)
	}
	if got.RequeueCount != 1 {
		t.Errorf("RequeueCount = %d, want 1", got.RequeueCount)
	}

	_, queued, err := s.List()
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if !containsString(queued, job.JobID) {
		t.Fatalf("job not back in queue: %v", queued)
	}
}

func TestRequeue_IncrementsAcrossMultipleCalls(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}
	if _, err := s.Requeue(job.JobID); err != nil {
		t.Fatalf("Requeue #1: %v", err)
	}
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched #2: %v", err)
	}
	got, err := s.Requeue(job.JobID)
	if err != nil {
		t.Fatalf("Requeue #2: %v", err)
	}
	if got.RequeueCount != 2 {
		t.Errorf("RequeueCount = %d, want 2", got.RequeueCount)
	}
}

func TestRequeue_UnknownJobID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Requeue("job-ghost"); err == nil {
		t.Fatal("expected error for unknown job_id")
	}
}

// ── Fail ─────────────────────────────────────────────────────────────────────

func TestFail_SetsErrorStatusAndRemovesFromQueue(t *testing.T) {
	s := newStore(t)
	job := queueJob(t, s)
	if _, err := s.MarkDispatched(job.JobID, "/x", "1.2.3.4:443"); err != nil {
		t.Fatalf("MarkDispatched: %v", err)
	}

	got, err := s.Fail(job.JobID, "requeue_exhausted", map[string]any{"error_type": "DispatchLost"})
	if err != nil {
		t.Fatalf("Fail: %v", err)
	}
	if got.Status != StatusError {
		t.Errorf("Status = %q, want %q", got.Status, StatusError)
	}
	if got.CompletionSource != "requeue_exhausted" {
		t.Errorf("CompletionSource = %q, want %q", got.CompletionSource, "requeue_exhausted")
	}
	if got.CompletedAtUnix == 0 {
		t.Error("CompletedAtUnix should be set")
	}
}

func TestFail_UnknownJobID(t *testing.T) {
	s := newStore(t)
	if _, err := s.Fail("job-ghost", "src", nil); err == nil {
		t.Fatal("expected error for unknown job_id")
	}
}

// ── CleanupOld ───────────────────────────────────────────────────────────────

func TestCleanupOld_RemovesOnlyOldTerminalJobs(t *testing.T) {
	s := newStore(t)
	retention := time.Hour

	// old + terminal -> should be removed
	oldDone := createJob(t, s)
	oldDone.Status = StatusComplete
	oldDone.UpdatedAtUnix = time.Now().Add(-2 * time.Hour).Unix()
	if err := s.Save(oldDone); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Save() stamps UpdatedAtUnix to now, so set it again directly after Save
	// by writing the record ourselves to simulate genuinely old state.
	forceUpdatedAt(t, s, oldDone.JobID, time.Now().Add(-2*time.Hour).Unix())

	// young + terminal -> should survive
	youngDone := createJob(t, s)
	youngDone.Status = StatusComplete
	if err := s.Save(youngDone); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// old + non-terminal (still queued) -> should survive regardless of age
	oldQueued := queueJob(t, s)
	forceUpdatedAt(t, s, oldQueued.JobID, time.Now().Add(-2*time.Hour).Unix())

	removed := s.CleanupOld(retention)

	if !containsString(removed, oldDone.JobID) {
		t.Errorf("removed = %v, want it to include old terminal job %s", removed, oldDone.JobID)
	}
	if containsString(removed, youngDone.JobID) {
		t.Errorf("removed = %v, should not include young terminal job %s", removed, youngDone.JobID)
	}
	if containsString(removed, oldQueued.JobID) {
		t.Errorf("removed = %v, should not include non-terminal job %s", removed, oldQueued.JobID)
	}

	// The old terminal job's directory must actually be gone.
	if _, err := s.Get(oldDone.JobID); err == nil {
		t.Error("old terminal job record still readable after CleanupOld")
	}
	// The survivors must still be readable.
	if _, err := s.Get(youngDone.JobID); err != nil {
		t.Errorf("young terminal job should survive cleanup: %v", err)
	}
	if _, err := s.Get(oldQueued.JobID); err != nil {
		t.Errorf("old non-terminal job should survive cleanup: %v", err)
	}
}

func TestCleanupOld_NothingToRemove(t *testing.T) {
	s := newStore(t)
	createJob(t, s)
	removed := s.CleanupOld(time.Hour)
	if len(removed) != 0 {
		t.Fatalf("removed = %v, want empty", removed)
	}
}

// ── StalledQueued ────────────────────────────────────────────────────────────

func TestStalledQueued_ReturnsOnlyOldQueuedJobs(t *testing.T) {
	s := newStore(t)
	fresh := queueJob(t, s)

	stale := queueJob(t, s)
	forceSubmittedAt(t, s, stale.JobID, time.Now().Add(-10*time.Minute).Unix())

	stalled := s.StalledQueued(5 * time.Minute)
	if !containsString(stalled, stale.JobID) {
		t.Errorf("stalled = %v, want it to include %s", stalled, stale.JobID)
	}
	if containsString(stalled, fresh.JobID) {
		t.Errorf("stalled = %v, should not include fresh job %s", stalled, fresh.JobID)
	}
}

func TestStalledQueued_EmptyWhenNothingQueued(t *testing.T) {
	s := newStore(t)
	stalled := s.StalledQueued(time.Second)
	if len(stalled) != 0 {
		t.Fatalf("stalled = %v, want empty", stalled)
	}
}

// ── DispatchState ────────────────────────────────────────────────────────────

func TestDispatchState_UpdateMergesRatherThanOverwrites(t *testing.T) {
	s := newStore(t)
	s.UpdateDispatchState(map[string]any{"last_dispatch_status": "checking_vm_health", "a": 1.0})
	s.UpdateDispatchState(map[string]any{"last_dispatch_status": "dispatched"}) // update one key

	state := s.DispatchState()
	if state["last_dispatch_status"] != "dispatched" {
		t.Errorf("last_dispatch_status = %v, want %q", state["last_dispatch_status"], "dispatched")
	}
	if state["a"] != 1.0 {
		t.Errorf("key 'a' should be preserved across the second update, got %v", state["a"])
	}
}

func TestDispatchState_EmptyBeforeAnyUpdate(t *testing.T) {
	s := newStore(t)
	state := s.DispatchState()
	if len(state) != 0 {
		t.Fatalf("state = %+v, want empty map before any UpdateDispatchState call", state)
	}
}

// ── Path helpers ─────────────────────────────────────────────────────────────

func TestOutgoingPayloadPathAndResultsPath(t *testing.T) {
	s := newStore(t)
	job := createJob(t, s)

	wantOutgoing := filepath.Join(s.root, "outgoing", job.JobID+"-secure-dispatch.json")
	if got := s.OutgoingPayloadPath(job.JobID); got != wantOutgoing {
		t.Errorf("OutgoingPayloadPath = %q, want %q", got, wantOutgoing)
	}

	wantResults := filepath.Join(s.jobDir(job.JobID), "results.json")
	if got := s.ResultsPath(job.JobID); got != wantResults {
		t.Errorf("ResultsPath = %q, want %q", got, wantResults)
	}
}

// ── local test-only helpers ──────────────────────────────────────────────────

// containsString reports whether slice contains target.
func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

// sha256HexUpper returns the SHA-256 digest of data as uppercase hex, used to
// confirm ReceiveArtifact compares hashes case-insensitively.
func sha256HexUpper(data []byte) string {
	sum := sha256.Sum256(data)
	hexStr := hex.EncodeToString(sum[:])
	upper := make([]byte, len(hexStr))
	for i := 0; i < len(hexStr); i++ {
		c := hexStr[i]
		if c >= 'a' && c <= 'f' {
			c -= 'a' - 'A'
		}
		upper[i] = c
	}
	return string(upper)
}

// forceUpdatedAt bypasses Save's "always stamp now" behavior by writing the
// job.json file directly, so tests can simulate genuinely old records.
func forceUpdatedAt(t *testing.T, s *Store, jobID string, unixTime int64) {
	t.Helper()
	job, err := s.Get(jobID)
	if err != nil {
		t.Fatalf("forceUpdatedAt: Get: %v", err)
	}
	job.UpdatedAtUnix = unixTime
	raw, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		t.Fatalf("forceUpdatedAt: marshal: %v", err)
	}
	if err := os.WriteFile(s.jobPath(jobID), raw, 0o644); err != nil {
		t.Fatalf("forceUpdatedAt: write: %v", err)
	}
}

// forceSubmittedAt bypasses Save the same way, for SubmittedAtUnix.
func forceSubmittedAt(t *testing.T, s *Store, jobID string, unixTime int64) {
	t.Helper()
	job, err := s.Get(jobID)
	if err != nil {
		t.Fatalf("forceSubmittedAt: Get: %v", err)
	}
	job.SubmittedAtUnix = unixTime
	raw, err := json.MarshalIndent(job, "", "  ")
	if err != nil {
		t.Fatalf("forceSubmittedAt: marshal: %v", err)
	}
	if err := os.WriteFile(s.jobPath(jobID), raw, 0o644); err != nil {
		t.Fatalf("forceSubmittedAt: write: %v", err)
	}
}