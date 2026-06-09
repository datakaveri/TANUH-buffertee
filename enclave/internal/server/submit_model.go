package server

import (
    "encoding/json"
    "fmt"
    "io"
    "log"
    "net/http"
    "sync"
    "time"

    "github.com/datakaveri/tanuh-buffer-tee/internal/bundle"
)

// jobStoreMu protects jobStore and jobQueue for concurrent access.
var (
    jobStoreMu sync.RWMutex
    jobStore   = make(map[string]*bundle.EncryptedModelRequest)
    jobQueue   []string
)

// HandleSubmitModel serves POST /v1/submit/model.
//
// New symmetric key flow (updated TANUH architecture):
//   - Browser gets a symmetric key from KMS after attestation
//   - Browser encrypts the model with that symmetric key
//   - Browser sends the encrypted model + RSA-OAEP wrapped key here
//   - Buffer TEE queues the job WITHOUT decrypting the model
//   - Processing TEE later fetches the key from Secrets Manager and decrypts
func (s *Server) HandleSubmitModel(w http.ResponseWriter, r *http.Request) {
    body, err := io.ReadAll(io.LimitReader(r.Body, 100<<20)) // 100 MB max
    if err != nil {
        http.Error(w, "failed to read body", http.StatusBadRequest)
        return
    }

    var req bundle.EncryptedModelRequest
    if err := json.Unmarshal(body, &req); err != nil {
        http.Error(w, "invalid JSON body", http.StatusBadRequest)
        return
    }

    // Validate required fields
    if req.JobID == "" {
        http.Error(w, "missing job_id", http.StatusBadRequest)
        return
    }
    if req.WrappedKey == "" {
        http.Error(w, "missing wrapped_key", http.StatusBadRequest)
        return
    }
    if req.EncryptedModel == "" {
        http.Error(w, "missing encrypted_model", http.StatusBadRequest)
        return
    }
    if req.DatasetID == 0 {
        http.Error(w, "missing dataset_id", http.StatusBadRequest)
        return
    }

    // Queue the job — Buffer TEE never decrypts the model
    jobStoreMu.Lock()
    if _, exists := jobStore[req.JobID]; exists {
        jobStoreMu.Unlock()
        http.Error(w, fmt.Sprintf("job_id %q already exists", req.JobID), http.StatusConflict)
        return
    }
    jobStore[req.JobID] = &req
    jobQueue = append(jobQueue, req.JobID)
    jobStoreMu.Unlock()

    log.Printf("submit/model: queued job %s dataset_id=%d submitted_by=%q",
        req.JobID, req.DatasetID, req.SubmittedBy)

    w.Header().Set("Content-Type", "application/json")
    w.WriteHeader(http.StatusAccepted)
    json.NewEncoder(w).Encode(bundle.JobQueuedResponse{
        JobID:    req.JobID,
        Status:   "queued",
        IssuedAt: time.Now().Unix(),
    })
}

// HandleListJobs serves GET /v1/jobs.
// Returns all queued job summaries — without encrypted model content.
// The Processing TEE polls this to find pending jobs.
func (s *Server) HandleListJobs(w http.ResponseWriter, r *http.Request) {
    jobStoreMu.RLock()
    defer jobStoreMu.RUnlock()

    type jobSummary struct {
        JobID       string `json:"job_id"`
        DatasetID   int    `json:"dataset_id"`
        SubmittedBy string `json:"submitted_by"`
    }

    summaries := make([]jobSummary, 0, len(jobQueue))
    for _, id := range jobQueue {
        job := jobStore[id]
        summaries = append(summaries, jobSummary{
            JobID:       job.JobID,
            DatasetID:   job.DatasetID,
            SubmittedBy: job.SubmittedBy,
        })
    }

    w.Header().Set("Content-Type", "application/json")
    json.NewEncoder(w).Encode(map[string]interface{}{
        "jobs":      summaries,
        "queue_len": len(jobQueue),
    })
}
