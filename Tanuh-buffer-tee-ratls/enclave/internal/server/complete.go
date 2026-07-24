package server

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/dispatch"
)

// HandleComplete serves POST /v1/jobs/{job_id}/complete — the completion
// callback from the Processing TEE carrying the job's terminal status
// ({job_id, status: "succeeded"|"failed", error?}).
//
// Authentication is machine-to-machine, NOT Keycloak: the caller presents
// its Confidential Space attestation token as the Bearer credential. We
// verify it exactly like a dispatch-side RA-TLS token (Google JWKS
// signature, iss/aud/exp/hwmodel/swname) and additionally require:
//
//  1. the token's image_digest to be one of the digests this buffer
//     dispatches to (GPU_CS_IMAGE_DIGEST / CPU_CS_IMAGE_DIGEST) — only our
//     own attested Processing TEE images can complete jobs, and
//  2. eat_nonce == hex(sha256(request body)) — the token is bound to this
//     exact callback payload, so it cannot be replayed with a different
//     status or job id.
func (s *Server) HandleComplete(w http.ResponseWriter, r *http.Request) {
	jobID := r.PathValue("job_id")

	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "message": "read body failed"})
		return
	}

	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "message": "missing attestation token"})
		return
	}
	claims, err := dispatch.VerifyOIDCToken(token, s.cfg.CallbackAudience, 30*time.Second)
	if err != nil {
		log.Printf("server: complete %s: attestation verification failed: %v", jobID, err)
		writeJSON(w, http.StatusUnauthorized, map[string]any{"status": "error", "message": "attestation verification failed"})
		return
	}
	if claims.ImageDigest != s.cfg.GPU.ImageDigest && claims.ImageDigest != s.cfg.CPU.ImageDigest {
		log.Printf("server: complete %s: caller digest %s is not a known Processing TEE image", jobID, claims.ImageDigest)
		writeJSON(w, http.StatusForbidden, map[string]any{"status": "error", "message": "unknown workload image"})
		return
	}
	bodySum := sha256.Sum256(body)
	if claims.EatNonce != hex.EncodeToString(bodySum[:]) {
		log.Printf("server: complete %s: eat_nonce does not match body hash", jobID)
		writeJSON(w, http.StatusForbidden, map[string]any{"status": "error", "message": "token not bound to this payload"})
		return
	}

	var req struct {
		JobID  string         `json:"job_id"`
		Status string         `json:"status"`
		Error  map[string]any `json:"error"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "message": "invalid JSON body"})
		return
	}
	if req.JobID != jobID {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "message": "job_id mismatch"})
		return
	}
	if req.Status != "succeeded" && req.Status != "failed" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"status": "error", "message": "status must be 'succeeded' or 'failed'"})
		return
	}

	job, err := s.store.Complete(jobID, req.Status == "succeeded", req.Error)
	if err != nil {
		if job == nil {
			writeJSON(w, http.StatusNotFound, map[string]any{"status": "error", "message": "Unknown job_id"})
			return
		}
		// Job exists but is not dispatched — duplicate or late callback.
		writeJSON(w, http.StatusConflict, map[string]any{"status": "ignored", "message": err.Error()})
		return
	}

	log.Printf("server: job %s terminal status via Processing TEE callback: %s (hwmodel=%s)",
		jobID, req.Status, claims.HWModel)
	s.store.UpdateDispatchState(map[string]any{
		"last_dispatch_attempt_unix": time.Now().Unix(),
		"last_dispatch_job_id":       jobID,
		"last_dispatch_status":       "callback_" + req.Status,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "success",
		"job_id":     jobID,
		"job_status": job.Status,
	})
}
