// Package scheduler runs the buffer's background loop: retention cleanup,
// queue-stall warnings, crash recovery for dispatched jobs that never called
// back, and the dispatch cycle (provision → build payload → RA-TLS deliver).
//
// Completion is callback-driven (the Processing TEE POSTs its terminal
// status to /v1/jobs/{id}/complete). A dispatched job is requeued ONLY when
// the dispatch timeout elapses with no callback AND its TEE is no longer
// healthy — and at most MaxRequeue times, after which it is failed. This
// replaces both the fire-and-forget finalizer and the old unbounded
// requeue-on-timeout that caused the re-run loop.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/config"
	"github.com/datakaveri/tanuh-buffer-tee/internal/jobs"
	"github.com/datakaveri/tanuh-buffer-tee/internal/provision"
)

// Scheduler wires the store, the provisioning engine, and the dispatcher.
type Scheduler struct {
	Cfg    config.Config
	Store  *jobs.Store
	Engine *provision.Engine
	Health provision.Health
	// Deliver is dispatch.Deliver, injectable for tests.
	Deliver func(ctx context.Context, addr, audience, digest string, payload []byte) error
}

// Run ticks until ctx is cancelled.
func (s *Scheduler) Run(ctx context.Context) {
	log.Printf("scheduler: started (interval=%s, dispatch_timeout=%s, retention=%s, max_requeue=%d)",
		s.Cfg.SchedulerTick, s.Cfg.DispatchTimeout, s.Cfg.JobRetention, s.Cfg.MaxRequeue)
	ticker := time.NewTicker(s.Cfg.SchedulerTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("scheduler: stopped")
			return
		case <-ticker.C:
			s.tick(ctx)
		}
	}
}

func (s *Scheduler) tick(ctx context.Context) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: tick panic recovered: %v", r)
		}
	}()

	for _, id := range s.Store.CleanupOld(s.Cfg.JobRetention) {
		log.Printf("scheduler: deleted job %s (retention elapsed)", id)
	}
	for _, id := range s.Store.StalledQueued(s.Cfg.QueueStallAfter) {
		log.Printf("scheduler: WARNING job %s queued longer than %s with no dispatch", id, s.Cfg.QueueStallAfter)
	}

	s.recoverStuckDispatched(ctx)
	s.dispatchNext(ctx)
}

// recoverStuckDispatched requeues (bounded) dispatched jobs whose TEE died
// without delivering the completion callback.
func (s *Scheduler) recoverStuckDispatched(ctx context.Context) {
	dispatched, err := s.Store.Dispatched()
	if err != nil {
		log.Printf("scheduler: list dispatched: %v", err)
		return
	}
	now := time.Now().Unix()
	for _, job := range dispatched {
		if now-job.DispatchedAtUnix < int64(s.Cfg.DispatchTimeout.Seconds()) {
			continue
		}
		// A live eval keeps the TEE healthy — leave it alone regardless of
		// elapsed time.
		if job.AssignedTEE != "" && s.Health.Healthy(ctx, "https://"+job.AssignedTEE+"/healthz") {
			continue
		}
		if job.RequeueCount >= s.Cfg.MaxRequeue {
			log.Printf("scheduler: job %s stuck with no callback and requeue budget exhausted (%d) — marking error",
				job.JobID, job.RequeueCount)
			if _, err := s.Store.Fail(job.JobID, "requeue_exhausted", map[string]any{
				"error_type":    "DispatchLost",
				"error_message": fmt.Sprintf("no completion callback after %d dispatches", job.RequeueCount+1),
			}); err != nil {
				log.Printf("scheduler: fail job %s: %v", job.JobID, err)
			}
			continue
		}
		log.Printf("scheduler: job %s dispatched %ds ago with no callback and TEE unhealthy — requeueing (%d/%d)",
			job.JobID, now-job.DispatchedAtUnix, job.RequeueCount+1, s.Cfg.MaxRequeue)
		if _, err := s.Store.Requeue(job.JobID); err != nil {
			log.Printf("scheduler: requeue job %s: %v", job.JobID, err)
		}
	}
}

// dispatchNext provisions a target for the next queued job and delivers it.
// One job in flight at a time, matching the Processing TEE's 409 gate.
func (s *Scheduler) dispatchNext(ctx context.Context) {
	busy, err := s.Store.AnyDispatched()
	if err != nil || busy {
		return
	}
	job, err := s.Store.NextQueued()
	if err != nil || job == nil {
		return
	}

	log.Printf("scheduler: dispatch cycle: job %s (dataset %d)", job.JobID, job.DatasetID)
	s.Store.UpdateDispatchState(map[string]any{
		"last_dispatch_attempt_unix": time.Now().Unix(),
		"last_dispatch_job_id":       job.JobID,
		"last_dispatch_status":       "checking_vm_health",
		"last_dispatch_error":        "",
	})

	res, err := s.Engine.Provision(ctx, job)
	if err != nil {
		log.Printf("scheduler: provision error for %s: %v", job.JobID, err)
		return
	}
	if res == nil {
		log.Printf("scheduler: job %s: no Processing TEE available this cycle — leaving queued", job.JobID)
		return
	}

	payload, err := s.buildPayload(job)
	if err != nil {
		log.Printf("scheduler: build payload for %s: %v", job.JobID, err)
		return
	}
	payloadPath := s.Store.OutgoingPayloadPath(job.JobID)
	if err := os.MkdirAll(filepath.Dir(payloadPath), 0o755); err == nil {
		if err := os.WriteFile(payloadPath, payload, 0o644); err != nil {
			log.Printf("scheduler: stage payload for %s: %v", job.JobID, err)
		}
	}

	if err := s.Deliver(ctx, res.Target.Addr, s.Cfg.DispatchAudience, res.Target.ImageDigest, payload); err != nil {
		log.Printf("scheduler: dispatch failed for %s: %v", job.JobID, err)
		s.Store.UpdateDispatchState(map[string]any{
			"last_dispatch_attempt_unix": time.Now().Unix(),
			"last_dispatch_job_id":       job.JobID,
			"last_dispatch_status":       "dispatch_failed",
			"last_dispatch_error":        err.Error(),
		})
		return
	}

	if _, err := s.Store.MarkDispatched(job.JobID, payloadPath, res.Target.Addr); err != nil {
		log.Printf("scheduler: mark dispatched %s: %v", job.JobID, err)
		return
	}
	s.Store.UpdateDispatchState(map[string]any{
		"last_dispatch_attempt_unix": time.Now().Unix(),
		"last_dispatch_job_id":       job.JobID,
		"last_dispatch_status":       "dispatched",
		"last_dispatch_error":        "",
	})
	log.Printf("scheduler: job %s dispatched successfully via RA-TLS (%s)", job.JobID, res.Target.Name)
}

// buildPayload assembles the secure dispatch payload — the same JSON shape
// the Python manager produced, plus buffer_job_url pointing at this server's
// :8443 completion endpoint.
func (s *Scheduler) buildPayload(job *jobs.Job) ([]byte, error) {
	modelBytes, err := s.Store.ArtifactBytes(job.JobID, jobs.ModelFileName)
	if err != nil {
		return nil, fmt.Errorf("read model: %w", err)
	}
	weightsBytes, err := s.Store.ArtifactBytes(job.JobID, jobs.WeightsFileName)
	if err != nil {
		return nil, fmt.Errorf("read weights: %w", err)
	}
	modelSum := sha256.Sum256(modelBytes)
	weightsSum := sha256.Sum256(weightsBytes)

	payload := map[string]any{
		"job_id":               job.JobID,
		"dataset_id":           job.DatasetID,
		"submitted_at_unix":    job.SubmittedAtUnix,
		"submitted_by":         job.SubmittedBy,
		"keycloak_token":       job.KeycloakToken,
		"hyperparameters":      job.Hyperparameters,
		"model_file":           jobs.ModelFileName,
		"weights_file":         jobs.WeightsFileName,
		"model_sha256":         hex.EncodeToString(modelSum[:]),
		"weights_sha256":       hex.EncodeToString(weightsSum[:]),
		"model_onnx_base64":    base64.StdEncoding.EncodeToString(modelBytes),
		"model_weights_base64": base64.StdEncoding.EncodeToString(weightsBytes),
		"buffer_job_url":       s.Cfg.CallbackBase + "/v1/jobs/" + job.JobID,
	}
	if ppBytes, err := s.Store.ArtifactBytes(job.JobID, jobs.PreprocessingFileName); err == nil {
		ppSum := sha256.Sum256(ppBytes)
		payload["preprocessing_script_base64"] = base64.StdEncoding.EncodeToString(ppBytes)
		payload["preprocessing_sha256"] = hex.EncodeToString(ppSum[:])
	}
	return json.Marshal(payload)
}
