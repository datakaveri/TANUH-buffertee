// Package provision implements the GPU-first / CPU-fallback provisioning
// state machine: up to MaxGPUAttempts stop→start cycles against the GPU
// Processing TEE (counted per-job, persisted so a buffer restart does not
// reset them), then the pre-provisioned CPU TEE. The fallback is non-sticky:
// every new job starts with a fresh GPU cycle.
//
// All side effects go through the Compute/Health/Clock interfaces so the
// policy is table-testable with fakes.
package provision

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/config"
	"github.com/datakaveri/tanuh-buffer-tee/internal/gcp"
	"github.com/datakaveri/tanuh-buffer-tee/internal/jobs"
)

// Compute starts/stops Processing TEE VMs. Start blocks until the Compute
// Operation is DONE; an operation-level failure (quota, stockout, config)
// surfaces as *gcp.OpError so the engine can fail over without waiting out
// a boot-health timeout.
type Compute interface {
	Start(ctx context.Context, t config.Target) error
	Stop(ctx context.Context, t config.Target) error
}

// Health probes a Processing TEE's /healthz endpoint.
type Health interface {
	Healthy(ctx context.Context, url string) bool
}

// Clock abstracts time for tests.
type Clock interface {
	Now() time.Time
	Sleep(ctx context.Context, d time.Duration)
}

// Result is the chosen dispatch target.
type Result struct {
	Target config.Target
}

// Engine holds the policy configuration and dependencies.
type Engine struct {
	Cfg     config.Config
	Compute Compute
	Health  Health
	Clock   Clock
	// Persist saves per-job provisioning mutations (attempt counts, target).
	Persist func(*jobs.Job) error
	// Note records a dispatch-state status line (mirrors the Python
	// dispatch_state.json breadcrumbs).
	Note func(status, errMsg string)

	mu        sync.Mutex
	lastStart map[string]time.Time // per-target cooldown (in-memory; a restart
	// may retry a start early, which is safe: starting a RUNNING instance is
	// a no-op at the API level)
}

// Provision decides which Processing TEE this job dispatches to. A nil
// Result with nil error means "nothing available this tick" — the job stays
// queued and the next scheduler tick retries (attempt counts persist).
func (e *Engine) Provision(ctx context.Context, job *jobs.Job) (*Result, error) {
	// GPU already exhausted on a previous tick → go straight to CPU.
	if job.GPUAttempts >= e.Cfg.MaxGPUAttempts {
		log.Printf("provision: job %s: GPU attempts exhausted (%d/%d) — targeting CPU fallback",
			job.JobID, job.GPUAttempts, e.Cfg.MaxGPUAttempts)
		return e.cpuFallback(ctx, job)
	}

	gpu := e.Cfg.GPU
	if !gpu.Configured() {
		log.Printf("provision: job %s: GPU target unconfigured — targeting CPU fallback", job.JobID)
		return e.cpuFallback(ctx, job)
	}

	// GPU already healthy → use it without consuming an attempt.
	if e.Health.Healthy(ctx, gpu.HealthURL()) {
		if err := e.setTarget(job, "gpu"); err != nil {
			return nil, err
		}
		return &Result{Target: gpu}, nil
	}

	// Capped stop→start retry loop. An attempt is only counted when a start
	// was actually issued — a cooldown skip does not burn an attempt.
	for job.GPUAttempts < e.Cfg.MaxGPUAttempts {
		attemptNo := job.GPUAttempts + 1
		log.Printf("provision: job %s: GPU provision attempt %d/%d", job.JobID, attemptNo, e.Cfg.MaxGPUAttempts)
		e.Note("provisioning_gpu", fmt.Sprintf("GPU attempt %d/%d", attemptNo, e.Cfg.MaxGPUAttempts))

		// On a retry do a clean stop→start so a VM stuck in a bad running
		// state reboots. The first attempt of a cold cycle skips the stop.
		if job.GPUAttempts > 0 {
			e.stopAndSettle(ctx, gpu)
		}

		issued, err := e.startWithCooldown(ctx, gpu)
		if err != nil {
			// Operation-level failure (quota/stockout/config): consume the
			// attempt and move on immediately — no point polling health for
			// a VM that never started.
			var opErr *gcp.OpError
			if errors.As(err, &opErr) {
				log.Printf("provision: job %s: GPU start operation failed fast: %v", job.JobID, err)
				e.Note("provisioning_gpu", "GPU start failed: "+opErr.Reason)
				job.GPUAttempts = attemptNo
				job.ProvisioningTarget = "gpu"
				if perr := e.Persist(job); perr != nil {
					return nil, perr
				}
				continue
			}
			// Transient API error (metadata/network): don't consume; retry
			// next tick.
			log.Printf("provision: job %s: GPU start error (not consuming attempt): %v", job.JobID, err)
			e.Note("provisioning_gpu", "GPU start error: "+err.Error())
			return nil, nil
		}
		if !issued {
			// Cooldown window — no boot happened; retry next tick.
			log.Printf("provision: job %s: GPU start skipped (cooldown) — retrying next cycle", job.JobID)
			return nil, nil
		}

		job.GPUAttempts = attemptNo
		job.ProvisioningTarget = "gpu"
		if err := e.Persist(job); err != nil {
			return nil, err
		}

		if e.waitHealthy(ctx, gpu.HealthURL(), gpu.BootTimeout) {
			return &Result{Target: gpu}, nil
		}
		// Not healthy within the boot timeout → stop the VM so a failed /
		// half-booted H100 is not left running (and billing).
		log.Printf("provision: job %s: GPU not healthy within %s — stopping the GPU VM",
			job.JobID, gpu.BootTimeout)
		e.stopAndSettle(ctx, gpu)
	}

	log.Printf("provision: job %s: GPU provisioning exhausted after %d attempts — falling back to CPU",
		job.JobID, e.Cfg.MaxGPUAttempts)
	return e.cpuFallback(ctx, job)
}

// cpuFallback provisions the pre-provisioned CPU TEE. Polled every tick
// until it comes up — a job never auto-fails on provisioning.
func (e *Engine) cpuFallback(ctx context.Context, job *jobs.Job) (*Result, error) {
	cpu := e.Cfg.CPU
	if !cpu.Configured() {
		log.Printf("provision: CPU fallback unavailable — CPU_CS_ADDR/CPU_CS_IMAGE_DIGEST not configured")
		e.Note("cpu_unconfigured", "CPU fallback requested but CPU target is unconfigured")
		return nil, nil
	}
	if err := e.setTarget(job, "cpu"); err != nil {
		return nil, err
	}

	if e.Health.Healthy(ctx, cpu.HealthURL()) {
		return &Result{Target: cpu}, nil
	}

	log.Printf("provision: CPU Processing TEE not healthy — requesting start")
	e.Note("awaiting_cpu", "GPU exhausted; provisioning CPU fallback")
	issued, err := e.startWithCooldown(ctx, cpu)
	if err != nil {
		log.Printf("provision: CPU start failed: %v", err)
		return nil, nil
	}
	if !issued {
		return nil, nil
	}
	if e.waitHealthy(ctx, cpu.HealthURL(), cpu.BootTimeout) {
		return &Result{Target: cpu}, nil
	}
	return nil, nil
}

// startWithCooldown issues a Start unless the per-target cooldown window is
// active. Returns (issued, error). The cooldown exists to avoid re-issuing
// a start against a VM that is already booting — so a start whose Operation
// FAILED (nothing is booting) does not arm it, letting quota/stockout
// errors burn through the attempt budget and reach the CPU fallback fast.
func (e *Engine) startWithCooldown(ctx context.Context, t config.Target) (bool, error) {
	e.mu.Lock()
	if e.lastStart == nil {
		e.lastStart = map[string]time.Time{}
	}
	prev := e.lastStart[t.Name]
	now := e.Clock.Now()
	if now.Sub(prev) < e.Cfg.StartCooldown {
		e.mu.Unlock()
		return false, nil
	}
	e.lastStart[t.Name] = now
	e.mu.Unlock()

	log.Printf("provision: starting Processing TEE (%s) instance %s", t.Name, t.Instance)
	if err := e.Compute.Start(ctx, t); err != nil {
		e.mu.Lock()
		e.lastStart[t.Name] = prev // failed start boots nothing — disarm cooldown
		e.mu.Unlock()
		return true, err
	}
	return true, nil
}

// stopAndSettle requests a stop and gives it a bounded window to take
// effect. Best-effort: failures are logged, not fatal.
func (e *Engine) stopAndSettle(ctx context.Context, t config.Target) {
	log.Printf("provision: stopping Processing TEE (%s) instance %s", t.Name, t.Instance)
	if err := e.Compute.Stop(ctx, t); err != nil {
		log.Printf("provision: %s stop did not succeed cleanly: %v", t.Name, err)
	}
	// Stop() already polled the operation; a short settle keeps parity with
	// the former script-based flow where TERMINATED lagged the API response.
	e.Clock.Sleep(ctx, min(e.Cfg.VMStopWait, 10*time.Second))
}

// waitHealthy polls the health URL until healthy or timeout.
func (e *Engine) waitHealthy(ctx context.Context, url string, timeout time.Duration) bool {
	deadline := e.Clock.Now().Add(timeout)
	for e.Clock.Now().Before(deadline) {
		if ctx.Err() != nil {
			return false
		}
		if e.Health.Healthy(ctx, url) {
			return true
		}
		e.Clock.Sleep(ctx, e.Cfg.PollInterval)
	}
	log.Printf("provision: %s did not become healthy within %s", url, timeout)
	return false
}

func (e *Engine) setTarget(job *jobs.Job, target string) error {
	if job.ProvisioningTarget == target {
		return nil
	}
	job.ProvisioningTarget = target
	return e.Persist(job)
}
