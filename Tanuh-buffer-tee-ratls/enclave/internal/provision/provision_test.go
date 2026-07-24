package provision

import (
	"context"
	"testing"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/config"
	"github.com/datakaveri/tanuh-buffer-tee/internal/gcp"
	"github.com/datakaveri/tanuh-buffer-tee/internal/jobs"
)

// fakeClock advances instantly on Sleep so boot timeouts elapse without
// real waiting.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }
func (c *fakeClock) Sleep(_ context.Context, d time.Duration) {
	c.now = c.now.Add(d)
}

type fakeCompute struct {
	startErr map[string]error // per target name
	starts   []string
	stops    []string
}

func (f *fakeCompute) Start(_ context.Context, t config.Target) error {
	f.starts = append(f.starts, t.Name)
	return f.startErr[t.Name]
}
func (f *fakeCompute) Stop(_ context.Context, t config.Target) error {
	f.stops = append(f.stops, t.Name)
	return nil
}

// fakeHealth returns per-URL scripted responses; healthyAfter lets a target
// become healthy after N probes.
type fakeHealth struct {
	healthy      map[string]bool
	healthyAfter map[string]int
	probes       map[string]int
}

func (f *fakeHealth) Healthy(_ context.Context, url string) bool {
	if f.probes == nil {
		f.probes = map[string]int{}
	}
	f.probes[url]++
	if n, ok := f.healthyAfter[url]; ok && f.probes[url] > n {
		return true
	}
	return f.healthy[url]
}

func testCfg() config.Config {
	return config.Config{
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
}

func newEngine(cfg config.Config, c *fakeCompute, h *fakeHealth) (*Engine, *jobs.Job) {
	job := &jobs.Job{JobID: "job-x"}
	e := &Engine{
		Cfg:     cfg,
		Compute: c,
		Health:  h,
		Clock:   &fakeClock{now: time.Unix(1_000_000, 0)},
		Persist: func(*jobs.Job) error { return nil },
		Note:    func(string, string) {},
	}
	return e, job
}

func TestGPUAlreadyHealthyConsumesNoAttempt(t *testing.T) {
	cfg := testCfg()
	h := &fakeHealth{healthy: map[string]bool{cfg.GPU.HealthURL(): true}}
	c := &fakeCompute{}
	e, job := newEngine(cfg, c, h)

	res, err := e.Provision(context.Background(), job)
	if err != nil || res == nil || res.Target.Name != "GPU" {
		t.Fatalf("want GPU result, got %+v err=%v", res, err)
	}
	if job.GPUAttempts != 0 {
		t.Fatalf("healthy GPU consumed an attempt: %d", job.GPUAttempts)
	}
	if len(c.starts) != 0 {
		t.Fatalf("unexpected starts: %v", c.starts)
	}
}

func TestBootTimeoutStopsVMAndFallsBack(t *testing.T) {
	cfg := testCfg()
	h := &fakeHealth{healthy: map[string]bool{cfg.CPU.HealthURL(): true}} // GPU never healthy
	c := &fakeCompute{}
	e, job := newEngine(cfg, c, h)

	res, err := e.Provision(context.Background(), job)
	if err != nil || res == nil || res.Target.Name != "CPU" {
		t.Fatalf("want CPU fallback, got %+v err=%v", res, err)
	}
	if job.GPUAttempts != cfg.MaxGPUAttempts {
		t.Fatalf("attempts = %d, want %d", job.GPUAttempts, cfg.MaxGPUAttempts)
	}
	// Every failed boot must stop the GPU so the H100 is not left billing.
	gpuStops := 0
	for _, s := range c.stops {
		if s == "GPU" {
			gpuStops++
		}
	}
	if gpuStops < cfg.MaxGPUAttempts {
		t.Fatalf("GPU stops = %d, want >= %d (stop-on-timeout)", gpuStops, cfg.MaxGPUAttempts)
	}
	if job.ProvisioningTarget != "cpu" {
		t.Fatalf("provisioning_target = %q, want cpu", job.ProvisioningTarget)
	}
}

func TestOpErrorFailsOverWithoutHealthWait(t *testing.T) {
	cfg := testCfg()
	h := &fakeHealth{healthy: map[string]bool{cfg.CPU.HealthURL(): true}}
	c := &fakeCompute{startErr: map[string]error{
		"GPU": &gcp.OpError{Instance: "gpu-vm", Action: "start", Reason: "QUOTA_EXCEEDED"},
	}}
	e, job := newEngine(cfg, c, h)
	clock := e.Clock.(*fakeClock)
	begin := clock.now

	res, err := e.Provision(context.Background(), job)
	if err != nil || res == nil || res.Target.Name != "CPU" {
		t.Fatalf("want CPU fallback, got %+v err=%v", res, err)
	}
	if job.GPUAttempts != cfg.MaxGPUAttempts {
		t.Fatalf("attempts = %d, want %d (op errors consume attempts)", job.GPUAttempts, cfg.MaxGPUAttempts)
	}
	// Fast fallover: no 30s boot-health wait per attempt should have elapsed.
	if clock.now.Sub(begin) >= cfg.GPU.BootTimeout {
		t.Fatalf("op-error path waited a boot timeout (%s elapsed)", clock.now.Sub(begin))
	}
}

func TestCooldownSkipDoesNotBurnAttempt(t *testing.T) {
	cfg := testCfg()
	h := &fakeHealth{healthy: map[string]bool{}} // nothing healthy
	c := &fakeCompute{}
	e, job := newEngine(cfg, c, h)

	// Prime the cooldown as if a start just happened.
	e.lastStart = map[string]time.Time{"GPU": e.Clock.Now()}

	res, err := e.Provision(context.Background(), job)
	if err != nil || res != nil {
		t.Fatalf("want nil result (retry next tick), got %+v err=%v", res, err)
	}
	if job.GPUAttempts != 0 {
		t.Fatalf("cooldown skip burned an attempt: %d", job.GPUAttempts)
	}
	if len(c.starts) != 0 {
		t.Fatalf("start issued during cooldown: %v", c.starts)
	}
}

func TestExhaustedAttemptsGoStraightToCPU(t *testing.T) {
	cfg := testCfg()
	h := &fakeHealth{healthy: map[string]bool{cfg.CPU.HealthURL(): true}}
	c := &fakeCompute{}
	e, job := newEngine(cfg, c, h)
	job.GPUAttempts = cfg.MaxGPUAttempts // exhausted on a previous tick

	res, err := e.Provision(context.Background(), job)
	if err != nil || res == nil || res.Target.Name != "CPU" {
		t.Fatalf("want CPU, got %+v err=%v", res, err)
	}
	for _, s := range c.starts {
		if s == "GPU" {
			t.Fatal("GPU start issued after attempts exhausted")
		}
	}
}

func TestCPUUnconfiguredReturnsNil(t *testing.T) {
	cfg := testCfg()
	cfg.CPU.ImageDigest = "" // unconfigured — no safe default digest exists
	h := &fakeHealth{healthy: map[string]bool{}}
	c := &fakeCompute{}
	e, job := newEngine(cfg, c, h)
	job.GPUAttempts = cfg.MaxGPUAttempts

	res, err := e.Provision(context.Background(), job)
	if err != nil || res != nil {
		t.Fatalf("want nil (stay queued), got %+v err=%v", res, err)
	}
}

func TestCPUBecomesHealthyAfterStart(t *testing.T) {
	cfg := testCfg()
	h := &fakeHealth{
		healthy:      map[string]bool{},
		healthyAfter: map[string]int{cfg.CPU.HealthURL(): 2},
	}
	c := &fakeCompute{startErr: map[string]error{
		"GPU": &gcp.OpError{Instance: "gpu-vm", Action: "start", Reason: "QUOTA_EXCEEDED"},
	}}
	e, job := newEngine(cfg, c, h)

	res, err := e.Provision(context.Background(), job)
	if err != nil || res == nil || res.Target.Name != "CPU" {
		t.Fatalf("want CPU after boot wait, got %+v err=%v", res, err)
	}
	cpuStarted := false
	for _, s := range c.starts {
		if s == "CPU" {
			cpuStarted = true
		}
	}
	if !cpuStarted {
		t.Fatal("CPU start never issued")
	}
}
