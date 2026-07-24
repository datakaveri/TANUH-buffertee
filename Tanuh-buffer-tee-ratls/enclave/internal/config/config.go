// Package config centralises the Buffer TEE's runtime configuration.
// Everything is parsed once in main from the environment; the Dockerfile is
// the single source of default values for deployment.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Target identifies one Processing TEE the buffer can provision (GPU or CPU).
type Target struct {
	Name        string // log label, e.g. "GPU" / "CPU"
	Addr        string // RA-TLS "host:port"; empty = target unavailable
	ImageDigest string // expected attested image digest; required to dispatch
	Instance    string // GCE instance name
	Zone        string
	BootTimeout time.Duration
}

// Configured reports whether the target can be dispatched to at all.
func (t Target) Configured() bool { return t.Addr != "" && t.ImageDigest != "" }

// HealthURL is the /healthz probe endpoint on the target.
func (t Target) HealthURL() string {
	if t.Addr == "" {
		return ""
	}
	return "https://" + t.Addr + "/healthz"
}

// Config is the full runtime configuration.
type Config struct {
	BaseDir string

	// Browser-facing RA-TLS server.
	ListenAddr      string
	ServerAudience  string // RATLS_SERVER_AUDIENCE (browser-facing attest)
	KeycloakJWKSURL string
	KeycloakIssuer  string

	// TLS serving cert for the :8443 listener. The buffer runs behind a
	// TLS-terminating reverse proxy (nginx/LB) that holds the real
	// browser-trusted cert and does not verify this upstream cert, so the
	// buffer self-signs at boot (see cmd/buffer-tee). These optional file
	// paths are an escape hatch for deployments that need a provided cert
	// here (e.g. L4/TCP passthrough); unset → self-signed.
	TLSCertFile string
	TLSKeyFile  string

	// Dispatch client (buffer → Processing TEE).
	DispatchAudience string // aud the Processing TEE's RA-TLS token must carry

	GPU Target
	CPU Target

	Project string // GCP project for Compute start/stop

	MaxGPUAttempts   int
	StartCooldown    time.Duration
	PollInterval     time.Duration
	VMStopWait       time.Duration
	SchedulerTick    time.Duration
	DispatchTimeout  time.Duration // no-callback requeue threshold
	MaxRequeue       int
	JobRetention     time.Duration
	QueueStallAfter  time.Duration

	// Completion callback (Processing TEE → this server on :8443).
	CallbackBase     string // e.g. https://tee.dev.tanuh.iudx.io:8443
	CallbackAudience string // aud required in the caller's CS attestation token
}

// FromEnv builds the Config from the environment.
func FromEnv() Config {
	base := getEnv("BASE_DIR", "/app")
	gpuAddr := getEnv("GPU_CS_ADDR", "")
	cpuAddr := getEnv("CPU_CS_ADDR", "")
	return Config{
		BaseDir: base,

		ListenAddr:      getEnv("LISTEN_ADDR", ":8443"),
		ServerAudience:  getEnv("RATLS_SERVER_AUDIENCE", "ratls-browser"),
		KeycloakJWKSURL: os.Getenv("KEYCLOAK_JWKS_URL"),
		KeycloakIssuer:  os.Getenv("KEYCLOAK_ISSUER"),

		TLSCertFile: os.Getenv("TLS_CERT"),
		TLSKeyFile:  os.Getenv("TLS_KEY"),

		DispatchAudience: getEnv("RATLS_AUDIENCE", "ratls-buffer-tee"),

		GPU: Target{
			Name:        "GPU",
			Addr:        gpuAddr,
			ImageDigest: os.Getenv("GPU_CS_IMAGE_DIGEST"),
			Instance:    getEnv("GPU_CS_INSTANCE", "gpu-cs-tdx-h100"),
			Zone:        getEnv("GPU_CS_ZONE", "us-central1-a"),
			BootTimeout: secondsEnv("PROCESSING_VM_BOOT_TIMEOUT_SECONDS", 300),
		},
		CPU: Target{
			Name:        "CPU",
			Addr:        cpuAddr,
			ImageDigest: os.Getenv("CPU_CS_IMAGE_DIGEST"),
			Instance:    getEnv("CPU_CS_INSTANCE", "cpu-cs-tdx"),
			Zone:        getEnv("CPU_CS_ZONE", "us-central1-a"),
			BootTimeout: secondsEnv("CPU_VM_BOOT_TIMEOUT_SECONDS", 300),
		},

		Project: getEnv("PROJECT", "p3dx-depa-sandbox"),

		MaxGPUAttempts:  intEnv("MAX_GPU_PROVISION_ATTEMPTS", 3),
		StartCooldown:   secondsEnv("PROCESSING_VM_START_COOLDOWN_SECONDS", 45),
		PollInterval:    secondsEnv("PROCESSING_VM_BOOT_POLL_INTERVAL_SECONDS", 5),
		VMStopWait:      secondsEnv("VM_STOP_WAIT_SECONDS", 60),
		SchedulerTick:   secondsEnv("SCHEDULER_INTERVAL_SECONDS", 15),
		DispatchTimeout: secondsEnv("DISPATCH_TIMEOUT_SECONDS", 600),
		MaxRequeue:      intEnv("MAX_REQUEUE", 2),
		JobRetention:    secondsEnv("JOB_RETENTION_SECONDS", 86400),
		QueueStallAfter: secondsEnv("QUEUE_STALL_THRESHOLD_SECONDS", 300),

		CallbackBase:     getEnv("BUFFER_CALLBACK_BASE", "https://tee.dev.tanuh.iudx.io:8443"),
		CallbackAudience: getEnv("CALLBACK_AUDIENCE", "tanuh-buffer-callback"),
	}
}

// BufferDir returns BASE_DIR/cvm_workflow/buffer — the job store root
// (layout unchanged from the Python manager for rollback compatibility).
func (c Config) BufferDir() string { return filepath.Join(c.BaseDir, "cvm_workflow", "buffer") }

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func secondsEnv(key string, def int) time.Duration {
	return time.Duration(intEnv(key, def)) * time.Second
}
