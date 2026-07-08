// buffer-tee is the single Buffer TEE binary. It owns the entire buffer
// role in-process: the browser-facing RA-TLS HTTPS server on :8443 (HPKE
// submit + chunked uploads), the persistent job store and queue, the
// GPU-first / CPU-fallback provisioning state machine (Compute API with
// Operation polling), RA-TLS dispatch to the Processing TEE, the
// attestation-authenticated completion callback, and bounded crash
// recovery. The former Flask manager, scheduler thread, dispatch
// subprocess, and VM shell scripts are all gone.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/bundle"
	"github.com/datakaveri/tanuh-buffer-tee/internal/config"
	"github.com/datakaveri/tanuh-buffer-tee/internal/dispatch"
	"github.com/datakaveri/tanuh-buffer-tee/internal/gcp"
	"github.com/datakaveri/tanuh-buffer-tee/internal/jobs"
	"github.com/datakaveri/tanuh-buffer-tee/internal/provision"
	"github.com/datakaveri/tanuh-buffer-tee/internal/rotation"
	"github.com/datakaveri/tanuh-buffer-tee/internal/scheduler"
	"github.com/datakaveri/tanuh-buffer-tee/internal/server"
)

func main() {
	cfg := config.FromEnv()

	if cfg.KeycloakJWKSURL != "" && cfg.KeycloakIssuer == "" {
		log.Fatal("KEYCLOAK_ISSUER must be set when KEYCLOAK_JWKS_URL is set")
	}
	if cfg.KeycloakJWKSURL != "" {
		log.Printf("buffer-tee: Keycloak auth enabled (issuer=%s)", cfg.KeycloakIssuer)
	} else {
		log.Println("buffer-tee: Keycloak auth disabled (KEYCLOAK_JWKS_URL not set)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	tlsCert, err := loadServingCert(ctx, cfg)
	if err != nil {
		log.Fatalf("buffer-tee: load TLS serving cert: %v", err)
	}

	log.Println("buffer-tee: generating keys and fetching OIDC token...")
	builder, err := bundle.NewBuilder(ctx, cfg.ServerAudience)
	if err != nil {
		log.Fatalf("buffer-tee: init failed: %v", err)
	}
	log.Println("buffer-tee: attestation bundle ready")

	rot := rotation.NewRotator(builder, rotation.DefaultConfig())
	go rot.Start(ctx)

	store, err := jobs.Open(cfg.BufferDir())
	if err != nil {
		log.Fatalf("buffer-tee: open job store: %v", err)
	}

	engine := &provision.Engine{
		Cfg:     cfg,
		Compute: computeAPI{project: cfg.Project},
		Health:  healthProbe{},
		Clock:   realClock{},
		Persist: store.Save,
		Note: func(status, errMsg string) {
			store.UpdateDispatchState(map[string]any{
				"last_dispatch_status": status,
				"last_dispatch_error":  errMsg,
			})
		},
	}
	sched := &scheduler.Scheduler{
		Cfg:     cfg,
		Store:   store,
		Engine:  engine,
		Health:  healthProbe{},
		Deliver: dispatch.Deliver,
	}
	go sched.Run(ctx)

	srv := server.New(builder, server.AuthConfig{JWKSUrl: cfg.KeycloakJWKSURL, Issuer: cfg.KeycloakIssuer}, store, cfg)
	httpSrv := &http.Server{
		Addr:    cfg.ListenAddr,
		Handler: srv.Handler(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{tlsCert},
			MinVersion:   tls.VersionTLS13, // TLS 1.3 only
		},
		ReadTimeout:  600 * time.Second,
		WriteTimeout: 600 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		<-ctx.Done()
		log.Println("buffer-tee: shutting down...")
		shutCtx, shutCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutCancel()
		if err := httpSrv.Shutdown(shutCtx); err != nil {
			log.Printf("buffer-tee: shutdown error: %v", err)
		}
	}()

	log.Printf("buffer-tee: listening on %s (TLS 1.3)", cfg.ListenAddr)
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("buffer-tee: server error: %v", err)
	}
	log.Println("buffer-tee: stopped")
}

// loadServingCert prefers explicit TLS_CERT/TLS_KEY files (local dev) and
// otherwise fetches the cert pair from Secret Manager into memory — the
// former entrypoint.sh curl+python bootstrap, without touching disk.
func loadServingCert(ctx context.Context, cfg config.Config) (tls.Certificate, error) {
	if cfg.TLSCertFile != "" && cfg.TLSKeyFile != "" {
		if _, err := os.Stat(cfg.TLSCertFile); err == nil {
			log.Printf("buffer-tee: loading TLS cert from files (%s)", cfg.TLSCertFile)
			return tls.LoadX509KeyPair(cfg.TLSCertFile, cfg.TLSKeyFile)
		}
	}
	log.Printf("buffer-tee: fetching TLS cert from Secret Manager (%s/%s)", cfg.TLSCertSecret, cfg.TLSKeySecret)
	certPEM, err := gcp.AccessSecret(ctx, cfg.TLSProject, cfg.TLSCertSecret)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM, err := gcp.AccessSecret(ctx, cfg.TLSProject, cfg.TLSKeySecret)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}

// computeAPI implements provision.Compute via the Compute REST API.
type computeAPI struct{ project string }

func (c computeAPI) Start(ctx context.Context, t config.Target) error {
	return gcp.StartInstance(ctx, c.project, t.Zone, t.Instance)
}
func (c computeAPI) Stop(ctx context.Context, t config.Target) error {
	return gcp.StopInstance(ctx, c.project, t.Zone, t.Instance)
}

// healthProbe implements provision.Health against the Processing TEE's
// self-signed RA-TLS endpoint (authentication happens at dispatch time via
// attestation, not here — this is only a liveness probe).
type healthProbe struct{}

var healthClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
	},
}

func (healthProbe) Healthy(ctx context.Context, url string) bool {
	if url == "" {
		return false
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := healthClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// realClock implements provision.Clock.
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }
func (realClock) Sleep(ctx context.Context, d time.Duration) {
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}
