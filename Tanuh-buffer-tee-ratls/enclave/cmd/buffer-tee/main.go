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
	"github.com/datakaveri/tanuh-buffer-tee/internal/rotation"
	"github.com/datakaveri/tanuh-buffer-tee/internal/server"
)

func main() {
	audience := mustEnv("RATLS_AUDIENCE")
	certFile  := mustEnv("TLS_CERT")
	keyFile   := mustEnv("TLS_KEY")

	jwksURL := os.Getenv("KEYCLOAK_JWKS_URL") // optional — empty disables auth
	issuer  := os.Getenv("KEYCLOAK_ISSUER")
	if jwksURL != "" && issuer == "" {
		log.Fatal("KEYCLOAK_ISSUER must be set when KEYCLOAK_JWKS_URL is set")
	}
	if jwksURL != "" {
		log.Printf("buffer-tee: Keycloak auth enabled (issuer=%s)", issuer)
	} else {
		log.Println("buffer-tee: Keycloak auth disabled (KEYCLOAK_JWKS_URL not set)")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Println("buffer-tee: generating keys and fetching OIDC token...")
	builder, err := bundle.NewBuilder(ctx, audience)
	if err != nil {
		log.Fatalf("buffer-tee: init failed: %v", err)
	}
	log.Println("buffer-tee: attestation bundle ready")

	rot := rotation.NewRotator(builder, rotation.DefaultConfig())
	go rot.Start(ctx)

	tlsCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("buffer-tee: load TLS cert: %v", err)
	}

	srv := server.New(builder, server.AuthConfig{JWKSUrl: jwksURL, Issuer: issuer})
	httpSrv := &http.Server{
		Addr:    ":8443",
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

	log.Println("buffer-tee: listening on :8443 (TLS 1.3)")
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("buffer-tee: server error: %v", err)
	}
	log.Println("buffer-tee: stopped")
}

func mustEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required env var %s is not set", key)
	}
	return v
}
