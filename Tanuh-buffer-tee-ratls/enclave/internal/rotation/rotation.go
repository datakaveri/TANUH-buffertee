package rotation

import (
	"context"
	"log"
	"time"

	"github.com/datakaveri/tanuh-buffer-tee/internal/bundle"
)

// Config controls rotation cadence.
type Config struct {
	OIDCEvery time.Duration // default: 45 * time.Minute
	FullEvery time.Duration // default: 24 * time.Hour
}

// DefaultConfig returns the production rotation schedule.
func DefaultConfig() Config {
	return Config{
		OIDCEvery: 45 * time.Minute,
		FullEvery:  24 * time.Hour,
	}
}

// Rotator periodically refreshes the OIDC token and rotates keys.
type Rotator struct {
	builder *bundle.Builder
	cfg     Config
}

// NewRotator creates a Rotator. Call Start in a goroutine.
func NewRotator(b *bundle.Builder, cfg Config) *Rotator {
	return &Rotator{builder: b, cfg: cfg}
}

// Start runs the rotation loop until ctx is cancelled.
// Errors are logged but never fatal — in-flight requests remain served by the
// current valid keys while a rotation retries on the next tick.
func (r *Rotator) Start(ctx context.Context) {
	oidcTicker := time.NewTicker(r.cfg.OIDCEvery)
	fullTicker := time.NewTicker(r.cfg.FullEvery)
	defer oidcTicker.Stop()
	defer fullTicker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-fullTicker.C:
			if err := r.builder.FullRotate(ctx); err != nil {
				log.Printf("rotation: full rotate failed: %v", err)
			} else {
				log.Printf("rotation: full key rotation complete")
			}
		case <-oidcTicker.C:
			if err := r.builder.RefreshOIDC(ctx); err != nil {
				log.Printf("rotation: OIDC refresh failed: %v", err)
			} else {
				log.Printf("rotation: OIDC token refreshed")
			}
		}
	}
}
