package dispatch

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
)

// Deliver performs one in-process job dispatch: RA-TLS connect to the
// Processing TEE at addr, verify its attestation against expectedDigest,
// and POST the secure payload to /api/load-model. This replaces the former
// one-shot subprocess client — same verification, no exec.
func Deliver(ctx context.Context, addr, audience, expectedDigest string, payload []byte) error {
	if expectedDigest == "" {
		return fmt.Errorf("dispatch: expected image digest must be set before dispatching")
	}

	log.Printf("dispatch: connecting to Processing TEE at %s", addr)
	session, err := Connect(ctx, addr, &VerificationOptions{
		Audience:            audience,
		ExpectedImageDigest: expectedDigest,
	})
	if err != nil {
		return fmt.Errorf("dispatch: RA-TLS failed: %w", err)
	}
	log.Printf("dispatch: RA-TLS verified — hwmodel=%s digest=%s", session.HWModel, session.ContainerImageDigest)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://"+addr+"/api/load-model", bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("dispatch: build POST /api/load-model: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := session.Client.Do(req)
	if err != nil {
		return fmt.Errorf("dispatch: POST /api/load-model: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	log.Printf("dispatch: Processing TEE response status=%d body=%s", resp.StatusCode, string(respBody))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("dispatch: processing TEE returned unexpected status %d", resp.StatusCode)
	}
	log.Printf("dispatch: payload delivered successfully to %s", addr)
	return nil
}
