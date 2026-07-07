package dispatch

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
)

// Run performs a one-shot job dispatch to a Processing TEE and returns an
// error on any failure (the caller exits non-zero so the Python job manager
// sees a failed dispatch).
//
// Configuration comes from the environment — the interface is unchanged from
// the old standalone buffer-tee client binary:
//
//	GPU_CS_ADDR          target "host:port" (GPU or CPU Processing TEE)
//	RATLS_AUDIENCE       expected aud claim in the attestation token
//	GPU_CS_IMAGE_DIGEST  expected container image digest of the target
//	JOB_PAYLOAD_PATH     path to the secure-dispatch JSON payload
func Run(ctx context.Context) error {
	addr := getEnv("GPU_CS_ADDR", "gpu-cs.internal:443")
	audience := getEnv("RATLS_AUDIENCE", "ratls-buffer-tee")
	expectedDigest := os.Getenv("GPU_CS_IMAGE_DIGEST")
	jobPayloadPath := os.Getenv("JOB_PAYLOAD_PATH")

	if expectedDigest == "" {
		return fmt.Errorf("dispatch: GPU_CS_IMAGE_DIGEST must be set")
	}
	if jobPayloadPath == "" {
		return fmt.Errorf("dispatch: JOB_PAYLOAD_PATH must be set")
	}

	opts := &VerificationOptions{
		Audience:            audience,
		ExpectedImageDigest: expectedDigest,
	}

	log.Printf("dispatch: connecting to Processing TEE at %s", addr)

	session, err := Connect(ctx, addr, opts)
	if err != nil {
		return fmt.Errorf("dispatch: RA-TLS failed: %w", err)
	}

	log.Printf("dispatch: RA-TLS verified")
	log.Printf("  HWModel:     %s", session.HWModel)
	log.Printf("  ImageDigest: %s", session.ContainerImageDigest)

	if err := deliverPayload(ctx, addr, session, jobPayloadPath); err != nil {
		return fmt.Errorf("dispatch: deliver payload: %w", err)
	}
	return nil
}

// deliverPayload POSTs the secure job payload to the verified Processing TEE.
func deliverPayload(
	ctx context.Context,
	addr string,
	session *VerifiedSession,
	jobPayloadPath string,
) error {
	log.Printf("dispatch: reading job payload from %s", jobPayloadPath)
	bodyBytes, err := os.ReadFile(jobPayloadPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(bodyBytes, &payload); err == nil {
		if jobID, ok := payload["job_id"].(string); ok {
			log.Printf("dispatch: dispatching verified payload for job_id=%s", jobID)
		}
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://"+addr+"/api/load-model",
		bytes.NewReader(bodyBytes),
	)
	if err != nil {
		return fmt.Errorf("build POST /api/load-model: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := session.Client.Do(req)
	if err != nil {
		return fmt.Errorf("POST /api/load-model: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	log.Printf("dispatch: Processing TEE response status=%d body=%s", resp.StatusCode, string(respBody))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("processing TEE returned unexpected status %d", resp.StatusCode)
	}
	log.Printf("dispatch: payload delivered successfully to %s", addr)
	return nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
