package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/yourorg/ratls/pkg/ratls"
)

func main() {
	ctx := context.Background()

	gpuCSAddr := getEnv("GPU_CS_ADDR", "gpu-cs.internal:443")
	audience := getEnv("RATLS_AUDIENCE", "ratls-buffer-tee")
	expectedDigest := getEnv("GPU_CS_IMAGE_DIGEST", "")
	jobPayloadPath := getEnv("JOB_PAYLOAD_PATH", "")

	if expectedDigest == "" {
		log.Fatal("buffer-tee: GPU_CS_IMAGE_DIGEST must be set")
	}
	if jobPayloadPath == "" {
		log.Fatal("buffer-tee: JOB_PAYLOAD_PATH must be set")
	}

	opts := &ratls.VerificationOptions{
		Audience:            audience,
		ExpectedImageDigest: expectedDigest,
	}

	log.Printf("buffer-tee: connecting to GPU CS at %s", gpuCSAddr)

	session, err := ratls.Connect(ctx, gpuCSAddr, opts)
	if err != nil {
		log.Fatalf("buffer-tee: RATLS failed: %v", err)
	}

	log.Printf("buffer-tee: RATLS verified")
	log.Printf("  HWModel:     %s", session.HWModel)
	log.Printf("  ImageDigest: %s", session.ContainerImageDigest)

	if err := uploadModelWeights(ctx, gpuCSAddr, session, jobPayloadPath); err != nil {
		log.Fatalf("buffer-tee: upload model: %v", err)
	}
}

func uploadModelWeights(
	ctx context.Context,
	gpuCSAddr string,
	session *ratls.VerifiedSession,
	jobPayloadPath string,
) error {
	log.Printf("buffer-tee: reading job payload from %s", jobPayloadPath)
	bodyBytes, err := os.ReadFile(jobPayloadPath)
	if err != nil {
		return fmt.Errorf("read payload: %w", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(bodyBytes, &payload); err == nil {
		if jobID, ok := payload["job_id"].(string); ok {
			log.Printf("buffer-tee: dispatching verified payload for job_id=%s", jobID)
		}
	}

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://"+gpuCSAddr+"/api/load-model",
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
	log.Printf("buffer-tee: GPU CS response status=%d body=%s", resp.StatusCode, string(respBody))
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("gpu-cs returned unexpected status %d", resp.StatusCode)
	}
	log.Printf("buffer-tee: payload delivered successfully to %s", gpuCSAddr)
	return nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
