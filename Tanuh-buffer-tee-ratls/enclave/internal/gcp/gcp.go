// Package gcp provides the minimal GCP REST calls the Buffer TEE needs
// (metadata token, Secret Manager access for the TLS cert, Compute instance
// start/stop with Operation polling), implemented with stdlib net/http only.
// Keeping the Cloud SDK out preserves the module's small audit surface —
// hpke/keys/bundle/attest stay dependency-free.
package gcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const metadataRoot = "http://metadata.google.internal/computeMetadata/v1"

// AccessToken returns the OAuth2 access token for the attached service
// account from the metadata server.
func AccessToken(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		metadataRoot+"/instance/service-accounts/default/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Metadata-Flavor", "Google")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("gcp: metadata token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("gcp: metadata token: status %d", resp.StatusCode)
	}

	var body struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("gcp: parse metadata token: %w", err)
	}
	if body.AccessToken == "" {
		return "", fmt.Errorf("gcp: metadata token empty")
	}
	return body.AccessToken, nil
}

// AccessSecret fetches the latest version of a Secret Manager secret's
// payload bytes.
func AccessSecret(ctx context.Context, projectID, secretID string) ([]byte, error) {
	token, err := AccessToken(ctx)
	if err != nil {
		return nil, err
	}
	u := fmt.Sprintf("https://secretmanager.googleapis.com/v1/projects/%s/secrets/%s/versions/latest:access",
		projectID, secretID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("gcp: secret %s: %w", secretID, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("gcp: secret %s: status %d: %s", secretID, resp.StatusCode, string(body))
	}
	var payload struct {
		Payload struct {
			Data string `json:"data"`
		} `json:"payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("gcp: parse secret %s: %w", secretID, err)
	}
	raw, err := base64.StdEncoding.DecodeString(payload.Payload.Data)
	if err != nil {
		return nil, fmt.Errorf("gcp: decode secret %s: %w", secretID, err)
	}
	return raw, nil
}

// OpError is a Compute Operation that completed with an error — quota
// exhaustion, zone stockout, bad config. It surfaces synchronously so the
// provisioning engine can fail over immediately instead of waiting out a
// boot-health timeout.
type OpError struct {
	Instance string
	Action   string
	Reason   string
}

func (e *OpError) Error() string {
	return fmt.Sprintf("gcp: %s %s: operation failed: %s", e.Action, e.Instance, e.Reason)
}

// StartInstance starts a stopped instance and polls the returned zonal
// Operation until DONE. Returns *OpError when the operation itself reports
// an error.
func StartInstance(ctx context.Context, project, zone, instance string) error {
	return instanceAction(ctx, project, zone, instance, "start", "")
}

// StopInstance stops an instance and polls the Operation until DONE.
// discardLocalSsd=true is mandatory for VMs with a Local SSD attached (the
// H100 GPU VM) — the API rejects an unqualified stop with 400 — and is
// accepted harmlessly on VMs without one.
func StopInstance(ctx context.Context, project, zone, instance string) error {
	return instanceAction(ctx, project, zone, instance, "stop", "?discardLocalSsd=true")
}

func instanceAction(ctx context.Context, project, zone, instance, action, query string) error {
	token, err := AccessToken(ctx)
	if err != nil {
		return err
	}
	u := fmt.Sprintf("https://compute.googleapis.com/compute/v1/projects/%s/zones/%s/instances/%s/%s%s",
		project, zone, instance, action, query)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, strings.NewReader("{}"))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("gcp: %s %s: %w", action, instance, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("gcp: %s %s: status %d: %s", action, instance, resp.StatusCode, string(body))
	}

	var op struct {
		SelfLink string `json:"selfLink"`
	}
	if err := json.Unmarshal(body, &op); err != nil || op.SelfLink == "" {
		return fmt.Errorf("gcp: %s %s: no operation in response", action, instance)
	}
	return waitOperation(ctx, token, op.SelfLink, instance, action)
}

// waitOperation polls a zonal Operation until DONE (or ctx cancellation).
// Operation errors (quota, stockout, config) become *OpError.
func waitOperation(ctx context.Context, token, opURL, instance, action string) error {
	deadline := time.Now().Add(2 * time.Minute)
	for {
		if time.Now().After(deadline) {
			return fmt.Errorf("gcp: %s %s: operation did not finish within 2m", action, instance)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, opURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		client := &http.Client{Timeout: 15 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			return fmt.Errorf("gcp: poll operation for %s %s: %w", action, instance, err)
		}
		var op struct {
			Status string `json:"status"`
			Error  *struct {
				Errors []struct {
					Code    string `json:"code"`
					Message string `json:"message"`
				} `json:"errors"`
			} `json:"error"`
		}
		err = json.NewDecoder(resp.Body).Decode(&op)
		resp.Body.Close()
		if err != nil {
			return fmt.Errorf("gcp: parse operation for %s %s: %w", action, instance, err)
		}

		if op.Status != "DONE" {
			continue
		}
		if op.Error != nil && len(op.Error.Errors) > 0 {
			reason := op.Error.Errors[0].Code
			if op.Error.Errors[0].Message != "" {
				reason += ": " + op.Error.Errors[0].Message
			}
			return &OpError{Instance: instance, Action: action, Reason: reason}
		}
		return nil
	}
}
