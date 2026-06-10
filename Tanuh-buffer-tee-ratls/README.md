# buffer-tee — RA-TLS Enclave (GCP Confidential Space)

A Go HTTPS service that runs inside a GCP Confidential Space (AMD SEV-SNP, n2d)
workload container. It generates fresh cryptographic keys on startup, binds them
into a Google-signed OIDC token via `eat_nonce`, and serves attestation bundles
plus HPKE-encrypted request/response to browser clients.

TLS terminates **inside** the container. No load balancer or proxy in the data path.

---

## Architecture

```
Browser
  │  GET /v1/attest   (X-RATLS-Nonce: <32B base64url>)
  │  POST /v1/submit  (X-RATLS-Browser-HPKE: <32B base64url>)
  ▼
buffer-tee  :8443 (TLS)
  ├── internal/keys       P-256 binding keypair + X25519 HPKE keypair
  ├── internal/attest     OIDC token from /run/container_launcher/teeserver.sock
  ├── internal/bundle     AttestBundle builder + eat_nonce verification
  ├── internal/hpke       Bidirectional HPKE (X25519 / HKDF-SHA256 / AES-256-GCM)
  ├── internal/rotation   Periodic OIDC refresh (45 min) + key rotation (24 h)
  └── internal/server     HTTP handlers + CORS middleware
```

---

## Wire format

### GET /v1/attest

Request headers:
- `X-RATLS-Nonce`: 32-byte liveness nonce, base64url encoded (no padding)

Response body (`AttestBundle`):
```json
{
  "bundle_version": "ratls-cs-v1",
  "oidc_token": "<Google-signed JWT>",
  "binding_pubkey_b64": "<SPKI DER, std base64>",
  "hpke_pubkey_b64": "<X25519 32B, std base64>",
  "nonce_sig_b64": "<ASN.1 DER ECDSA sig, std base64>",
  "issued_at": 1234567890
}
```

### POST /v1/submit

Request headers:
- `X-RATLS-Browser-HPKE`: 32-byte browser ephemeral X25519 pubkey, base64url (no padding)

Request body (`EncryptedRequest`):
```json
{ "enc": "<std base64>", "ciphertext": "<std base64>", "aad": "<std base64>" }
```

Response body (`EncryptedResponse`): same shape as request.

---

## Running locally (development only)

```bash
# Generate a self-signed TLS certificate
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout key.pem -out cert.pem -days 1 -nodes -subj "/CN=localhost"

cd enclave
RATLS_AUDIENCE=https://example.com TLS_CERT=../cert.pem TLS_KEY=../key.pem \
  go run ./cmd/buffer-tee
```

The OIDC step will fail outside GCP Confidential Space (socket not present),
but the server otherwise starts for local handler testing.

---

## Building the container

```bash
cd enclave
docker build -t buffer-tee:latest .
```

---

## Running on GCP Confidential Space

```bash
gcloud run deploy buffer-tee \
  --image gcr.io/<PROJECT>/buffer-tee:latest \
  --platform managed \
  --confidential-computing \
  --set-env-vars RATLS_AUDIENCE=https://example.com \
  --set-secrets TLS_CERT=tls-cert:latest,TLS_KEY=tls-key:latest \
  --port 8443 \
  --no-allow-unauthenticated
```

**Do not use the `confidential-space-debug` image in production.** It lacks the
`STABLE` attribute in `support_attributes`, which the browser verifier checks.

---

## Testing

```bash
cd enclave

# Unit tests (no network required)
go test ./internal/keys/ ./internal/hpke/ -v -race -count=1

# Build check
go build ./...
```

End-to-end smoke test (inside a CS VM):
```bash
curl -k \
  -H "X-RATLS-Nonce: $(openssl rand -base64 32 | tr '+/' '-_' | tr -d '=')" \
  https://localhost:8443/v1/attest | jq .bundle_version
```

---

## Security notes

- Private key bytes are never written to disk, logs, environment variables, or serialized.
- The liveness nonce travels in `X-RATLS-Nonce` header only — never in the URL.
- A fresh HPKE context is constructed per request (`SetupSender`/`SetupRecipient`).
- `eat_nonce` is verified against the generated key fingerprints in `NewBuilder`.
  If the token does not contain the expected values, startup fails.
