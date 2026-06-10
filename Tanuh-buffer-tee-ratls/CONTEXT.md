# Buffer TEE RA-TLS — Full Context Document

This document captures everything built and deployed in the initial session.
A new Claude chat can use this file alone to understand the full state of the project.

---

## What This Project Is

A Go HTTPS service (`buffer-tee`) that runs inside a **GCP Confidential Space** VM
(AMD SEV-SNP, n2d-standard-2). It proves its identity to browser clients using
**Remote Attestation TLS (RA-TLS)**:

1. On startup, it generates a fresh **ECDSA P-256 binding keypair** and a fresh
   **X25519 HPKE keypair**.
2. It requests a **Google-signed OIDC token** from the Confidential Space TEE launcher,
   embedding fingerprints of both keys as `eat_nonce` claims.
3. It verifies that the returned token actually contains those fingerprints (binding guarantee).
4. It serves `/v1/attest` — the **attestation bundle** — to browsers. The bundle lets
   the browser verify: (a) the code running is the expected image, (b) the keys in
   the bundle are the ones attested by Google.
5. It serves `/v1/submit` — **bidirectional HPKE-encrypted** request/response.
   Browser encrypts to the enclave's HPKE pubkey; enclave decrypts and re-encrypts
   the response back to the browser's ephemeral pubkey.
6. Keys and the OIDC token are **rotated periodically** without dropping in-flight requests.

TLS terminates **inside** the container. No proxy, no load balancer in the data path.

---

## Repository Layout

```
Tanuh-buffer-tee-ratls/
├── CONTEXT.md                  ← this file
├── README.md                   ← user-facing docs, wire format, deploy instructions
└── enclave/
    ├── go.mod                  ← module: github.com/datakaveri/tanuh-buffer-tee, go 1.26
    ├── go.sum                  ← empty (no external deps; all crypto is stdlib)
    ├── Dockerfile              ← multi-stage build; bakes certs; sets launch policy label
    ├── certs/
    │   ├── tls.crt             ← self-signed P-256 cert (365-day), /CN=buffer-tee
    │   └── tls.key             ← private key for the cert
    ├── cmd/buffer-tee/
    │   └── main.go             ← entrypoint: reads env, wires everything, ListenAndServeTLS
    └── internal/
        ├── keys/
        │   ├── keys.go         ← EnclaveKeys, Generate(), SignNonce(), fingerprint helpers
        │   └── keys_test.go    ← 5 tests (SPKI round-trip, fingerprint, sign/verify, DH symmetry)
        ├── attest/
        │   └── oidc.go         ← FetchOIDC() via unix socket to teeserver
        ├── bundle/
        │   ├── types.go        ← AttestBundle, EncryptedRequest, EncryptedResponse structs
        │   └── bundle.go       ← Builder with RWMutex, eat_nonce verify, RefreshOIDC, FullRotate
        ├── hpke/
        │   ├── hpke.go         ← ContextInfo, OpenFromBrowser, SealToBrowser (stdlib crypto/hpke)
        │   └── hpke_test.go    ← 4 tests (round-trips, wrong info, tampered ct)
        ├── rotation/
        │   └── rotation.go     ← Rotator with two tickers: OIDCEvery + FullEvery
        └── server/
            ├── server.go       ← ServeMux registration + CORS middleware
            ├── attest.go       ← GET /v1/attest handler
            └── submit.go       ← POST /v1/submit handler
```

---

## Technology Stack

| Concern | Library |
|---|---|
| HPKE (X25519 / HKDF-SHA256 / AES-256-GCM) | `crypto/hpke` (Go 1.26 stdlib) |
| X25519 keypair | `crypto/ecdh` (Go 1.26 stdlib) |
| ECDSA P-256 binding keypair | `crypto/ecdsa`, `crypto/elliptic`, `crypto/x509` (stdlib) |
| HTTPS server | `net/http`, `crypto/tls` (stdlib) |
| OIDC from CS launcher | unix socket HTTP client (`net/http` + `net.Dialer`) |

**No external Go dependencies.** `go.sum` is intentionally empty.

---

## Key Architectural Decisions and Why

### 1. `crypto/hpke` not `cloudflare/circl`
The spec originally listed `cloudflare/circl/hpke`. Go 1.26 ships `crypto/hpke` with
the same suite (X25519/HKDF-SHA256/AES-256-GCM). We use stdlib to eliminate the
external dependency. The actual Go 1.26 API uses:
- `hpke.NewSender(pk, kdf, aead, info)` → `(enc []byte, *hpke.Sender, error)`
- `hpke.NewRecipient(enc, k, kdf, aead, info)` → `(*hpke.Recipient, error)`
- `hpke.NewDHKEMPrivateKey(priv *ecdh.PrivateKey)` → `hpke.PrivateKey`
- `hpke.NewDHKEMPublicKey(pub *ecdh.PublicKey)` → `hpke.PublicKey`

### 2. `EnclaveKeys` uses `*ecdh.PrivateKey` / `*ecdh.PublicKey`
Not raw `[]byte` scalars. `ecdh.X25519().GenerateKey(rand.Reader)` handles clamping
internally. Raw bytes are retrieved via `.Bytes()` when needed (bundle JSON, eat_nonce).

### 3. Port 8443 (not 443)
The final image runs as root (uid 0) but we use 8443 for consistency with the firewall
rule and because it's conventional for non-system HTTPS ports in container workloads.

### 4. Root inside container (no `USER nonroot`)
`distroless/static-debian12` (root user) is used because the teeserver unix socket at
`/run/container_launcher/teeserver.sock` requires root access from inside the container.
Using `distroless:nonroot` causes `permission denied` on the socket.

### 5. `tee.launch_policy.allow_env_override` label
GCP Confidential Space blocks all `tee-env-*` operator overrides unless the image
explicitly declares them via a Docker label. Without this label the launcher exits with
`env var ... is not allowed to be overridden`. The Dockerfile sets:
```dockerfile
LABEL "tee.launch_policy.allow_env_override"="RATLS_AUDIENCE,TLS_CERT,TLS_KEY"
```

### 6. eat_nonce verification is mandatory
In `NewBuilder`, after receiving the OIDC token from the teeserver, we parse the JWT
payload (no signature verification needed — the token came from the trusted socket) and
assert `eat_nonce[0] == BindingFingerprintB64URL()` and `eat_nonce[1] == HPKEPubB64URL()`.
If this check is skipped, the binding guarantee (keys ↔ attestation) is void.

### 7. Encoding rules (easy to mix up)
- **JSON bundle fields** (`binding_pubkey_b64`, `hpke_pubkey_b64`, `nonce_sig_b64`,
  and `EncryptedRequest` Enc/Ciphertext/AAD): `base64.StdEncoding` (padded, standard alphabet)
- **HTTP headers** (`X-RATLS-Nonce`, `X-RATLS-Browser-HPKE`) and **eat_nonce** values:
  `base64.RawURLEncoding` (no padding, URL-safe)

### 8. HPKE sender/recipient contexts are never reused
Each call to `SealToBrowser` and `OpenFromBrowser` calls `hpke.NewSender` /
`hpke.NewRecipient` fresh. Reusing a `*hpke.Sender` across requests would break AEAD
security (sequence number collision).

---

## Wire Format

### GET /v1/attest

**Request header:**
```
X-RATLS-Nonce: <32-byte liveness nonce, base64url no padding>
```

**Response body (`AttestBundle`):**
```json
{
  "bundle_version": "ratls-cs-v1",
  "oidc_token":        "<Google-signed JWT>",
  "binding_pubkey_b64": "<SPKI DER, std base64>",
  "hpke_pubkey_b64":   "<X25519 raw 32B, std base64>",
  "nonce_sig_b64":     "<ASN.1 DER ECDSA signature, std base64>",
  "issued_at":         1234567890
}
```

Browser verification steps:
1. Decode `oidc_token`, verify signature against Google's JWKS.
2. Assert `hwmodel == "GCP_AMD_SEV_SNP"`, `swname == "CONFIDENTIAL_SPACE"`.
3. Assert `submods.container.image_digest == EXPECTED_IMAGE_DIGEST`.
4. Assert `submods.confidential_space.support_attributes` contains `"STABLE"` (production only; debug image omits it).
5. Assert `eat_nonce[0] == sha256url(binding_pubkey_b64_decoded)` and `eat_nonce[1] == hpke_pubkey_b64url`.
6. Verify `nonce_sig_b64` with ECDSA over `sha256(nonce)` using `binding_pubkey_b64`.

### POST /v1/submit

**Request headers:**
```
X-RATLS-Browser-HPKE: <32-byte browser ephemeral X25519 pubkey, base64url no padding>
```

**Request body:**
```json
{ "enc": "<std base64>", "ciphertext": "<std base64>", "aad": "<std base64>" }
```

**Response body:** same shape as request.

**HPKE context info string:**
```
"ratls-cs-v1|" || sha256(enclavePub) || sha256(browserPub)   (76 bytes)
```
This binds both parties' public keys to the protocol name, preventing cross-protocol key reuse.

---

## OIDC Token Structure (from GCP CS)

Observed claims from a live token (debug image):
```json
{
  "aud": "ratls-browser",
  "iss": "https://confidentialcomputing.googleapis.com",
  "hwmodel": "GCP_AMD_SEV_SNP",
  "swname": "CONFIDENTIAL_SPACE",
  "swversion": ["260400"],
  "secboot": true,
  "dbgstat": "enabled",
  "eat_nonce": ["<binding fingerprint b64url>", "<hpke pub b64url>"],
  "submods": {
    "container": {
      "image_digest": "sha256:...",
      "image_reference": "us-central1-docker.pkg.dev/...",
      "restart_policy": "Never",
      "env_override": { "RATLS_AUDIENCE": "ratls-browser", ... },
      "args": ["/buffer-tee"]
    },
    "confidential_space": {
      "monitoring_enabled": { "memory": false }
    },
    "gce": {
      "zone": "us-central1-b",
      "project_id": "p3dx-depa-sandbox"
    }
  },
  "google_service_accounts": ["cs-buffer-tee@p3dx-depa-sandbox.iam.gserviceaccount.com"]
}
```

Note: on the **debug** image `dbgstat` is `"enabled"` and `support_attributes` is absent.
The production image (`--image-family=confidential-space`) will have `"STABLE"` in
`support_attributes` and `dbgstat: "disabled"`.

---

## Current Deployed State

| Item | Value |
|---|---|
| GCP Project | `p3dx-depa-sandbox` |
| Zone | `us-central1-b` |
| VM | `buffer-tee-vm` |
| External IP | `34.16.92.7` |
| Port | `8443` |
| Service account | `cs-buffer-tee@p3dx-depa-sandbox.iam.gserviceaccount.com` |
| Image family used | `confidential-space-debug` (⚠ not production) |
| Firewall rule | `allow-ratls-tee` — TCP 8443 inbound, tag `ratls-tee` |
| RATLS_AUDIENCE | `ratls-browser` |
| TLS cert | Self-signed `/CN=buffer-tee` (baked into image at `/certs/tls.{crt,key}`) |

**Current image digest (in Artifact Registry):**
```
sha256:624370104424b9e5d4614723fa152ff0b2e9d99585ab9254fe11ec1ffbb758f6
```
Full reference:
```
us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls-enclave/buffer-tee@sha256:624370104424b9e5d4614723fa152ff0b2e9d99585ab9254fe11ec1ffbb758f6
```

This digest goes into `EXPECTED_IMAGE_DIGEST` in the browser verifier.

---

## Rotation Schedule

| Event | Cadence | What happens |
|---|---|---|
| OIDC refresh | Every 45 min | Re-fetches token with the same keys; replaces `oidcToken` under write lock |
| Full rotation | Every 24 h | Generates fresh keys + new OIDC token; atomically replaces everything |

On error: log and continue — in-flight requests keep serving with the previous valid state.

---

## Build & Deploy Runbook

### Prerequisites
```bash
cd enclave/
```

### Local verification (must pass before touching GCP)
```bash
go test ./...                                      # unit tests
GOOS=linux GOARCH=amd64 go build ./cmd/buffer-tee/ # cross-compile check
go vet ./...                                       # static analysis
```

### Generate TLS cert (first time only)
```bash
mkdir -p certs
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
  -keyout certs/tls.key -out certs/tls.crt \
  -days 365 -nodes -subj "/CN=buffer-tee"
```

### Build and push to Artifact Registry
```bash
docker buildx build \
  --platform linux/amd64 \
  -t us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls-enclave/buffer-tee:latest \
  --push .

DIGEST=$(docker inspect \
  us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls-enclave/buffer-tee:latest \
  --format='{{index .RepoDigests 0}}' | cut -d@ -f2)
echo "Digest: $DIGEST"
```

### Delete old VM (if exists)
```bash
python3 -c "
import subprocess
subprocess.run(['gcloud','compute','instances','delete','buffer-tee-vm',
  '--zone=us-central1-b','--project=p3dx-depa-sandbox','--quiet'],
  capture_output=True, text=True, timeout=120)
"
```
> **Note:** Direct `gcloud compute` commands time out in this environment's Bash tool.
> Always invoke them via `python3 -c "import subprocess; subprocess.run([...], timeout=N)"`.

### Deploy to Confidential Space
```bash
python3 -c "
import subprocess
DIGEST = 'sha256:<your-digest>'
r = subprocess.run([
  'gcloud','compute','instances','create','buffer-tee-vm',
  '--project=p3dx-depa-sandbox',
  '--zone=us-central1-b',
  '--machine-type=n2d-standard-2',
  '--confidential-compute-type=SEV_SNP',
  '--maintenance-policy=TERMINATE',
  '--service-account=cs-buffer-tee@p3dx-depa-sandbox.iam.gserviceaccount.com',
  '--scopes=https://www.googleapis.com/auth/cloud-platform',
  '--image-project=confidential-space-images',
  '--image-family=confidential-space-debug',
  '--tags=ratls-tee',
  f'--metadata=^~^tee-image-reference=us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls-enclave/buffer-tee@{DIGEST}~tee-container-log-redirect=true~tee-env-RATLS_AUDIENCE=ratls-browser~tee-env-TLS_CERT=/certs/tls.crt~tee-env-TLS_KEY=/certs/tls.key',
  '--shielded-secure-boot',
], capture_output=True, text=True, timeout=120)
print(r.stdout, r.stderr)
"
```

### Create firewall rule (first time only)
```bash
python3 -c "
import subprocess
subprocess.run(['gcloud','compute','firewall-rules','create','allow-ratls-tee',
  '--project=p3dx-depa-sandbox','--direction=INGRESS','--action=ALLOW',
  '--rules=tcp:8443','--target-tags=ratls-tee','--source-ranges=0.0.0.0/0'],
  capture_output=True, text=True, timeout=60)
"
```

### Watch serial output (wait ~80s after create)
```bash
python3 -c "
import subprocess
r = subprocess.run(
  ['gcloud','compute','instances','get-serial-port-output','buffer-tee-vm',
   '--zone=us-central1-b','--project=p3dx-depa-sandbox'],
  capture_output=True, text=True, timeout=60)
print(r.stdout[-3000:])
"
```

Looking for:
```
buffer-tee: generating keys and fetching OIDC token...
buffer-tee: attestation bundle ready
buffer-tee: listening on :8443 (TLS)
```

### Get external IP
```bash
python3 -c "
import subprocess
r = subprocess.run(['gcloud','compute','instances','describe','buffer-tee-vm',
  '--zone=us-central1-b','--project=p3dx-depa-sandbox',
  '--format=get(networkInterfaces[0].accessConfigs[0].natIP)'],
  capture_output=True, text=True, timeout=30)
print(r.stdout.strip())
"
```

### Smoke test
```bash
TEE_IP="34.16.92.7"
NONCE=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
curl -sk -H "X-RATLS-Nonce: $NONCE" "https://${TEE_IP}:8443/v1/attest" | python3 -m json.tool
```

### Decode and validate the OIDC token
```bash
TEE_IP="34.16.92.7"
NONCE=$(python3 -c "import os,base64; print(base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode())")
python3 -c "
import subprocess, base64, json
result = subprocess.run(['curl','-sk','-H','X-RATLS-Nonce: $NONCE',
  'https://${TEE_IP}:8443/v1/attest'], capture_output=True, text=True)
bundle = json.loads(result.stdout)
parts = bundle['oidc_token'].split('.')
p = parts[1] + '=' * (4 - len(parts[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(p))
print(json.dumps(payload, indent=2))
"
```

---

## Errors Encountered and Fixes Applied

### Fix 1: `go.sum` missing
**Symptom:** Docker build fails with `"/go.sum": not found`.
**Cause:** Module has no external deps; `go mod tidy` produces nothing.
**Fix:** Create an empty `go.sum` file.

### Fix 2: env var override blocked
**Symptom:** `env var {RATLS_AUDIENCE ratls-browser} is not allowed to be overridden`; launcher exits with code 4.
**Cause:** GCP Confidential Space blocks `tee-env-*` operator overrides unless the image declares them.
**Fix:** Add to Dockerfile:
```dockerfile
LABEL "tee.launch_policy.allow_env_override"="RATLS_AUDIENCE,TLS_CERT,TLS_KEY"
```

### Fix 3: permission denied on teeserver socket
**Symptom:** `dial unix /run/container_launcher/teeserver.sock: connect: permission denied`
**Cause:** Container was running as `nonroot` (uid 65532); socket requires root.
**Fix:** Changed from `distroless/static-debian12:nonroot` to `distroless/static-debian12`
and removed `USER nonroot` from Dockerfile.

### Fix 4: `crypto/hpke` API was wrong in the plan
**Symptom (caught at compile time):** `undefined: hpke.SetupRecipient`, `undefined: hpke.SetupSender`.
**Cause:** The plan incorrectly used `SetupSender`/`SetupRecipient`. The actual Go 1.26 API is
`hpke.NewSender` / `hpke.NewRecipient`.
**Fix:** Updated `internal/hpke/hpke.go` to use the correct function names, and wrap
`*ecdh.PrivateKey` → `hpke.NewDHKEMPrivateKey`, `*ecdh.PublicKey` → `hpke.NewDHKEMPublicKey`.

### Fix 5: gcloud compute commands time out in Bash tool
**Symptom:** Any `gcloud compute ...` command exits with code 120 (tool timeout).
**Cause:** Bash tool has a 2-minute default and gcloud compute API calls take longer in this environment.
**Fix:** Wrap all `gcloud compute` calls in `python3 -c "import subprocess; subprocess.run([...], timeout=N)"`.
`gcloud version`, `gcloud auth list`, and other quick commands work fine directly.

---

## Dockerfile (current state)

```dockerfile
FROM golang:1.26-bookworm AS build

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" \
    -o /out/buffer-tee ./cmd/buffer-tee

FROM gcr.io/distroless/static-debian12

COPY --from=build /out/buffer-tee /buffer-tee
COPY certs/tls.crt /certs/tls.crt
COPY certs/tls.key /certs/tls.key

# Declare which env vars the CS operator is allowed to override via tee-env-* metadata.
LABEL "tee.launch_policy.allow_env_override"="RATLS_AUDIENCE,TLS_CERT,TLS_KEY"

EXPOSE 8443
ENTRYPOINT ["/buffer-tee"]
```

Key decisions in this Dockerfile:
- `golang:1.26-bookworm` — required for `crypto/hpke` (stdlib ≥ 1.24)
- `CGO_ENABLED=0` — required for distroless (no glibc)
- `-trimpath -ldflags="-s -w"` — strip paths and debug symbols
- `distroless/static-debian12` (not `:nonroot`) — root required for teeserver socket
- `LABEL tee.launch_policy.allow_env_override` — mandatory for operator env var injection
- No `USER` directive — runs as root inside container

---

## What's Next (Browser Verifier)

The browser verifier (`VERIFIER_PLAN.md`) needs these constants extracted from the live deployment:

```
EXPECTED_IMAGE_DIGEST = "sha256:624370104424b9e5d4614723fa152ff0b2e9d99585ab9254fe11ec1ffbb758f6"
EXPECTED_HWMODEL      = "GCP_AMD_SEV_SNP"
EXPECTED_SWNAME       = "CONFIDENTIAL_SPACE"
EXPECTED_AUDIENCE     = "ratls-browser"
EXPECTED_ISSUER       = "https://confidentialcomputing.googleapis.com"
JWKS_URL              = "https://confidentialcomputing.googleapis.com/.well-known/openid-configuration"
```

The verifier must:
1. Verify the OIDC token signature against Google's JWKS.
2. Assert `hwmodel`, `swname`, `image_digest`, and (for production) `support_attributes` contains `"STABLE"`.
3. Assert `eat_nonce[0]` == `base64url(sha256(SPKI DER of binding_pubkey))`.
4. Assert `eat_nonce[1]` == HPKE pubkey bytes as base64url (same value as `hpke_pubkey_b64` decoded then re-encoded as raw URL).
5. Verify `nonce_sig_b64` is a valid ECDSA-P256 signature over `sha256(nonce)` using `binding_pubkey_b64`.

When switching from debug → production image, re-deploy with `--image-family=confidential-space`
(not `confidential-space-debug`), update `EXPECTED_IMAGE_DIGEST` to the new digest, and
enable the `STABLE` check in the verifier.

---

## Security Invariants

- **Private key material** (`BindingPriv.D`, `HPKEPriv`) is never written to disk, logs,
  environment variables, or serialized. `EnclaveKeys` does not implement `json.Marshaler`
  or `String()`.
- **Liveness nonce** travels in `X-RATLS-Nonce` header only — never in the URL path or
  query string (keeps it out of access logs).
- **HPKE contexts** are constructed fresh per request via `hpke.NewSender` / `hpke.NewRecipient`.
  No state is carried between requests.
- **eat_nonce verification** in `NewBuilder` is mandatory. If the token does not contain
  the expected key fingerprints, startup fails. Skipping this check voids the binding guarantee.
- **`confidential-space-debug`** is the current deployed image. The browser verifier must
  NOT enforce `STABLE` until the production image is deployed. Do not remove this note.
