# TANUH Buffer TEE

Always-on AMD SEV Confidential Space VM that sits between the browser and the Processing TEE. It handles attestation, encrypted job intake, file staging, queueing, and secure dispatch — the browser never communicates with the Processing TEE directly.

## Architecture

```
Browser
  │  HPKE-encrypted metadata  (POST /v1/submit)
  │  AES-256-GCM chunked file  (PUT  /v1/upload/:job_id/model|weights|preprocessing)
  ▼
Go RA-TLS proxy  :8443  (Tanuh-buffer-tee-ratls/)
  │  Keycloak JWT validated here
  │  HPKE decrypt / AES-GCM decrypt / SHA-256 verify
  ▼
Flask enclave manager  :4100  (enclave_manager_buffer.py)
  │  Job records + file staging under /app/cvm_workflow/buffer/
  │  Ordered queue in queue.json
  ▼
Scheduler (background thread, every 15 s)
  │  GPU attempt first → CPU fallback (cpu-cs-tdx) if GPU unavailable
  ▼
Processing TEE  :443  (RA-TLS dispatch)
```

## Components

| Path | Role |
|---|---|
| `Tanuh-buffer-tee-ratls/` | Go HTTP server — RA-TLS attestation, HPKE/AES-GCM crypto, Keycloak JWT middleware |
| `enclave_manager_buffer.py` | Python Flask — job lifecycle, file storage, queue, scheduler, RA-TLS dispatch |
| `start-gpu-cs-vm.sh` / `stop-gpu-cs-vm.sh` | GCP VM start/stop scripts for the GPU Processing TEE |
| `start-cpu-cs-vm.sh` / `stop-cpu-cs-vm.sh` | GCP VM start/stop scripts for the CPU Processing TEE |
| `entrypoint.sh` | Container entrypoint — starts Flask then Go proxy |

## API Endpoints (Go proxy at :8443)

| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/v1/attest` | — | RA-TLS attestation bundle (OIDC token + HPKE pub + liveness sig) |
| `POST` | `/v1/submit` | JWT | HPKE-encrypted job metadata → returns `{ job_id }` |
| `PUT` | `/v1/upload/:job_id/model` | JWT | AES-256-GCM chunked model upload |
| `PUT` | `/v1/upload/:job_id/weights` | JWT | AES-256-GCM chunked weights upload |
| `PUT` | `/v1/upload/:job_id/preprocessing` | JWT | AES-256-GCM chunked preprocessing script upload |
| `GET` | `/v1/status/:job_id` | JWT | Job status record |
| `GET` | `/v1/queue` | JWT (`org_admin`) | All jobs + ordered queue; includes `queued_count` |
| `GET` | `/v1/results/:job_id` | JWT | Job results once complete |
| `GET` | `/healthz` | — | Health check |

Internal Flask endpoints (`:4100`, not exposed externally): `POST /buffer/jobs`, `GET /buffer/jobs`, `GET /buffer/jobs/:id`, `PUT /buffer/jobs/:id/model|weights|preprocessing`, `GET /buffer/jobs/:id/results`, `GET /buffer/dispatch/state`, `GET /healthz`

## Job Lifecycle

1. Browser POSTs HPKE-encrypted `{ dataset_id, model_sha256, weights_sha256 }` → job record created (`status: pending`)
2. Browser uploads model, weights, and optionally a preprocessing script via AES-256-GCM chunked PUTs
3. Once all required files arrive and SHA-256 hashes verify → `status: queued`, appended to `queue.json`
4. Scheduler picks next queued job → attempts GPU TEE → falls back to CPU TEE if unavailable
5. Encrypted payload dispatched to Processing TEE over RA-TLS → `status: dispatched`
6. Processing TEE POSTs results back → `status: complete`

## Authentication

All routes except `/v1/attest` and `/healthz` require a Keycloak Bearer JWT. The Go proxy validates the RS256 signature against the JWKS endpoint on every request.

`GET /v1/queue` additionally requires the `org_admin` realm role (`realm_access.roles`).

## Environment Variables

All runtime vars must be passed via GCP Confidential Space metadata with the `tee-env-` prefix.

| Variable | Default | Description |
|---|---|---|
| `RATLS_SERVER_AUDIENCE` | `ratls-browser` | Expected audience in OIDC token presented by browser |
| `GPU_CS_ADDR` | `10.128.15.210:443` | Internal IP:port of the GPU Processing TEE |
| `GPU_CS_IMAGE_DIGEST` | *(see Dockerfile)* | Expected image digest for GPU TEE RA-TLS verification |
| `CPU_CS_ADDR` | — | Internal IP:port of the CPU Processing TEE |
| `CPU_CS_IMAGE_DIGEST` | — | Expected image digest for CPU TEE RA-TLS verification |
| `CPU_CS_INSTANCE` | — | GCP instance name of the CPU Processing TEE |
| `CPU_CS_ZONE` | — | GCP zone of the CPU Processing TEE |
| `MAX_GPU_PROVISION_ATTEMPTS` | `1` | GPU provision attempts before falling back to CPU |
| `PROCESSING_VM_BOOT_TIMEOUT_SECONDS` | `300` | Seconds to wait for Processing TEE to boot |
| `SCHEDULER_INTERVAL_SECONDS` | `15` | Queue poll interval in seconds |
| `KEYCLOAK_JWKS_URL` | — | JWKS endpoint for JWT validation |
| `KEYCLOAK_ISSUER` | — | Expected `iss` claim in Keycloak JWTs |

## Build & Deploy

```bash
IMAGE=us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls/buffer-tee

docker build -t $IMAGE:latest .
docker push $IMAGE:latest

# Get digest — required for tee-image-reference metadata and UI constants.ts
docker inspect --format='{{index .RepoDigests 0}}' $IMAGE:latest
```

Update VM metadata:
```bash
gcloud compute instances add-metadata buffer-tee-vm --zone=us-east1-c \
  --metadata tee-image-reference=$IMAGE@sha256:<digest>
```

Update `constants.ts` in `Tanuh-browser-ratls/src/lib/constants.ts` with the new digest, then rebuild the UI.

## Debug

Serial/container logs include:
- `[Buffer-TEE]` — Go proxy lifecycle events
- `[Buffer-TEE workflow]` — Flask job and scheduler events
- `[scheduler]` — Scheduler ticks and dispatch decisions

Runtime state is persisted at `/app/cvm_workflow/buffer/` inside the container:
- `jobs/<job_id>/job.json` — job record
- `queue.json` — ordered queue of pending job IDs
- `outgoing/<job_id>-secure-dispatch.json` — encrypted dispatch payload
