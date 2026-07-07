# Single Go binary: `buffer-tee` serves the browser-facing RA-TLS HTTPS
# endpoint (:8443); `buffer-tee dispatch` is the one-shot RA-TLS dispatch
# client the job manager invokes per job.
FROM golang:1.26-bookworm AS go-builder
WORKDIR /src
COPY Tanuh-buffer-tee-ratls/enclave/go.mod Tanuh-buffer-tee-ratls/enclave/go.sum ./
RUN go mod download
COPY Tanuh-buffer-tee-ratls/enclave/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/buffer-tee ./cmd/buffer-tee/

FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PYTHONPATH=/app \
    BASE_DIR=/app \
    DEBIAN_FRONTEND=noninteractive \
    TEE_USE_TLS=0 \
    BUFFER_RATLS_CLIENT_BIN=/usr/local/bin/buffer-tee \
    GPU_CS_ADDR=10.128.15.210:443 \
    GPU_CS_IMAGE_DIGEST=sha256:3fadd63f22df132aa794e2da23e64a6981acdad40f74dcb82b13d753e8598577 \
    RATLS_AUDIENCE=ratls-buffer-tee \
    BUFFER_BOOTSTRAP_PLACEHOLDER_QUEUE=0 \
    SCHEDULER_INTERVAL_SECONDS=15 \
    RATLS_SERVER_AUDIENCE=ratls-browser \
    TLS_CERT=/run/certs/tls.crt \
    TLS_KEY=/run/certs/tls.key

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        curl \
        libgomp1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN python -m pip install --upgrade pip \
    && python -m pip install -r /tmp/requirements.txt

COPY . /app
COPY --from=go-builder /out/buffer-tee /usr/local/bin/buffer-tee

RUN chmod +x /app/entrypoint.sh /usr/local/bin/buffer-tee \
    && mkdir -p /app/cvm_workflow/buffer /app/cvm_workflow/tls /app/cvm_workflow/logs

LABEL "tee.launch_policy.allow_env_override"="RATLS_SERVER_AUDIENCE,TLS_CERT,TLS_KEY,GPU_CS_ADDR,GPU_CS_IMAGE_DIGEST,KEYCLOAK_JWKS_URL,KEYCLOAK_ISSUER,CPU_CS_ADDR,CPU_CS_IMAGE_DIGEST,CPU_CS_INSTANCE,CPU_CS_ZONE,MAX_GPU_PROVISION_ATTEMPTS,PROCESSING_VM_BOOT_TIMEOUT_SECONDS"

EXPOSE 4100 8443

ENTRYPOINT ["/app/entrypoint.sh"]
