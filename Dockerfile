FROM golang:1.22-bullseye AS ratls-client-builder
WORKDIR /src
COPY b2p-ratls/go.mod b2p-ratls/go.sum ./b2p-ratls/
WORKDIR /src/b2p-ratls
RUN go mod download
COPY b2p-ratls/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/buffer-tee ./cmd/buffer-tee/

FROM golang:1.26-bookworm AS ratls-server-builder
WORKDIR /src
COPY Tanuh-buffer-tee-ratls/enclave/go.mod ./
RUN echo "" > go.sum
RUN go mod download
COPY Tanuh-buffer-tee-ratls/enclave/ ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" \
    -o /out/buffer-server ./cmd/buffer-tee/

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
    TLS_CERT=/app/certs/tls.crt \
    TLS_KEY=/app/certs/tls.key

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
COPY --from=ratls-client-builder /out/buffer-tee /usr/local/bin/buffer-tee
COPY --from=ratls-server-builder /out/buffer-server /usr/local/bin/buffer-server
COPY Tanuh-buffer-tee-ratls/enclave/certs /app/certs

RUN chmod +x /app/entrypoint.sh /usr/local/bin/buffer-tee /usr/local/bin/buffer-server \
    && mkdir -p /app/cvm_workflow/buffer /app/cvm_workflow/tls /app/cvm_workflow/logs

LABEL "tee.launch_policy.allow_env_override"="RATLS_SERVER_AUDIENCE,TLS_CERT,TLS_KEY,GPU_CS_IMAGE_DIGEST,KEYCLOAK_JWKS_URL,KEYCLOAK_ISSUER"

EXPOSE 4100 8443

ENTRYPOINT ["/app/entrypoint.sh"]
