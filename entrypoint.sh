#!/bin/sh
set -eu

export BASE_DIR="${BASE_DIR:-/app}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export BUFFER_TEE_HOST="${BUFFER_TEE_HOST:-0.0.0.0}"
export BUFFER_TEE_PORT="${BUFFER_TEE_PORT:-4100}"
export TEE_USE_TLS="${TEE_USE_TLS:-0}"

# RATLS_AUDIENCE is used by the buffer-tee Go CLIENT to verify the Processing TEE
# (aud=ratls-buffer-tee in the Processing TEE's OIDC token). Do NOT change it.
# The Tanuh buffer-server uses RATLS_SERVER_AUDIENCE (default: ratls-browser) separately.
export TLS_CERT="${TLS_CERT:-/app/certs/tls.crt}"
export TLS_KEY="${TLS_KEY:-/app/certs/tls.key}"

mkdir -p \
  "$BASE_DIR/cvm_workflow/buffer" \
  "$BASE_DIR/cvm_workflow/tls" \
  "$BASE_DIR/cvm_workflow/logs"

if [ -f /app/start-gpu-cs-vm.sh ]; then
  chmod +x /app/start-gpu-cs-vm.sh
fi

# Start the user-facing RA-TLS HTTPS server on :8443.
# It uses RATLS_SERVER_AUDIENCE (browser-facing audience) — kept separate from
# RATLS_AUDIENCE which is used by the buffer-tee dispatch client.
RATLS_AUDIENCE="${RATLS_SERVER_AUDIENCE:-ratls-browser}" \
  /usr/local/bin/buffer-server &
RATLS_SERVER_PID=$!

cleanup() {
  kill "$RATLS_SERVER_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

cd /app
exec python enclave_manager_buffer.py
