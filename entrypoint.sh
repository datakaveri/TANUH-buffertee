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
# The buffer-tee serve mode uses RATLS_SERVER_AUDIENCE (default: ratls-browser) separately.
export TLS_CERT="${TLS_CERT:-/app/certs/tls.crt}"
export TLS_KEY="${TLS_KEY:-/app/certs/tls.key}"

mkdir -p \
  "$BASE_DIR/cvm_workflow/buffer" \
  "$BASE_DIR/cvm_workflow/tls" \
  "$BASE_DIR/cvm_workflow/logs"

for _vm_script in start-gpu-cs-vm.sh stop-gpu-cs-vm.sh start-cpu-cs-vm.sh stop-cpu-cs-vm.sh; do
  if [ -f "/app/${_vm_script}" ]; then
    chmod +x "/app/${_vm_script}"
  fi
done

# Fetch TLS cert from GCP Secret Manager at startup.
# Cert is not baked into the image — fetched at runtime so renewals don't require a rebuild.
_SM_TOKEN=$(curl -sf \
  -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")
_SM_BASE="https://secretmanager.googleapis.com/v1/projects/p3dx-depa-sandbox/secrets"

mkdir -p /run/certs
curl -sf -H "Authorization: Bearer $_SM_TOKEN" \
  "$_SM_BASE/tanuh-tls-cert/versions/latest:access" \
  | python3 -c "import sys,json,base64; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)['payload']['data']))" \
  > /run/certs/tls.crt
curl -sf -H "Authorization: Bearer $_SM_TOKEN" \
  "$_SM_BASE/tanuh-tls-key/versions/latest:access" \
  | python3 -c "import sys,json,base64; sys.stdout.buffer.write(base64.b64decode(json.load(sys.stdin)['payload']['data']))" \
  > /run/certs/tls.key
chmod 600 /run/certs/tls.key

export TLS_CERT=/run/certs/tls.crt
export TLS_KEY=/run/certs/tls.key

# Start the user-facing RA-TLS HTTPS server on :8443 (buffer-tee serve mode).
# It uses RATLS_SERVER_AUDIENCE (browser-facing audience) — kept separate from
# RATLS_AUDIENCE which is used by `buffer-tee dispatch` (Processing TEE audience).
RATLS_AUDIENCE="${RATLS_SERVER_AUDIENCE:-ratls-browser}" \
  /usr/local/bin/buffer-tee &
RATLS_SERVER_PID=$!

cleanup() {
  kill "$RATLS_SERVER_PID" 2>/dev/null || true
}
trap cleanup INT TERM EXIT

cd /app
exec python enclave_manager_buffer.py
