#!/bin/sh
set -eu

export BASE_DIR="${BASE_DIR:-/app}"
export PYTHONUNBUFFERED="${PYTHONUNBUFFERED:-1}"
export PYTHONDONTWRITEBYTECODE="${PYTHONDONTWRITEBYTECODE:-1}"
export BUFFER_TEE_HOST="${BUFFER_TEE_HOST:-0.0.0.0}"
export BUFFER_TEE_PORT="${BUFFER_TEE_PORT:-4100}"
export PROCESSING_TEE_HOST="${PROCESSING_TEE_HOST:-127.0.0.1}"
export PROCESSING_TEE_PORT="${PROCESSING_TEE_PORT:-4000}"
export TEE_USE_TLS="${TEE_USE_TLS:-1}"

mkdir -p \
  "$BASE_DIR/cvm_workflow/buffer" \
  "$BASE_DIR/cvm_workflow/tls" \
  "$BASE_DIR/cvm_workflow/logs"

cd /app
exec python enclave_manager_buffer.py
