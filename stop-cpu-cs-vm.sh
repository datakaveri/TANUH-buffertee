#!/bin/sh
# Stop the CPU fallback Processing TEE VM (clean stop before a restart retry).
set -eu

PROJECT="${PROJECT:-p3dx-depa-sandbox}"
ZONE="${ZONE:-us-central1-a}"
INSTANCE="${INSTANCE:-cpu-cs-snp}"

TOKEN="$(curl -s -H 'Metadata-Flavor: Google' \
  'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token' \
  | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"

if [ -z "${TOKEN}" ]; then
  echo "Failed to get access token from metadata server"
  exit 1
fi

URL="https://compute.googleapis.com/compute/v1/projects/${PROJECT}/zones/${ZONE}/instances/${INSTANCE}/stop?discardLocalSsd=true"

echo "Sending stop request for ${INSTANCE}..."
HTTP_CODE="$(curl -s -o /tmp/stop-cpu-cs-vm-response.json -w '%{http_code}' \
  -X POST \
  -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/json" \
  "${URL}")"

echo "HTTP status: ${HTTP_CODE}"
echo "Response:"
cat /tmp/stop-cpu-cs-vm-response.json
echo

case "${HTTP_CODE}" in
  200|202)
    echo "Stop request accepted for ${INSTANCE}"
    ;;
  *)
    echo "Stop request failed"
    exit 1
    ;;
esac
