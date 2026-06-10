# Buffer TEE Image

This directory is a self-contained Docker build context for the always-on Buffer TEE.

The image:
- builds the RA-TLS Buffer client from `b2p-ratls`
- starts `enclave_manager_buffer.py` on port `4100`
- optionally bootstraps two placeholder ResNet34 ONNX jobs for dataset IDs `1` and `2`
- starts the Processing TEE VM through `start-gpu-cs-vm.sh` when no RA-TLS Processing endpoint is healthy
- dispatches the scheduled job payload over RA-TLS to GPU CS
- receives Processing results at `/buffer/jobs/<job_id>/results`

Important runtime env vars, supplied through Confidential Space metadata as `tee-env-*`:
- `BUFFER_BOOTSTRAP_PLACEHOLDER_QUEUE=1`
- `GPU_CS_ADDR=<processing-internal-ip>:443`
- `GPU_CS_IMAGE_DIGEST=sha256:<gpu-cs-image-digest>`
- `RATLS_AUDIENCE=ratls-buffer-tee`
- `SCHEDULER_INTERVAL_SECONDS=15`

Debug trail:
- VM serial/container logs include `[Buffer-TEE workflow]` and `[scheduler]` lines.
- Runtime state is written under `/app/cvm_workflow/buffer` inside the container.
