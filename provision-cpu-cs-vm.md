# Provisioning the CPU Fallback Processing TEE (`cpu-cs-snp`)

One-time setup so the Buffer TEE can fall back to a CPU Processing TEE when the
GPU VM (`gpu-cs-tdx-h100`) cannot be provisioned after `MAX_GPU_PROVISION_ATTEMPTS`
(default 3) stop→start cycles.

The CPU VM is **pre-created and kept stopped**; the Buffer TEE only *starts* it
on fallback (it is not created on demand). It must be authorized exactly like the
GPU VM so it can decrypt datasets — TANUH gates Secret Manager / GCS access on the
VM's **instance_id** via the Workload Identity Federation (WIF) provider condition.

> ⚠️ A freshly created VM has a NEW instance_id. Without the WIF binding below it
> will be DENIED dataset-key access and cannot run any eval. Do not skip Step 4.

Project: `p3dx-depa-sandbox`. Adjust zone if `us-central1-a` lacks capacity.

---

## Step 0 — Build & push the CPU image

The CPU image is a **separate image with its own digest** (not the GPU image).
See `Processing_TEE/Dockerfile.cpu` + `Processing_TEE/requirements.cpu.txt`.

```bash
cd /home/azureuser/TANUH-machines/Processing_TEE

docker build -f Dockerfile.cpu \
  -t us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls/cpu-cs:latest .
docker push us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls/cpu-cs:latest

# Read back the pushed digest — this is CPU_CS_IMAGE_DIGEST for the Buffer TEE.
gcloud artifacts docker images describe \
  us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls/cpu-cs:latest \
  --format='value(image_summary.digest)'
# -> sha256:....  (record it)
```

> NOTE: the CPU wheel set in `requirements.cpu.txt` has not been built/verified in
> this environment. The first build may surface pip resolution issues with the
> heavier ML libraries; the Dockerfile mirrors the proven GPU build structure.

## Step 1 — Create the stopped CPU Confidential Space VM

CPU-only: **no** `guestAccelerator`, **no** `tee-install-gpu-driver`. Same SA as
the GPU VM. SEV-SNP (not TDX — TDX is GPU-specific here). Created then stopped.

```bash
gcloud compute instances create cpu-cs-snp \
  --zone=us-central1-a \
  --project=p3dx-depa-sandbox \
  --machine-type=n2d-standard-8 \
  --confidential-compute-type=SEV_SNP \
  --maintenance-policy=TERMINATE \
  --image-project=confidential-space-images \
  --image-family=confidential-space \
  --service-account=tanuh-processing-tee@p3dx-depa-sandbox.iam.gserviceaccount.com \
  --scopes=https://www.googleapis.com/auth/cloud-platform \
  --metadata=^~^tee-image-reference=us-central1-docker.pkg.dev/p3dx-depa-sandbox/ratls/cpu-cs:latest~tee-container-log-redirect=true~tee-env-GPU_CS_IMAGE_DIGEST=sha256:<CPU_DIGEST_FROM_STEP_0>

# Stop it — the Buffer TEE starts it only when GPU provisioning is exhausted.
gcloud compute instances stop cpu-cs-snp \
  --zone=us-central1-a --project=p3dx-depa-sandbox
```

> Mirror any other `tee-env-*` metadata the GPU VM carries (RATLS audience,
> callback host, etc.). Compare with:
> `gcloud compute instances describe gpu-cs-tdx-h100 --zone=us-central1-a --format='value(metadata)'`

## Step 2 — Get the CPU VM instance_id

```bash
gcloud compute instances describe cpu-cs-snp \
  --zone=us-central1-a --project=p3dx-depa-sandbox \
  --format="value(id)"
# -> CPU_INSTANCE_ID
```

## Step 3 — Allow the CPU instance_id in the WIF provider

The provider currently pins `attribute.instance_id == '<gpu id>'`. Widen it to
accept either VM. Get the GPU id first if you don't have it:

```bash
GPU_INSTANCE_ID=$(gcloud compute instances describe gpu-cs-tdx-h100 \
  --zone=us-central1-a --project=p3dx-depa-sandbox --format="value(id)")
CPU_INSTANCE_ID=<from Step 2>

gcloud iam workload-identity-pools providers update-oidc tanuh-tee-oidc \
  --location=global \
  --workload-identity-pool=tanuh-tee-pool \
  --project=p3dx-depa-sandbox \
  --attribute-condition="attribute.instance_id == '${GPU_INSTANCE_ID}' || attribute.instance_id == '${CPU_INSTANCE_ID}'"
```

## Step 4 — Bind the SA to the CPU instance_id

```bash
PROJECT_NUMBER=$(gcloud projects describe p3dx-depa-sandbox --format="value(projectNumber)")
CPU_INSTANCE_ID=<from Step 2>

gcloud iam service-accounts add-iam-policy-binding \
  tanuh-processing-tee@p3dx-depa-sandbox.iam.gserviceaccount.com \
  --role=roles/iam.workloadIdentityUser \
  --member="principalSet://iam.googleapis.com/projects/${PROJECT_NUMBER}/locations/global/workloadIdentityPools/tanuh-tee-pool/attribute.instance_id/${CPU_INSTANCE_ID}" \
  --project=p3dx-depa-sandbox
```

Secret Manager (`tanuh-dataset-key-{1,2,3}`) and the GCS dataset bucket are already
granted to the shared SA `tanuh-processing-tee@`, so no further grants are needed
once the WIF binding above is in place.

## Step 5 — Point the Buffer TEE at the CPU VM

Set these on the **buffer-tee-vm** (env / `tee-env-*` metadata, matching how the
Buffer TEE reads config). `CPU_CS_ADDR` is the CPU VM's internal IP + `:443`.

```bash
gcloud compute instances describe cpu-cs-snp \
  --zone=us-central1-a --project=p3dx-depa-sandbox \
  --format="value(networkInterfaces[0].networkIP)"
# -> CPU_INTERNAL_IP
```

| Buffer TEE env var      | Value                                   |
|-------------------------|-----------------------------------------|
| `CPU_CS_ADDR`           | `<CPU_INTERNAL_IP>:443`                  |
| `CPU_CS_IMAGE_DIGEST`   | `sha256:<CPU_DIGEST_FROM_STEP_0>`        |
| `CPU_CS_INSTANCE`       | `cpu-cs-snp` (default)                   |
| `CPU_CS_ZONE`           | `us-central1-a` (default)                |
| `MAX_GPU_PROVISION_ATTEMPTS` | `3` (default)                       |
| `CPU_VM_BOOT_TIMEOUT_SECONDS` | `300` (default)                    |

Until `CPU_CS_ADDR` **and** `CPU_CS_IMAGE_DIGEST` are both set, the fallback path
logs `cpu_unconfigured` and the Buffer TEE behaves as GPU-only (now capped at
`MAX_GPU_PROVISION_ATTEMPTS` stop→start cycles instead of retrying forever).

## Step 6 — Verify

1. Confirm the CPU VM can fetch a dataset key once started (run the same Secret
   Manager fetch the GPU VM uses; it must return 200, not 403 — proves the WIF
   binding works for the new instance_id).
2. Force a fallback: temporarily set `MAX_GPU_PROVISION_ATTEMPTS=0` (or point
   `GPU_CS_ADDR` at an unreachable host) and submit a job. The Buffer log should
   show `GPU attempts exhausted → targeting CPU fallback`, then a CPU start, then
   `RA-TLS dispatch ... target=cpu`.
3. Confirm results land in GCS and the job completes as normal.

---

## Scripts used by the Buffer TEE

| Script (in `Buffer_TEE/`) | Purpose | INSTANCE default |
|---------------------------|---------|------------------|
| `start-gpu-cs-vm.sh`      | start GPU VM            | `gpu-cs-tdx-h100` |
| `stop-gpu-cs-vm.sh`       | stop GPU VM (retry)     | `gpu-cs-tdx-h100` |
| `start-cpu-cs-vm.sh`      | start CPU fallback VM   | `cpu-cs-snp`      |
| `stop-cpu-cs-vm.sh`       | stop CPU fallback VM    | `cpu-cs-snp`      |

All four take `PROJECT`, `ZONE`, `INSTANCE` env overrides.
