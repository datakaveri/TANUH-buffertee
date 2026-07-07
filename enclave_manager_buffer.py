"""
Buffer TEE — Enclave Manager
============================

Flow:
  1. User-Facing UI establishes RA-TLS to the buffer-tee Go server (port 8443).
  2. User uploads model.onnx + weights, encrypted via HPKE inside the browser.
  3. The Go server decrypts inside the TEE, then POSTs to /buffer/jobs here.
  4. job_scheduler.py dispatches the job to the Processing TEE via RA-TLS
     (`buffer-tee dispatch` → gpu-cs Go server on port 443).
  5. Processing TEE decrypts dataset, runs ONNX inference, submits results to
     the external leaderboard, then self-deallocates.
  6. The scheduler finalizes the dispatched job once its Processing TEE has
     self-deallocated (see _finalize_dispatched_jobs for the stop-gap caveat).
"""

import base64
import hashlib
import json
import os
import time
import uuid
from pathlib import Path

import requests
import job_scheduler

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from lib.buffer_lock import job_file_lock
from lib.config import config


# ── App setup ─────────────────────────────────────────────────────────────────

app = Flask(__name__)
CORS(app, resources={r"/*": {
    "origins": config.cors.origins,
    "methods": config.cors.methods,
    "allow_headers": config.cors.allow_headers,
    "expose_headers": config.cors.expose_headers,
    "supports_credentials": config.cors.supports_credentials,
    "max_age": config.cors.max_age,
}}, supports_credentials=True)


# ── Paths ─────────────────────────────────────────────────────────────────────

BUFFER_WORKFLOW_DIR         = Path(config.base_dir) / "cvm_workflow" / "buffer"
BUFFER_JOBS_DIR             = BUFFER_WORKFLOW_DIR / "jobs"
BUFFER_QUEUE_FILE           = BUFFER_WORKFLOW_DIR / "queue.json"
BUFFER_OUTGOING_DIR         = BUFFER_WORKFLOW_DIR / "outgoing"
BUFFER_RUNTIME_DIR          = BUFFER_WORKFLOW_DIR / "runtime"
BUFFER_SHARED_ARTIFACTS_DIR = BUFFER_WORKFLOW_DIR / "shared_artifacts"
DISPATCH_STATE_FILE         = BUFFER_RUNTIME_DIR / "dispatch_state.json"

MODEL_FILE_NAME          = "model.onnx"
WEIGHTS_FILE_NAME        = "model.onnx.data"
PREPROCESSING_FILE_NAME  = "preprocessing.py"

BUFFER_TEE_HOST  = os.getenv("BUFFER_TEE_HOST",  "0.0.0.0")
BUFFER_TEE_PORT  = int(os.getenv("BUFFER_TEE_PORT", "4100"))

PROCESSING_RATLS_ADDR             = os.getenv("GPU_CS_ADDR", "10.128.15.210:443")
PROCESSING_RATLS_HEALTHCHECK_URL  = os.getenv("PROCESSING_RATLS_HEALTHCHECK_URL",
                                               f"https://{PROCESSING_RATLS_ADDR}/healthz")
PROCESSING_VM_START_SCRIPT        = os.getenv("PROCESSING_VM_START_SCRIPT",
                                               str(Path(config.base_dir) / "start-gpu-cs-vm.sh"))
PROCESSING_VM_START_COMMAND       = os.getenv("PROCESSING_VM_START_COMMAND", "")
PROCESSING_VM_START_COOLDOWN_SECONDS = int(os.getenv("PROCESSING_VM_START_COOLDOWN_SECONDS", "45"))
PROCESSING_VM_BOOT_TIMEOUT_SECONDS  = int(os.getenv("PROCESSING_VM_BOOT_TIMEOUT_SECONDS", "300"))
PROCESSING_VM_BOOT_POLL_INTERVAL    = int(os.getenv("PROCESSING_VM_BOOT_POLL_INTERVAL_SECONDS", "5"))
PROCESSING_EXPECTED_IMAGE_DIGEST    = os.getenv("GPU_CS_IMAGE_DIGEST", "")

# ── GPU / CPU provisioning targets ─────────────────────────────────────────────
# The Buffer TEE first tries to provision the GPU Processing TEE. If it fails to
# become healthy after MAX_GPU_PROVISION_ATTEMPTS stop→start cycles, it falls
# back to a pre-provisioned CPU Processing TEE VM (separate image, own digest).
# The fallback is per-job and non-sticky: every new job tries the GPU first.

MAX_GPU_PROVISION_ATTEMPTS        = int(os.getenv("MAX_GPU_PROVISION_ATTEMPTS", "3"))

# GPU VM identity + stop hook (for the clean stop→start retry cycle).
GPU_CS_INSTANCE                   = os.getenv("GPU_CS_INSTANCE", "gpu-cs-tdx-h100")
GPU_CS_ZONE                       = os.getenv("GPU_CS_ZONE", "us-central1-a")
GPU_VM_STOP_SCRIPT                = os.getenv("GPU_VM_STOP_SCRIPT",
                                               str(Path(config.base_dir) / "stop-gpu-cs-vm.sh"))

# CPU fallback VM. CPU_CS_ADDR must be set for the fallback path to function;
# if unset, provisioning degrades to GPU-only (capped at MAX_GPU_PROVISION_ATTEMPTS).
CPU_CS_ADDR                       = os.getenv("CPU_CS_ADDR", "")
CPU_RATLS_HEALTHCHECK_URL         = os.getenv("CPU_RATLS_HEALTHCHECK_URL",
                                               f"https://{CPU_CS_ADDR}/healthz" if CPU_CS_ADDR else "")
CPU_CS_INSTANCE                   = os.getenv("CPU_CS_INSTANCE", "cpu-cs-snp")
CPU_CS_ZONE                       = os.getenv("CPU_CS_ZONE", "us-central1-a")
CPU_VM_START_SCRIPT               = os.getenv("CPU_VM_START_SCRIPT",
                                               str(Path(config.base_dir) / "start-cpu-cs-vm.sh"))
CPU_VM_STOP_SCRIPT                = os.getenv("CPU_VM_STOP_SCRIPT",
                                               str(Path(config.base_dir) / "stop-cpu-cs-vm.sh"))
CPU_VM_BOOT_TIMEOUT_SECONDS       = int(os.getenv("CPU_VM_BOOT_TIMEOUT_SECONDS", "300"))
# Distinct image digest for the CPU build. Required for CPU dispatch — there is
# no safe default (the CPU image is a different image than the GPU one).
CPU_CS_IMAGE_DIGEST               = os.getenv("CPU_CS_IMAGE_DIGEST", "")
# How long to wait for a VM to reach a stopped/TERMINATED state before restarting
# it during a retry cycle. Bounded so a stuck stop never hangs the scheduler.
VM_STOP_WAIT_SECONDS              = int(os.getenv("VM_STOP_WAIT_SECONDS", "60"))
# A job marked "dispatched" whose Processing TEE died before producing results
# would otherwise block the scheduler forever. If results are still absent from
# local disk, the VM is unhealthy, and at least this many seconds have passed
# since dispatch, treat the job as orphaned and requeue it for re-dispatch.
DISPATCH_ORPHAN_GRACE_SECONDS       = int(os.getenv("DISPATCH_ORPHAN_GRACE_SECONDS", "60"))

BUFFER_RATLS_CLIENT_BIN    = os.getenv("BUFFER_RATLS_CLIENT_BIN", "")
BUFFER_RATLS_CLIENT_WORKDIR = Path(os.getenv("BUFFER_RATLS_CLIENT_WORKDIR",
                                              str(Path(config.base_dir) / "Tanuh-buffer-tee-ratls" / "enclave")))

import subprocess, sys


# ── Logging ───────────────────────────────────────────────────────────────────

def buffer_debug(message):
    print(f"[Buffer-TEE] {message}", flush=True)


# ── Directory helpers ─────────────────────────────────────────────────────────

def _ensure_dirs():
    for d in (BUFFER_WORKFLOW_DIR, BUFFER_JOBS_DIR, BUFFER_OUTGOING_DIR,
              BUFFER_RUNTIME_DIR, BUFFER_SHARED_ARTIFACTS_DIR):
        d.mkdir(parents=True, exist_ok=True)


# ── JSON helpers ──────────────────────────────────────────────────────────────

def _json_dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _json_load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


# ── Queue helpers ─────────────────────────────────────────────────────────────

def _read_queue():
    if BUFFER_QUEUE_FILE.exists():
        return _json_load(BUFFER_QUEUE_FILE)
    return {"queued_job_ids": []}


def _write_queue(payload):
    _json_dump(BUFFER_QUEUE_FILE, payload)


def _queue_job(job):
    q = _read_queue()
    q.setdefault("queued_job_ids", []).append(job["job_id"])
    _write_queue(q)


def _remove_job_from_queue(job_id):
    q = _read_queue()
    q["queued_job_ids"] = [jid for jid in q.get("queued_job_ids", []) if jid != job_id]
    _write_queue(q)


def _next_queued_job():
    for job_id in _read_queue().get("queued_job_ids", []):
        path = _job_metadata_path(job_id)
        if path.exists():
            job = _json_load(path)
            if job.get("status") == "queued":
                return job
    return None


# ── Job file helpers ──────────────────────────────────────────────────────────

def _job_dir(job_id):           return BUFFER_JOBS_DIR / job_id
def _job_metadata_path(job_id): return _job_dir(job_id) / "job.json"
def _job_results_path(job_id):  return _job_dir(job_id) / "results.json"
def _all_job_metadata_paths():  return sorted(BUFFER_JOBS_DIR.glob("*/job.json"))

def _load_job(job_id):   return _json_load(_job_metadata_path(job_id))
def _save_job(job):      _json_dump(_job_metadata_path(job["job_id"]), job)


# ── Dispatch state ────────────────────────────────────────────────────────────

def _dispatch_state():
    if DISPATCH_STATE_FILE.exists():
        return _json_load(DISPATCH_STATE_FILE)
    return {
        "last_vm_start_request_unix": 0,
        "last_vm_start_mode": "",
        "last_vm_healthcheck_unix": 0,
        "last_vm_healthcheck_ok": False,
        "last_dispatch_attempt_unix": 0,
        "last_dispatch_job_id": "",
        "last_dispatch_status": "",
        "last_dispatch_error": "",
    }


def _save_dispatch_state(state):
    _json_dump(DISPATCH_STATE_FILE, state)


def _update_dispatch_state(**updates):
    state = _dispatch_state()
    state.update(updates)
    _save_dispatch_state(state)
    return state


# ── Job creation ──────────────────────────────────────────────────────────────

def _canonical_dataset_id(dataset_id):
    dataset_id = int(dataset_id)
    if dataset_id not in (1, 2, 3):
        raise ValueError("dataset_id must be 1, 2, or 3")
    return dataset_id


def _save_uploaded_artifacts(job_dir, content):
    """Write model.onnx and weights from base64 fields sent by the browser UI."""
    artifacts_dir = Path(job_dir) / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    model_bytes   = base64.b64decode(content["model_onnx_base64"])
    weights_bytes = base64.b64decode(content["model_weights_base64"])
    model_path    = artifacts_dir / MODEL_FILE_NAME
    weights_path  = artifacts_dir / WEIGHTS_FILE_NAME
    model_path.write_bytes(model_bytes)
    weights_path.write_bytes(weights_bytes)
    return model_path, weights_path


def _create_job_record(content):
    """
    Create a job from metadata. Model files are uploaded separately.

    Required: dataset_id
    Optional: model_sha256, weights_sha256, submitted_by
    """
    _ensure_dirs()
    dataset_id = _canonical_dataset_id(content.get("dataset_id", 1))
    job_id     = content.get("job_id") or f"job-{uuid.uuid4().hex[:12]}"
    job_dir    = _job_dir(job_id)

    if job_dir.exists():
        raise ValueError(f"Job {job_id} already exists")

    (job_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    # Status is "pending_upload" until model + weights arrive via binary upload
    job = {
        "job_id":            job_id,
        "status":            "pending_upload",
        "dataset_id":        dataset_id,
        "submitted_at_unix": int(time.time()),
        "updated_at_unix":   int(time.time()),
        "hyperparameters":   content.get("hyperparameters", {}),
        "model_file":        MODEL_FILE_NAME,
        "weights_file":      WEIGHTS_FILE_NAME,
        "artifact_dir":      str(job_dir / "artifacts"),
        "submitted_by":      content.get("submitted_by", "unknown"),
        "keycloak_token":    content.get("keycloak_token", ""),
        "model_sha256_expected":          content.get("model_sha256", ""),
        "weights_sha256_expected":        content.get("weights_sha256", ""),
        "preprocessing_sha256_expected":  content.get("preprocessing_sha256", ""),
        "notes":             content.get("notes", ""),
    }
    _save_job(job)
    return job  # NOT queued yet — queued after files arrive


def _receive_artifact(job_id, artifact_name, data: bytes):
    """Write a binary artifact and queue the job when all required files are present."""
    _ensure_dirs()
    job = _load_job(job_id)
    if job["status"] not in ("pending_upload",):
        raise ValueError(f"Job {job_id} is not awaiting upload (status={job['status']})")

    allowed = {MODEL_FILE_NAME, WEIGHTS_FILE_NAME, PREPROCESSING_FILE_NAME}
    if artifact_name not in allowed:
        raise ValueError(f"Unknown artifact name: {artifact_name}")

    artifacts_dir = Path(job["artifact_dir"])
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    path = artifacts_dir / artifact_name
    path.write_bytes(data)

    sha256_actual = hashlib.sha256(data).hexdigest()
    sha256_key_map = {
        MODEL_FILE_NAME:         "model_sha256_expected",
        WEIGHTS_FILE_NAME:       "weights_sha256_expected",
        PREPROCESSING_FILE_NAME: "preprocessing_sha256_expected",
    }
    sha256_expected = job.get(sha256_key_map[artifact_name], "")
    if sha256_expected and sha256_actual != sha256_expected:
        raise ValueError(
            f"SHA256 mismatch for {artifact_name}: "
            f"expected {sha256_expected}, got {sha256_actual}"
        )

    job["updated_at_unix"] = int(time.time())

    # If the client committed to a preprocessing hash in /v1/submit, wait for
    # preprocessing.py before queuing — regardless of dataset_id.
    model_path         = artifacts_dir / MODEL_FILE_NAME
    weights_path       = artifacts_dir / WEIGHTS_FILE_NAME
    preprocessing_path = artifacts_dir / PREPROCESSING_FILE_NAME
    all_required = model_path.exists() and weights_path.exists()
    if all_required and job.get("preprocessing_sha256_expected", ""):
        all_required = preprocessing_path.exists()

    if all_required:
        job["status"] = "queued"
        _save_job(job)
        _queue_job(job)
        buffer_debug(f"Job {job_id} all required files received — queued")
    else:
        _save_job(job)
        buffer_debug(f"Job {job_id} artifact {artifact_name} saved ({len(data)//1024} KB)")

    return job


# ── Artifact serving ──────────────────────────────────────────────────────────

def _artifact_path(job_id, artifact_name):
    allowed = {MODEL_FILE_NAME, WEIGHTS_FILE_NAME, PREPROCESSING_FILE_NAME}
    if artifact_name not in allowed:
        raise FileNotFoundError(f"Unknown artifact: {artifact_name}")
    path = _job_dir(job_id) / "artifacts" / artifact_name
    if not path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_name}")
    return path


def _artifact_bytes(job_id, artifact_name):
    return _artifact_path(job_id, artifact_name).read_bytes()


# ── Processing TEE health & start ─────────────────────────────────────────────

def _vm_is_healthy(healthcheck_url, label="Processing TEE"):
    """Probe a TEE /healthz endpoint. Records the result in dispatch state."""
    if not healthcheck_url:
        buffer_debug(f"{label} healthcheck skipped — no healthcheck URL configured")
        return False
    try:
        resp = requests.get(healthcheck_url, timeout=5, verify=False)
        ok = resp.status_code == 200
        _update_dispatch_state(
            last_vm_healthcheck_unix=int(time.time()),
            last_vm_healthcheck_ok=ok,
        )
        buffer_debug(f"{label} healthcheck → {resp.status_code}")
        return ok
    except Exception as exc:
        _update_dispatch_state(
            last_vm_healthcheck_unix=int(time.time()),
            last_vm_healthcheck_ok=False,
            last_dispatch_error=f"healthcheck failed: {exc}",
        )
        buffer_debug(f"{label} healthcheck failed: {exc}")
        return False


def _processing_vm_is_healthy():
    """Backward-compatible GPU healthcheck wrapper."""
    return _vm_is_healthy(PROCESSING_RATLS_HEALTHCHECK_URL, "Processing TEE (GPU)")


def _resolve_start_command(start_script, start_command=""):
    """Resolve a (target, mode) pair for a VM start/stop action. A non-empty
    command takes precedence over the script path."""
    if start_command and start_command.strip():
        return start_command.strip(), "command"
    candidate = Path(start_script)
    if candidate.exists():
        return str(candidate), "script"
    return "", ""


def _run_vm_subprocess(target, mode, action_label):
    """Run a VM start/stop script or command. Returns True on exit 0."""
    try:
        completed = subprocess.run(
            [target] if mode == "script" else target,
            cwd=config.base_dir,
            capture_output=True, text=True,
            timeout=60, check=False,
            shell=(mode == "command"),
        )
    except Exception as exc:
        buffer_debug(f"{action_label} failed: {exc}")
        return False, f"{action_label} error: {exc}"

    if completed.stdout: print(completed.stdout, end="", flush=True)
    if completed.stderr: print(completed.stderr, end="", flush=True)

    if completed.returncode != 0:
        buffer_debug(f"{action_label} exited with {completed.returncode}")
        return False, f"{action_label} exited {completed.returncode}"
    return True, ""


def _request_vm_start(start_script, label, cooldown_key, start_command=""):
    """Request a VM start, honouring a per-target cooldown so the GPU cooldown
    does not block a CPU start attempt (and vice versa). cooldown_key namespaces
    the last-start timestamp in dispatch state."""
    now = int(time.time())
    state = _dispatch_state()
    last_key = f"last_vm_start_request_unix_{cooldown_key}"
    last = int(state.get(last_key, state.get("last_vm_start_request_unix", 0)))
    if now - last < PROCESSING_VM_START_COOLDOWN_SECONDS:
        buffer_debug(f"{label} start skipped — within cooldown window")
        return False

    start_target, start_mode = _resolve_start_command(start_script, start_command)
    if not start_target:
        buffer_debug(f"No {label} start command configured")
        _update_dispatch_state(**{
            last_key: now,
            "last_vm_start_request_unix": now,
            "last_vm_start_mode": "missing",
            "last_dispatch_error": f"No {label} start command configured",
        })
        return False

    buffer_debug(f"Starting {label} via {start_mode}: {start_target}")
    ok, err = _run_vm_subprocess(start_target, start_mode, f"{label} start")
    _update_dispatch_state(**{
        last_key: now,
        "last_vm_start_request_unix": now,
        "last_vm_start_mode": start_mode,
        "last_dispatch_error": err,
    })
    return ok


def _request_processing_vm_start():
    """Backward-compatible GPU start wrapper."""
    return _request_vm_start(
        PROCESSING_VM_START_SCRIPT, "Processing TEE (GPU)", "gpu",
        start_command=PROCESSING_VM_START_COMMAND,
    )


def _stop_vm(stop_script, label):
    """Request a VM stop and wait (bounded by VM_STOP_WAIT_SECONDS) for it to
    stop responding to healthchecks, so the following start is a clean boot.
    A best-effort step: failures are logged but do not abort the retry."""
    stop_target, stop_mode = _resolve_start_command(stop_script)
    if not stop_target:
        buffer_debug(f"No {label} stop command configured — skipping clean stop")
        return False
    buffer_debug(f"Stopping {label} via {stop_mode}: {stop_target}")
    ok, err = _run_vm_subprocess(stop_target, stop_mode, f"{label} stop")
    if not ok:
        buffer_debug(f"{label} stop request did not succeed cleanly: {err}")
    # Give the stop a bounded window to take effect. We don't have a status API
    # here, so we simply pause; the subsequent start is idempotent regardless.
    waited = 0
    while waited < VM_STOP_WAIT_SECONDS:
        time.sleep(min(PROCESSING_VM_BOOT_POLL_INTERVAL, VM_STOP_WAIT_SECONDS - waited))
        waited += PROCESSING_VM_BOOT_POLL_INTERVAL
    return ok


def _wait_for_vm(healthcheck_url, timeout_seconds, label="Processing TEE"):
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if _vm_is_healthy(healthcheck_url, label):
            buffer_debug(f"{label} is healthy and ready")
            return True
        time.sleep(PROCESSING_VM_BOOT_POLL_INTERVAL)
    buffer_debug(f"{label} did not become healthy within {timeout_seconds}s")
    return False


def _wait_for_processing_vm():
    """Backward-compatible GPU boot wait wrapper."""
    return _wait_for_vm(
        PROCESSING_RATLS_HEALTHCHECK_URL, PROCESSING_VM_BOOT_TIMEOUT_SECONDS,
        "Processing TEE (GPU)",
    )


# ── Provisioning orchestration (GPU-first, 3-retry, CPU fallback) ──────────────

def _try_cpu_fallback(job):
    """Provision the CPU fallback Processing TEE. Returns (addr, digest) on
    success or (None, None). The CPU VM is pre-provisioned and authorized, so
    this starts it (it is not created on demand). Polled every tick until it
    comes up — a job never auto-fails on provisioning."""
    if not CPU_CS_ADDR:
        buffer_debug("CPU fallback unavailable — CPU_CS_ADDR not configured")
        _update_dispatch_state(
            last_dispatch_status="cpu_unconfigured",
            last_dispatch_error="CPU fallback requested but CPU_CS_ADDR is unset",
        )
        return None, None
    if not CPU_CS_IMAGE_DIGEST:
        buffer_debug("CPU fallback unavailable — CPU_CS_IMAGE_DIGEST not configured")
        _update_dispatch_state(
            last_dispatch_status="cpu_unconfigured",
            last_dispatch_error="CPU fallback requested but CPU_CS_IMAGE_DIGEST is unset",
        )
        return None, None

    job["provisioning_target"] = "cpu"
    _save_job(job)

    if _vm_is_healthy(CPU_RATLS_HEALTHCHECK_URL, "Processing TEE (CPU)"):
        return CPU_CS_ADDR, CPU_CS_IMAGE_DIGEST

    buffer_debug("CPU Processing TEE not healthy — requesting start")
    _update_dispatch_state(
        last_dispatch_status="awaiting_cpu",
        last_dispatch_error="GPU exhausted; provisioning CPU fallback",
    )
    if _request_vm_start(CPU_VM_START_SCRIPT, "Processing TEE (CPU)", "cpu"):
        if _wait_for_vm(CPU_RATLS_HEALTHCHECK_URL, CPU_VM_BOOT_TIMEOUT_SECONDS,
                        "Processing TEE (CPU)"):
            return CPU_CS_ADDR, CPU_CS_IMAGE_DIGEST
    return None, None


def _provision_processing_tee(job):
    """Decide which Processing TEE to dispatch this job to.

    Returns (ratls_addr, image_digest) for the healthy target, or (None, None)
    if neither GPU nor CPU could be provisioned this cycle (the job stays queued
    and the scheduler retries next tick).

    GPU is attempted first via up to MAX_GPU_PROVISION_ATTEMPTS stop→start
    cycles, counted per-job in job["gpu_provision_attempts"] (persisted each
    attempt so a Buffer restart does not reset the count). Once the count is
    exhausted, the job targets the CPU fallback directly — including on later
    scheduler ticks — until the CPU VM comes up. The fallback is non-sticky:
    each new job starts with gpu_provision_attempts == 0 and tries the GPU.
    """
    attempts = int(job.get("gpu_provision_attempts", 0))

    # Already exhausted GPU on a previous tick → go straight to CPU.
    if attempts >= MAX_GPU_PROVISION_ATTEMPTS:
        buffer_debug(
            f"Job {job['job_id']}: GPU attempts exhausted ({attempts}/"
            f"{MAX_GPU_PROVISION_ATTEMPTS}) — targeting CPU fallback"
        )
        return _try_cpu_fallback(job)

    # GPU already healthy → use it without consuming an attempt.
    if _vm_is_healthy(PROCESSING_RATLS_HEALTHCHECK_URL, "Processing TEE (GPU)"):
        job["provisioning_target"] = "gpu"
        _save_job(job)
        return PROCESSING_RATLS_ADDR, PROCESSING_EXPECTED_IMAGE_DIGEST

    # GPU stop→start retry loop, capped, persisted per-job. An attempt is only
    # counted when a start is actually issued — a start skipped by the cooldown
    # does not burn an attempt (the scheduler simply retries on a later tick).
    while int(job.get("gpu_provision_attempts", 0)) < MAX_GPU_PROVISION_ATTEMPTS:
        prior_attempts = int(job.get("gpu_provision_attempts", 0))
        attempt_no     = prior_attempts + 1
        buffer_debug(
            f"Job {job['job_id']}: GPU provision attempt "
            f"{attempt_no}/{MAX_GPU_PROVISION_ATTEMPTS}"
        )
        _update_dispatch_state(
            last_dispatch_status="provisioning_gpu",
            last_dispatch_error=f"GPU attempt {attempt_no}/{MAX_GPU_PROVISION_ATTEMPTS}",
        )
        # On a retry (not the first attempt) do a clean stop→start so a VM stuck
        # in a bad running state is rebooted. The first attempt of a cold cycle
        # skips the stop — the VM is simply off and stopping wastes the wait.
        if prior_attempts > 0:
            _stop_vm(GPU_VM_STOP_SCRIPT, "Processing TEE (GPU)")
        if not _request_vm_start(PROCESSING_VM_START_SCRIPT, "Processing TEE (GPU)",
                                 "gpu", start_command=PROCESSING_VM_START_COMMAND):
            # Start was skipped (cooldown) or unconfigured — no boot happened, so
            # do NOT consume an attempt. Bail out; the scheduler retries next tick.
            buffer_debug(
                f"Job {job['job_id']}: GPU start not issued this tick "
                f"(cooldown/unconfigured) — retrying next cycle"
            )
            return None, None
        # A real start was issued → consume the attempt and persist it.
        job["gpu_provision_attempts"] = attempt_no
        job["provisioning_target"]    = "gpu"
        _save_job(job)
        if _wait_for_vm(PROCESSING_RATLS_HEALTHCHECK_URL,
                        PROCESSING_VM_BOOT_TIMEOUT_SECONDS, "Processing TEE (GPU)"):
            return PROCESSING_RATLS_ADDR, PROCESSING_EXPECTED_IMAGE_DIGEST
        # Not healthy within PROCESSING_VM_BOOT_TIMEOUT_SECONDS → stop the GPU VM
        # so a failed / half-booted H100 is not left running (and billing) while
        # we retry or fall back to CPU.
        buffer_debug(
            f"Job {job['job_id']}: GPU not healthy within "
            f"{PROCESSING_VM_BOOT_TIMEOUT_SECONDS}s — stopping the GPU VM"
        )
        _stop_vm(GPU_VM_STOP_SCRIPT, "Processing TEE (GPU)")

    # GPU exhausted this cycle → fall back to CPU.
    buffer_debug(
        f"Job {job['job_id']}: GPU provisioning exhausted after "
        f"{MAX_GPU_PROVISION_ATTEMPTS} attempts — falling back to CPU"
    )
    return _try_cpu_fallback(job)


# ── RA-TLS dispatch ───────────────────────────────────────────────────────────

def _buffer_url(path):
    """Public URL the Processing TEE can use to call back into this service."""
    host = os.getenv("BUFFER_TEE_CALLBACK_HOST") or BUFFER_TEE_HOST
    if host in ("0.0.0.0", "::"):
        try:
            import socket
            host = socket.gethostbyname(socket.gethostname())
        except Exception:
            host = "127.0.0.1"
    return f"http://{host}:{BUFFER_TEE_PORT}{path}"


def _build_secure_dispatch_payload(job):
    model_bytes   = _artifact_bytes(job["job_id"], MODEL_FILE_NAME)
    weights_bytes = _artifact_bytes(job["job_id"], WEIGHTS_FILE_NAME)
    payload = {
        "job_id":            job["job_id"],
        "dataset_id":        job["dataset_id"],
        "submitted_at_unix": job["submitted_at_unix"],
        "submitted_by":      job.get("submitted_by", ""),
        "keycloak_token":    job.get("keycloak_token", ""),
        "hyperparameters":   job["hyperparameters"],
        "model_file":        MODEL_FILE_NAME,
        "weights_file":      WEIGHTS_FILE_NAME,
        "model_sha256":      hashlib.sha256(model_bytes).hexdigest(),
        "weights_sha256":    hashlib.sha256(weights_bytes).hexdigest(),
        "model_onnx_base64":    base64.b64encode(model_bytes).decode(),
        "model_weights_base64": base64.b64encode(weights_bytes).decode(),
        "buffer_job_url":    _buffer_url(f"/buffer/jobs/{job['job_id']}"),
    }
    # Include preprocessing script for Oral Cancer jobs
    preprocessing_path = Path(job["artifact_dir"]) / PREPROCESSING_FILE_NAME
    if preprocessing_path.exists():
        preprocessing_bytes = preprocessing_path.read_bytes()
        payload["preprocessing_script_base64"] = base64.b64encode(preprocessing_bytes).decode()
        payload["preprocessing_sha256"] = hashlib.sha256(preprocessing_bytes).hexdigest()
    return payload


def _write_secure_dispatch_payload(job):
    payload      = _build_secure_dispatch_payload(job)
    payload_path = BUFFER_OUTGOING_DIR / f"{job['job_id']}-secure-dispatch.json"
    _json_dump(payload_path, payload)
    return payload_path, payload


def _ratls_client_command():
    """Dispatch runs via the single buffer-tee binary in `dispatch` mode."""
    if BUFFER_RATLS_CLIENT_BIN.strip():
        return [BUFFER_RATLS_CLIENT_BIN.strip(), "dispatch"], None
    linux = BUFFER_RATLS_CLIENT_WORKDIR / "buffer-tee"
    if linux.exists():
        return [str(linux), "dispatch"], None
    return ["go", "run", "./cmd/buffer-tee", "dispatch"], str(BUFFER_RATLS_CLIENT_WORKDIR)


def _run_ratls_dispatch(job, payload_path, addr=None, image_digest=None):
    """Dispatch a job to a Processing TEE over RA-TLS. addr/image_digest select
    the target (GPU or CPU fallback); both default to the GPU target. The Go
    RA-TLS client validates the server's attested image digest against
    image_digest, so a CPU dispatch must pass the CPU image's digest."""
    addr         = addr or PROCESSING_RATLS_ADDR
    image_digest = image_digest or PROCESSING_EXPECTED_IMAGE_DIGEST
    if not image_digest:
        raise ValueError("Processing TEE image digest must be set before dispatching")

    command, override_workdir = _ratls_client_command()
    workdir = override_workdir or config.base_dir
    env = os.environ.copy()
    env["GPU_CS_ADDR"]          = addr
    env["RATLS_AUDIENCE"]       = env.get("RATLS_AUDIENCE", "ratls-buffer-tee")
    env["GPU_CS_IMAGE_DIGEST"]  = image_digest
    env["JOB_PAYLOAD_PATH"]     = str(payload_path)
    env.setdefault("GOTELEMETRY", "off")

    buffer_debug(
        f"RA-TLS dispatch: {' '.join(command)} → job {job['job_id']} "
        f"(target={job.get('provisioning_target', 'gpu')} addr={addr})"
    )
    completed = subprocess.run(
        command, cwd=workdir, env=env,
        capture_output=True, text=True,
        timeout=180, check=False,
    )
    if completed.stdout: print(completed.stdout, end="", flush=True)
    if completed.stderr: print(completed.stderr, end="", flush=True)
    if completed.returncode != 0:
        raise RuntimeError(f"RA-TLS dispatch failed (exit {completed.returncode})")


def _mark_job_dispatched(job_id, payload_path, addr=None):
    job = _load_job(job_id)
    job["status"]                  = "dispatched"
    job["assigned_processing_tee"] = addr or PROCESSING_RATLS_ADDR
    job["dispatched_at_unix"]      = int(time.time())
    job["updated_at_unix"]         = int(time.time())
    job["delivery"] = {"mode": "ratls_json_payload", "payload_path": str(payload_path)}
    _save_job(job)
    _remove_job_from_queue(job_id)
    return job


# ── Main scheduler dispatch callback ─────────────────────────────────────────

def _finalize_dispatched_jobs():
    """
    Mark dispatched jobs complete once their Processing TEE has finished.

    In the current design the Processing TEE delivers results to the external
    leaderboard and then self-deallocates; it does NOT report completion back to
    the buffer. So a job that was dispatched and whose Processing TEE is no
    longer running is DONE — not orphaned. Marking it "complete" drains the
    queue and prevents the scheduler from re-dispatching (and re-running) it.

    TEMPORARY stop-gap (fire-and-forget): the buffer cannot distinguish a clean
    finish from a mid-eval crash this way. The proper fix is a completion
    callback from the Processing TEE to buffer_job_url (already forwarded in the
    dispatch payload) carrying the real terminal status, which would let us
    requeue only genuine failures. See _run_ratls_dispatch / _build_secure_dispatch_payload.

    A dispatched job is finalized when BOTH:
      - the dispatch happened at least DISPATCH_ORPHAN_GRACE_SECONDS ago, and
      - the assigned Processing TEE is not currently healthy (a live eval keeps
        it up — those are left running).
    Returns the list of finalized job_ids.
    """
    finalized = []
    now = int(time.time())
    with job_file_lock:
        dispatched = [
            _json_load(p) for p in _all_job_metadata_paths()
            if _json_load(p).get("status") == "dispatched"
        ]
    if not dispatched:
        return finalized

    for job in dispatched:
        job_id = job.get("job_id")
        if now - int(job.get("dispatched_at_unix", 0)) < DISPATCH_ORPHAN_GRACE_SECONDS:
            continue
        # If the assigned Processing TEE is still healthy, an eval may be in
        # flight — leave it alone. Probe the assigned TEE (GPU or CPU fallback),
        # not just the GPU, so a live CPU eval is never finalized prematurely.
        assigned_addr = job.get("assigned_processing_tee", "") or PROCESSING_RATLS_ADDR
        assigned_healthcheck_url = f"https://{assigned_addr}/healthz"
        if _vm_is_healthy(assigned_healthcheck_url, f"Processing TEE ({assigned_addr})"):
            continue
        # TEE has finished and self-deallocated → the job is done.
        with job_file_lock:
            current = _load_job(job_id)
            if current.get("status") != "dispatched":
                continue
            current["status"]            = "complete"
            current["updated_at_unix"]   = now
            current["completed_at_unix"] = now
            current["completion_source"] = "dispatch_finalized"
            _save_job(current)
        finalized.append(job_id)
        buffer_debug(
            f"Finalized job {job_id} as complete — Processing TEE finished and "
            f"self-deallocated (results delivered to the leaderboard)"
        )
        _update_dispatch_state(
            last_dispatch_attempt_unix=now,
            last_dispatch_job_id=job_id,
            last_dispatch_status="finalized_complete",
            last_dispatch_error="",
        )
    return finalized


def dispatch_next_queued_job():
    """
    Called by job_scheduler every SCHEDULER_INTERVAL_SECONDS.

    1. Recover any jobs orphaned by a dead Processing TEE.
    2. Skip if another job is already (still legitimately) dispatched.
    3. Provision a Processing TEE for the job: GPU first (up to
       MAX_GPU_PROVISION_ATTEMPTS stop→start cycles), then CPU fallback.
    4. Build the secure payload and dispatch via RA-TLS to the chosen target.
    """
    _ensure_dirs()

    _finalize_dispatched_jobs()

    with job_file_lock:
        if any(_json_load(p).get("status") == "dispatched"
               for p in _all_job_metadata_paths()):
            return
        job = _next_queued_job()

    if not job:
        return

    buffer_debug(f"Dispatch cycle: job {job['job_id']} (dataset {job['dataset_id']})")
    _update_dispatch_state(
        last_dispatch_attempt_unix=int(time.time()),
        last_dispatch_job_id=job["job_id"],
        last_dispatch_status="checking_vm_health",
        last_dispatch_error="",
    )

    # GPU-first provisioning with a capped stop→start retry, then CPU fallback.
    # Returns the chosen target's RA-TLS addr + expected image digest, or
    # (None, None) if neither could be provisioned this tick (job stays queued
    # and the next scheduler tick retries — the per-job attempt count persists).
    addr, image_digest = _provision_processing_tee(job)
    if not addr:
        buffer_debug(
            f"Job {job['job_id']}: no Processing TEE available this cycle — "
            f"leaving queued for retry"
        )
        return

    with job_file_lock:
        current = _next_queued_job()
        if not current or current["job_id"] != job["job_id"]:
            return
        payload_path, _ = _write_secure_dispatch_payload(current)

    try:
        _run_ratls_dispatch(job, payload_path, addr=addr, image_digest=image_digest)
    except Exception as exc:
        buffer_debug(f"RA-TLS dispatch failed for {job['job_id']}: {exc}")
        _update_dispatch_state(
            last_dispatch_attempt_unix=int(time.time()),
            last_dispatch_job_id=job["job_id"],
            last_dispatch_status="dispatch_failed",
            last_dispatch_error=str(exc),
        )
        return

    with job_file_lock:
        _mark_job_dispatched(job["job_id"], payload_path, addr=addr)

    _update_dispatch_state(
        last_dispatch_attempt_unix=int(time.time()),
        last_dispatch_job_id=job["job_id"],
        last_dispatch_status="dispatched",
        last_dispatch_error="",
    )
    buffer_debug(f"Job {job['job_id']} dispatched successfully via RA-TLS")


# ── Flask routes ──────────────────────────────────────────────────────────────

@app.route("/buffer/jobs", methods=["POST"])
def enqueue_job():
    """
    Create a job from metadata. Model files arrive separately via binary upload.
    Required: dataset_id. Optional: model_sha256, weights_sha256, submitted_by.
    """
    content = request.json or {}
    try:
        job = _create_job_record(content)
        return jsonify({
            "status":    job["status"],   # "pending_upload"
            "job_id":    job["job_id"],
            "dataset_id": job["dataset_id"],
        }), 202
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/buffer/jobs/<job_id>/model", methods=["PUT"])
def upload_model(job_id):
    """Receive binary model.onnx bytes and write to job artifacts."""
    data = request.get_data()
    if not data:
        return jsonify({"status": "error", "message": "empty body"}), 400
    try:
        job = _receive_artifact(job_id, MODEL_FILE_NAME, data)
        return jsonify({"status": job["status"], "job_id": job_id,
                        "bytes": len(data)}), 200
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/buffer/jobs/<job_id>/weights", methods=["PUT"])
def upload_weights(job_id):
    """Receive binary weights bytes and write to job artifacts."""
    data = request.get_data()
    if not data:
        return jsonify({"status": "error", "message": "empty body"}), 400
    try:
        job = _receive_artifact(job_id, WEIGHTS_FILE_NAME, data)
        return jsonify({"status": job["status"], "job_id": job_id,
                        "bytes": len(data)}), 200
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/buffer/jobs/<job_id>/preprocessing", methods=["PUT"])
def upload_preprocessing(job_id):
    """Receive plaintext preprocessing.py bytes and write to job artifacts."""
    data = request.get_data()
    if not data:
        return jsonify({"status": "error", "message": "empty body"}), 400
    try:
        job = _receive_artifact(job_id, PREPROCESSING_FILE_NAME, data)
        return jsonify({"status": job["status"], "job_id": job_id,
                        "bytes": len(data)}), 200
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/buffer/jobs", methods=["GET"])
def list_jobs():
    _ensure_dirs()
    jobs = [_json_load(p) for p in sorted(BUFFER_JOBS_DIR.glob("*/job.json"))]
    queue = _read_queue()
    queued_ids = queue.get("queued_job_ids", [])
    return jsonify({
        "status":         "success",
        "queued_count":   len(queued_ids),
        "queued_job_ids": queued_ids,
        "jobs":           jobs,
    }), 200


@app.route("/buffer/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    path = _job_metadata_path(job_id)
    if not path.exists():
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404
    return jsonify({"status": "success", "job": _json_load(path)}), 200


@app.route("/buffer/jobs/<job_id>/artifacts/<artifact_name>", methods=["GET"])
def get_job_artifact(job_id, artifact_name):
    try:
        path = _artifact_path(job_id, artifact_name)
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Artifact not found"}), 404
    return send_file(path, as_attachment=True, download_name=artifact_name)


@app.route("/buffer/jobs/<job_id>/results", methods=["GET"])
def get_job_results(job_id):
    """Return inference results for a completed job.

    Results are written to local disk by the scheduler poll once the Processing
    TEE reports them; a miss means they haven't arrived yet.
    """
    job_path = _job_metadata_path(job_id)
    if not job_path.exists():
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404

    results_path = _job_results_path(job_id)
    if results_path.exists():
        return jsonify(_json_load(results_path)), 200

    job = _json_load(job_path)
    return jsonify({"status": job.get("status", "unknown"), "message": "results not yet available"}), 404


@app.route("/buffer/dispatch/state", methods=["GET"])
def get_dispatch_state():
    return jsonify({"status": "success", "dispatch_state": _dispatch_state()}), 200


@app.route("/healthz", methods=["GET"])
def healthz():
    return jsonify({"status": "ok"}), 200


# ── Startup ───────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    _ensure_dirs()
    print("=" * 60)
    print("Buffer TEE Manager — starting")
    print(f"  Flask (internal):   http://0.0.0.0:{BUFFER_TEE_PORT}")
    print(f"  RA-TLS server:      https://0.0.0.0:8443  (buffer-tee)")
    print(f"  Processing TEE:     {PROCESSING_RATLS_ADDR}")
    print("=" * 60)

    job_scheduler.set_dispatch_callback(dispatch_next_queued_job)
    job_scheduler.start_scheduler_thread()

    app.run(host=BUFFER_TEE_HOST, port=BUFFER_TEE_PORT, debug=False, use_reloader=False)
