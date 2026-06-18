"""
Buffer TEE — Enclave Manager
============================

Flow:
  1. User-Facing UI establishes RA-TLS to the Tanuh buffer-server (Go, port 8443).
  2. User uploads model.onnx + weights, encrypted via HPKE inside the browser.
  3. buffer-server decrypts inside the SEV-SNP TEE, then POSTs to /buffer/jobs here.
  4. job_scheduler.py dispatches the job to the Processing TEE via RA-TLS
     (buffer-tee Go client → gpu-cs Go server on port 443).
  5. Processing TEE decrypts dataset, runs ONNX inference, uploads results to GCS,
     then self-deallocates.
  6. Buffer TEE polls GCS for results on GET /v1/results/{job_id} and returns them
     to the browser.
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
PROCESSING_VM_BOOT_TIMEOUT_SECONDS  = int(os.getenv("PROCESSING_VM_BOOT_TIMEOUT_SECONDS", "180"))
PROCESSING_VM_BOOT_POLL_INTERVAL    = int(os.getenv("PROCESSING_VM_BOOT_POLL_INTERVAL_SECONDS", "5"))
PROCESSING_EXPECTED_IMAGE_DIGEST    = os.getenv("GPU_CS_IMAGE_DIGEST", "")
# A job marked "dispatched" whose Processing TEE died before uploading results
# would otherwise block the scheduler forever. If results are still absent from
# GCS, the VM is unhealthy, and at least this many seconds have passed since
# dispatch, treat the job as orphaned and requeue it for re-dispatch.
DISPATCH_ORPHAN_GRACE_SECONDS       = int(os.getenv("DISPATCH_ORPHAN_GRACE_SECONDS", "60"))

BUFFER_RATLS_CLIENT_BIN    = os.getenv("BUFFER_RATLS_CLIENT_BIN", "")
BUFFER_RATLS_CLIENT_WORKDIR = Path(os.getenv("BUFFER_RATLS_CLIENT_WORKDIR",
                                              str(Path(config.base_dir) / "b2p-ratls")))

GCS_RESULTS_BUCKET = os.getenv("GCS_RESULTS_BUCKET", "p3dx-tanuh-results")

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

    # For dataset_id=2 (Oral Cancer) require model + weights + preprocessing.py.
    # For all other datasets require only model + weights.
    model_path        = artifacts_dir / MODEL_FILE_NAME
    weights_path      = artifacts_dir / WEIGHTS_FILE_NAME
    preprocessing_path = artifacts_dir / PREPROCESSING_FILE_NAME
    all_required = model_path.exists() and weights_path.exists()
    if all_required and int(job.get("dataset_id", 0)) == 2:
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

def _processing_vm_is_healthy():
    try:
        resp = requests.get(PROCESSING_RATLS_HEALTHCHECK_URL, timeout=5, verify=False)
        ok = resp.status_code == 200
        _update_dispatch_state(
            last_vm_healthcheck_unix=int(time.time()),
            last_vm_healthcheck_ok=ok,
        )
        buffer_debug(f"Processing TEE healthcheck → {resp.status_code}")
        return ok
    except Exception as exc:
        _update_dispatch_state(
            last_vm_healthcheck_unix=int(time.time()),
            last_vm_healthcheck_ok=False,
            last_dispatch_error=f"healthcheck failed: {exc}",
        )
        buffer_debug(f"Processing TEE healthcheck failed: {exc}")
        return False


def _vm_start_command():
    if PROCESSING_VM_START_COMMAND.strip():
        return PROCESSING_VM_START_COMMAND.strip(), "command"
    candidate = Path(PROCESSING_VM_START_SCRIPT)
    if candidate.exists():
        return str(candidate), "script"
    return "", ""


def _request_processing_vm_start():
    now = int(time.time())
    state = _dispatch_state()
    if now - int(state.get("last_vm_start_request_unix", 0)) < PROCESSING_VM_START_COOLDOWN_SECONDS:
        buffer_debug("VM start skipped — within cooldown window")
        return False

    start_target, start_mode = _vm_start_command()
    if not start_target:
        buffer_debug("No Processing TEE start command configured")
        _update_dispatch_state(
            last_vm_start_request_unix=now,
            last_vm_start_mode="missing",
            last_dispatch_error="No processing VM start command configured",
        )
        return False

    buffer_debug(f"Starting Processing TEE via {start_mode}: {start_target}")
    try:
        completed = subprocess.run(
            [start_target] if start_mode == "script" else start_target,
            cwd=config.base_dir,
            capture_output=True, text=True,
            timeout=60, check=False,
            shell=(start_mode == "command"),
        )
    except Exception as exc:
        buffer_debug(f"VM start failed: {exc}")
        _update_dispatch_state(
            last_vm_start_request_unix=now,
            last_vm_start_mode=start_mode,
            last_dispatch_error=f"VM start error: {exc}",
        )
        return False

    if completed.stdout: print(completed.stdout, end="", flush=True)
    if completed.stderr: print(completed.stderr, end="", flush=True)

    if completed.returncode != 0:
        buffer_debug(f"VM start command exited with {completed.returncode}")
        _update_dispatch_state(
            last_vm_start_request_unix=now,
            last_vm_start_mode=start_mode,
            last_dispatch_error=f"VM start exited {completed.returncode}",
        )
        return False

    _update_dispatch_state(
        last_vm_start_request_unix=now,
        last_vm_start_mode=start_mode,
        last_dispatch_error="",
    )
    return True


def _wait_for_processing_vm():
    deadline = time.time() + PROCESSING_VM_BOOT_TIMEOUT_SECONDS
    while time.time() < deadline:
        if _processing_vm_is_healthy():
            buffer_debug("Processing TEE is healthy and ready")
            return True
        time.sleep(PROCESSING_VM_BOOT_POLL_INTERVAL)
    buffer_debug(f"Processing TEE did not become healthy within {PROCESSING_VM_BOOT_TIMEOUT_SECONDS}s")
    return False


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
    if BUFFER_RATLS_CLIENT_BIN.strip():
        return [BUFFER_RATLS_CLIENT_BIN.strip()], None
    linux  = BUFFER_RATLS_CLIENT_WORKDIR / "buffer-tee"
    if linux.exists():
        return [str(linux)], None
    return ["go", "run", "./cmd/buffer-tee"], str(BUFFER_RATLS_CLIENT_WORKDIR)


def _run_ratls_dispatch(job, payload_path):
    if not PROCESSING_EXPECTED_IMAGE_DIGEST:
        raise ValueError("GPU_CS_IMAGE_DIGEST must be set before dispatching")

    command, override_workdir = _ratls_client_command()
    workdir = override_workdir or config.base_dir
    env = os.environ.copy()
    env["GPU_CS_ADDR"]          = PROCESSING_RATLS_ADDR
    env["RATLS_AUDIENCE"]       = env.get("RATLS_AUDIENCE", "ratls-buffer-tee")
    env["GPU_CS_IMAGE_DIGEST"]  = PROCESSING_EXPECTED_IMAGE_DIGEST
    env["JOB_PAYLOAD_PATH"]     = str(payload_path)
    env.setdefault("GOTELEMETRY", "off")

    buffer_debug(f"RA-TLS dispatch: {' '.join(command)} → job {job['job_id']}")
    completed = subprocess.run(
        command, cwd=workdir, env=env,
        capture_output=True, text=True,
        timeout=180, check=False,
    )
    if completed.stdout: print(completed.stdout, end="", flush=True)
    if completed.stderr: print(completed.stderr, end="", flush=True)
    if completed.returncode != 0:
        raise RuntimeError(f"RA-TLS dispatch failed (exit {completed.returncode})")


def _mark_job_dispatched(job_id, payload_path):
    job = _load_job(job_id)
    job["status"]                  = "dispatched"
    job["assigned_processing_tee"] = PROCESSING_RATLS_ADDR
    job["dispatched_at_unix"]      = int(time.time())
    job["updated_at_unix"]         = int(time.time())
    job["delivery"] = {"mode": "ratls_json_payload", "payload_path": str(payload_path)}
    _save_job(job)
    _remove_job_from_queue(job_id)
    return job


# ── Main scheduler dispatch callback ─────────────────────────────────────────

def _requeue_orphaned_dispatched_jobs():
    """
    Recover jobs stuck in "dispatched" because the Processing TEE died before
    uploading results (e.g. mid-eval shutdown). Such a job is removed from the
    queue and would otherwise block the scheduler forever.

    A dispatched job is considered orphaned when ALL of:
      - its results are not yet present in GCS, and
      - the dispatch happened at least DISPATCH_ORPHAN_GRACE_SECONDS ago, and
      - the Processing TEE is not currently healthy (a live eval keeps it up).

    Orphaned jobs are reset to "queued" and re-added to the queue. Returns the
    list of requeued job_ids.
    """
    requeued = []
    now = int(time.time())
    with job_file_lock:
        dispatched = [
            _json_load(p) for p in _all_job_metadata_paths()
            if _json_load(p).get("status") == "dispatched"
        ]
    if not dispatched:
        return requeued

    for job in dispatched:
        job_id = job.get("job_id")
        if now - int(job.get("dispatched_at_unix", 0)) < DISPATCH_ORPHAN_GRACE_SECONDS:
            continue
        # If results have landed in GCS, the job is actually complete — cache and skip.
        try:
            payload = _fetch_results_from_gcs(job_id)
        except Exception as exc:
            buffer_debug(f"Orphan check: GCS fetch for {job_id} failed: {exc}")
            payload = None
        if payload is not None:
            _cache_results_locally(job_id, payload)
            continue
        # No results yet. If the Processing TEE is still healthy, an eval may be
        # in flight — leave it alone. Otherwise the VM is gone: requeue.
        if _processing_vm_is_healthy():
            continue
        with job_file_lock:
            current = _load_job(job_id)
            if current.get("status") != "dispatched":
                continue
            current["status"]         = "queued"
            current["updated_at_unix"] = now
            current["requeued_at_unix"] = now
            current["requeue_count"]   = int(current.get("requeue_count", 0)) + 1
            _save_job(current)
            _queue_job(current)
        requeued.append(job_id)
        buffer_debug(
            f"Requeued orphaned job {job_id} — Processing TEE died before "
            f"results upload (requeue #{current['requeue_count']})"
        )
        _update_dispatch_state(
            last_dispatch_attempt_unix=now,
            last_dispatch_job_id=job_id,
            last_dispatch_status="requeued_orphan",
            last_dispatch_error="processing TEE died before results upload",
        )
    return requeued


def dispatch_next_queued_job():
    """
    Called by job_scheduler every SCHEDULER_INTERVAL_SECONDS.

    1. Recover any jobs orphaned by a dead Processing TEE.
    2. Skip if another job is already (still legitimately) dispatched.
    3. Healthcheck the Processing TEE; start it if not running.
    4. Build the secure payload and dispatch via RA-TLS.
    """
    _ensure_dirs()

    _requeue_orphaned_dispatched_jobs()

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

    if not _processing_vm_is_healthy():
        buffer_debug("Processing TEE not healthy — requesting start")
        if not _request_processing_vm_start():
            return
        if not _wait_for_processing_vm():
            return

    with job_file_lock:
        current = _next_queued_job()
        if not current or current["job_id"] != job["job_id"]:
            return
        payload_path, _ = _write_secure_dispatch_payload(current)

    try:
        _run_ratls_dispatch(job, payload_path)
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
        _mark_job_dispatched(job["job_id"], payload_path)

    _update_dispatch_state(
        last_dispatch_attempt_unix=int(time.time()),
        last_dispatch_job_id=job["job_id"],
        last_dispatch_status="dispatched",
        last_dispatch_error="",
    )
    buffer_debug(f"Job {job['job_id']} dispatched successfully via RA-TLS")


# ── Results — GCS fetch ────────────────────────────────────────────────────────

def _fetch_results_from_gcs(job_id):
    """
    Download results.json for job_id from GCS.
    Returns the parsed dict on success, None if the object doesn't exist yet,
    or raises on unexpected errors.
    """
    from google.cloud import storage as gcs
    blob_name = f"results/{job_id}/results.json"
    client    = gcs.Client()
    bucket    = client.bucket(GCS_RESULTS_BUCKET)
    blob      = bucket.blob(blob_name)
    if not blob.exists():
        return None
    return json.loads(blob.download_as_text())


def _cache_results_locally(job_id, results_payload):
    """Persist GCS-fetched results (or an error report) to disk and update the
    job status. The Processing TEE writes an error payload (status="error") to
    the same GCS location on failure, so a fetched payload may be either."""
    _ensure_dirs()
    results_path = _job_results_path(job_id)
    _json_dump(results_path, results_payload)

    is_error  = isinstance(results_payload, dict) and results_payload.get("status") == "error"
    job_status = "error" if is_error else "complete"

    with job_file_lock:
        job = _load_job(job_id)
        job["status"]          = job_status
        job["updated_at_unix"] = int(time.time())
        job["results_path"]    = str(results_path)
        job["gcs_results_uri"] = f"gs://{GCS_RESULTS_BUCKET}/results/{job_id}/results.json"
        if is_error:
            job["last_error"] = results_payload.get("error", "")
        _save_job(job)
        _update_dispatch_state(
            last_dispatch_attempt_unix=int(time.time()),
            last_dispatch_job_id=job_id,
            last_dispatch_status=("job_failed" if is_error else "results_received"),
            last_dispatch_error=(results_payload.get("error", "") if is_error else ""),
        )
    buffer_debug(
        f"{'Error report' if is_error else 'Results'} cached locally for job {job_id}"
    )


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
    return jsonify({
        "status":         "success",
        "queued_job_ids": queue.get("queued_job_ids", []),
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

    Checks local disk cache first; on miss, polls GCS directly.
    When GCS has the object the results are cached locally and returned.
    """
    job_path = _job_metadata_path(job_id)
    if not job_path.exists():
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404

    # Fast path: already cached from a previous fetch
    results_path = _job_results_path(job_id)
    if results_path.exists():
        return jsonify(_json_load(results_path)), 200

    # Slow path: ask GCS
    try:
        payload = _fetch_results_from_gcs(job_id)
    except Exception as exc:
        buffer_debug(f"GCS fetch for {job_id} failed: {exc}")
        job = _json_load(job_path)
        return jsonify({"status": job.get("status", "unknown"), "message": "results not yet available"}), 404

    if payload is None:
        job = _json_load(job_path)
        return jsonify({"status": job.get("status", "unknown"), "message": "results not yet available"}), 404

    _cache_results_locally(job_id, payload)
    return jsonify(payload), 200


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
    print(f"  RA-TLS server:      https://0.0.0.0:8443  (buffer-server)")
    print(f"  Processing TEE:     {PROCESSING_RATLS_ADDR}")
    print(f"  GCS results bucket: gs://{GCS_RESULTS_BUCKET}")
    print("=" * 60)

    job_scheduler.set_dispatch_callback(dispatch_next_queued_job)
    job_scheduler.start_scheduler_thread()

    app.run(host=BUFFER_TEE_HOST, port=BUFFER_TEE_PORT, debug=False, use_reloader=False)
