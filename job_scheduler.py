import json
import logging
import os
import shutil
import threading
import time
from pathlib import Path

import requests
import tee_tls
from lib.buffer_lock import job_file_lock
from lib.config import config


SCHEDULER_INTERVAL_SECONDS    = int(os.getenv("SCHEDULER_INTERVAL_SECONDS",    "30"))
DISPATCH_TIMEOUT_SECONDS      = int(os.getenv("DISPATCH_TIMEOUT_SECONDS",      "600"))
JOB_RETENTION_SECONDS         = int(os.getenv("JOB_RETENTION_SECONDS",         "86400"))
QUEUE_STALL_THRESHOLD_SECONDS = int(os.getenv("QUEUE_STALL_THRESHOLD_SECONDS", "300"))


_BUFFER_WORKFLOW_DIR = Path(config.base_dir) / "cvm_workflow" / "buffer"
_BUFFER_JOBS_DIR     = _BUFFER_WORKFLOW_DIR / "jobs"
_BUFFER_QUEUE_FILE   = _BUFFER_WORKFLOW_DIR / "queue.json"


def _json_load(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _json_dump(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)



def _job_dir(job_id: str) -> Path:
    return _BUFFER_JOBS_DIR / job_id


def _job_metadata_path(job_id: str) -> Path:
    return _job_dir(job_id) / "job.json"


def _job_results_path(job_id: str) -> Path:
    return _job_dir(job_id) / "results.json"


def _read_queue() -> dict:
    if _BUFFER_QUEUE_FILE.exists():
        return _json_load(_BUFFER_QUEUE_FILE)
    return {"queued_job_ids": []}


def _write_queue(payload: dict) -> None:
    _json_dump(_BUFFER_QUEUE_FILE, payload)


def _requeue_job_id(job_id: str) -> None:
    q = _read_queue()
    ids = q.setdefault("queued_job_ids", [])
    if job_id not in ids:
        ids.append(job_id)
    _write_queue(q)


def _all_job_metadata_paths():
    return sorted(_BUFFER_JOBS_DIR.glob("*/job.json"))

# Re-queue dispatched jobs that have timed out

def _handle_dispatch_timeouts() -> None:
    now = time.time()
    for metadata_path in _all_job_metadata_paths():
        try:
            job = _json_load(metadata_path)
        except Exception:
            continue

        if job.get("status") != "dispatched":
            continue

        # Fall back to updated_at_unix for jobs dispatched before this field existed
        dispatched_at = job.get("dispatched_at_unix") or job.get("updated_at_unix", 0)
        age = now - dispatched_at
        if age < DISPATCH_TIMEOUT_SECONDS:
            continue

        job_id = job["job_id"]
        logging.warning(
            "[scheduler] Job %s stuck in dispatched for %.0fs (threshold %ds) — re-queuing",
            job_id, age, DISPATCH_TIMEOUT_SECONDS,
        )
        job["status"] = "queued"
        job["updated_at_unix"] = int(now)
        job["requeue_count"] = job.get("requeue_count", 0) + 1
        job.pop("assigned_processing_tee_id", None)
        job.pop("processing_tee_results_url", None)
        job.pop("dispatched_at_unix", None)
        _json_dump(metadata_path, job)
        _requeue_job_id(job_id)

# Poll processing TEE for results on dispatched jobs

def _poll_dispatched_for_results() -> None:
    for metadata_path in _all_job_metadata_paths():
        try:
            job = _json_load(metadata_path)
        except Exception:
            continue

        if job.get("status") != "dispatched":
            continue

        results_url = job.get("processing_tee_results_url", "").strip()
        if not results_url:
            continue

        job_id = job["job_id"]
        try:
            response = requests.get(
                results_url,
                timeout=15,
                **tee_tls.requests_kwargs("buffer-client"),
            )
        except Exception as exc:
            logging.warning("[scheduler] Poll GET %s for job %s failed: %s", results_url, job_id, exc)
            continue

        if response.status_code == 404:
            logging.debug("[scheduler] Job %s still processing (404 from %s)", job_id, results_url)
            continue

        if response.status_code != 200:
            logging.warning(
                "[scheduler] Unexpected %d polling %s for job %s — will retry next tick",
                response.status_code, results_url, job_id,
            )
            continue

        try:
            results_payload = response.json()
        except Exception as exc:
            logging.error("[scheduler] Non-JSON 200 body from %s for job %s: %s", results_url, job_id, exc)
            continue

        results_path = _job_results_path(job_id)
        _json_dump(results_path, results_payload)
        job["status"] = "complete"
        job["updated_at_unix"] = int(time.time())
        job["results_path"] = str(results_path)
        job["results_source"] = "scheduler_poll"
        _json_dump(metadata_path, job)
        logging.info("[scheduler] Job %s marked complete via poll from %s", job_id, results_url)

# Delete job directories past the retention window

def _cleanup_old_jobs() -> None:
    now = time.time()
    terminal_statuses = {"complete", "rejected"}
    for metadata_path in _all_job_metadata_paths():
        try:
            job = _json_load(metadata_path)
        except Exception:
            continue

        if job.get("status") not in terminal_statuses:
            continue

        age = now - job.get("updated_at_unix", 0)
        if age < JOB_RETENTION_SECONDS:
            continue

        job_id = job["job_id"]
        job_directory = _job_dir(job_id)
        logging.info(
            "[scheduler] Deleting job %s (status=%s, age=%.0fs)",
            job_id, job["status"], age,
        )
        try:
            shutil.rmtree(job_directory)
        except Exception as exc:
            logging.error("[scheduler] Could not delete %s: %s", job_directory, exc)

# Warn when jobs sit queued without being claimed

def _check_queue_health() -> None:
    now = time.time()
    q = _read_queue()
    for job_id in q.get("queued_job_ids", []):
        metadata_path = _job_metadata_path(job_id)
        if not metadata_path.exists():
            continue
        try:
            job = _json_load(metadata_path)
        except Exception:
            continue
        if job.get("status") != "queued":
            continue
        age = now - job.get("submitted_at_unix", now)
        if age >= QUEUE_STALL_THRESHOLD_SECONDS:
            logging.warning(
                "[scheduler] Job %s has been queued for %.0fs (threshold %ds) — no processing TEE has claimed it",
                job_id, age, QUEUE_STALL_THRESHOLD_SECONDS,
            )

# Main scheduler loop

def _scheduler_loop() -> None:
    logging.info(
        "[scheduler] Background scheduler started (interval=%ds, dispatch_timeout=%ds, "
        "retention=%ds, stall_threshold=%ds)",
        SCHEDULER_INTERVAL_SECONDS, DISPATCH_TIMEOUT_SECONDS,
        JOB_RETENTION_SECONDS, QUEUE_STALL_THRESHOLD_SECONDS,
    )
    while True:
        try:
            with job_file_lock:
                _handle_dispatch_timeouts()
                _poll_dispatched_for_results()
                _cleanup_old_jobs()
                _check_queue_health()
        except Exception:
            logging.exception("[scheduler] Unhandled exception in scheduler loop")
        time.sleep(SCHEDULER_INTERVAL_SECONDS)


def start_scheduler_thread() -> threading.Thread:
    t = threading.Thread(target=_scheduler_loop, name="job-scheduler", daemon=True)
    t.start()
    logging.info("[scheduler] Scheduler thread started (tid=%s)", t.ident)
    return t
