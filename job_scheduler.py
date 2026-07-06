import json
import logging
import os
import shutil
import threading
import time
from pathlib import Path

from lib.buffer_lock import job_file_lock
from lib.config import config


SCHEDULER_INTERVAL_SECONDS    = int(os.getenv("SCHEDULER_INTERVAL_SECONDS",    "15"))
DISPATCH_TIMEOUT_SECONDS      = int(os.getenv("DISPATCH_TIMEOUT_SECONDS",      "600"))
JOB_RETENTION_SECONDS         = int(os.getenv("JOB_RETENTION_SECONDS",         "86400"))
QUEUE_STALL_THRESHOLD_SECONDS = int(os.getenv("QUEUE_STALL_THRESHOLD_SECONDS", "300"))


_BUFFER_WORKFLOW_DIR = Path(config.base_dir) / "cvm_workflow" / "buffer"
_BUFFER_JOBS_DIR     = _BUFFER_WORKFLOW_DIR / "jobs"
_BUFFER_QUEUE_FILE   = _BUFFER_WORKFLOW_DIR / "queue.json"
_DISPATCH_CALLBACK   = None


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


def set_dispatch_callback(callback) -> None:
    global _DISPATCH_CALLBACK
    _DISPATCH_CALLBACK = callback

# NOTE: dispatched-job recovery lives in the buffer manager's
# _finalize_dispatched_jobs() (fire-and-forget: a dispatched job whose
# Processing TEE has self-deallocated is marked complete, not re-queued).
# The old timeout-based re-queue here caused the same job to run repeatedly
# because results are delivered to the leaderboard, never back to the buffer.

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
                _cleanup_old_jobs()
                _check_queue_health()
        except Exception:
            logging.exception("[scheduler] Unhandled exception in scheduler loop")

        if _DISPATCH_CALLBACK is not None:
            try:
                _DISPATCH_CALLBACK()
            except Exception:
                logging.exception("[scheduler] Dispatch callback failed")
        time.sleep(SCHEDULER_INTERVAL_SECONDS)


def start_scheduler_thread() -> threading.Thread:
    t = threading.Thread(target=_scheduler_loop, name="job-scheduler", daemon=True)
    t.start()
    logging.info("[scheduler] Scheduler thread started (tid=%s)", t.ident)
    return t
