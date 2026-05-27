import base64
import hashlib
import json
import os
import platform
import shutil
import sys
import time
import uuid
from pathlib import Path

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS

import P3DX_SDK
import tee_tls
from lib.config import config


app = Flask(__name__)

CORS(
    app,
    resources={
        r"/*": {
            "origins": config.cors.origins,
            "methods": config.cors.methods,
            "allow_headers": config.cors.allow_headers,
            "expose_headers": config.cors.expose_headers,
            "supports_credentials": config.cors.supports_credentials,
            "max_age": config.cors.max_age,
        }
    },
    supports_credentials=True,
)


BUFFER_WORKFLOW_DIR = Path(config.base_dir) / "cvm_workflow" / "buffer"
BUFFER_JOBS_DIR = BUFFER_WORKFLOW_DIR / "jobs"
BUFFER_QUEUE_FILE = BUFFER_WORKFLOW_DIR / "queue.json"
BUFFER_ATTESTATION_DIR = BUFFER_WORKFLOW_DIR / "attestation"
BUFFER_OUTGOING_DIR = BUFFER_WORKFLOW_DIR / "outgoing"
BUFFER_RUNTIME_DIR = BUFFER_WORKFLOW_DIR / "runtime"
BUFFER_SHARED_ARTIFACTS_DIR = BUFFER_WORKFLOW_DIR / "shared_artifacts"
BUFFER_TEE_HOST = os.getenv("BUFFER_TEE_HOST", "127.0.0.1")
BUFFER_TEE_PORT = int(os.getenv("BUFFER_TEE_PORT", "4100"))
PROCESSING_TEE_HOST = os.getenv("PROCESSING_TEE_HOST", "127.0.0.1")
PROCESSING_TEE_PORT = int(os.getenv("PROCESSING_TEE_PORT", str(config.service.port)))
URL_SCHEME = "https" if tee_tls.tls_enabled() else "http"

# Production processing TEE should receive the confirmation payload here:
# POST https://<processing-tee-host>:4000/enclave/cvm/confirmation
PROCESSING_CONFIRMATION_ENDPOINT_PLACEHOLDER = (
    f"{URL_SCHEME}://{PROCESSING_TEE_HOST}:{PROCESSING_TEE_PORT}/enclave/cvm/confirmation"
)


def buffer_debug(message):
    print(f"[Buffer-TEE workflow] {message}", flush=True)


def _requests_kwargs(client_role):
    kwargs = tee_tls.requests_kwargs(client_role)
    if kwargs:
        buffer_debug(
            f"Using TLS client role '{client_role}' with CA {kwargs['verify']} and cert {kwargs['cert'][0]}"
        )
    else:
        buffer_debug(f"TLS disabled; '{client_role}' requests will use plain HTTP")
    return kwargs


def _ensure_dirs():
    for directory in (
        BUFFER_WORKFLOW_DIR,
        BUFFER_JOBS_DIR,
        BUFFER_ATTESTATION_DIR,
        BUFFER_OUTGOING_DIR,
        BUFFER_RUNTIME_DIR,
        BUFFER_SHARED_ARTIFACTS_DIR,
    ):
        directory.mkdir(parents=True, exist_ok=True)


def _ensure_vendor_path():
    vendor_path = Path(config.base_dir) / ".vendor"
    if vendor_path.exists() and str(vendor_path) not in sys.path:
        sys.path.insert(0, str(vendor_path))


def _json_dump(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)


def _json_load(path):
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _read_queue():
    if BUFFER_QUEUE_FILE.exists():
        return _json_load(BUFFER_QUEUE_FILE)
    return {"queued_job_ids": []}


def _write_queue(queue_payload):
    _json_dump(BUFFER_QUEUE_FILE, queue_payload)


def _job_dir(job_id):
    return BUFFER_JOBS_DIR / job_id


def _job_metadata_path(job_id):
    return _job_dir(job_id) / "job.json"


def _job_results_path(job_id):
    return _job_dir(job_id) / "results.json"


def _load_job(job_id):
    return _json_load(_job_metadata_path(job_id))


def _save_job(job):
    _json_dump(_job_metadata_path(job["job_id"]), job)


def _canonical_dataset_id(dataset_id):
    dataset_id = int(dataset_id)
    if dataset_id not in (1, 2, 3):
        raise ValueError("dataset_id must be one of 1, 2, or 3")
    return dataset_id


def _resnet34_hyperparameters():
    return {
        "architecture": "resnet34",
        "weights": "random-placeholder",
        "input_shape": [1, 3, 64, 64],
        "num_classes": 3,
        "opset_version": 17,
        "normalization": "placeholder datasets are already scaled to 0..1",
        "batch_size": 8,
    }


def _create_placeholder_resnet34_onnx(target_dir, force=False):
    model_path = Path(target_dir) / "model.onnx"
    weights_path = Path(target_dir) / "model_weights.onnx.data"
    if model_path.exists() and weights_path.exists() and not force:
        return model_path, weights_path

    _ensure_vendor_path()
    import torch
    from torchvision.models import resnet34
    import onnx

    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    temp_model_path = target_dir / "model.inline.onnx"
    if weights_path.exists():
        weights_path.unlink()

    model = resnet34(weights=None, num_classes=3)
    model.eval()
    dummy_input = torch.randn(1, 3, 64, 64)

    torch.onnx.export(
        model,
        dummy_input,
        str(temp_model_path),
        input_names=["input"],
        output_names=["logits"],
        dynamic_axes={"input": {0: "batch"}, "logits": {0: "batch"}},
        opset_version=17,
        dynamo=False,
    )

    onnx_model = onnx.load(str(temp_model_path))
    onnx.save_model(
        onnx_model,
        str(model_path),
        save_as_external_data=True,
        all_tensors_to_one_file=True,
        location=weights_path.name,
        size_threshold=0,
    )
    temp_model_path.unlink(missing_ok=True)
    return model_path, weights_path


def _copy_placeholder_artifacts_to_job(job_dir, force=False):
    source_model, source_weights = _create_placeholder_resnet34_onnx(BUFFER_SHARED_ARTIFACTS_DIR, force=force)
    artifacts_dir = Path(job_dir) / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    target_model = artifacts_dir / "model.onnx"
    target_weights = artifacts_dir / "model_weights.onnx.data"
    shutil.copy2(source_model, target_model)
    shutil.copy2(source_weights, target_weights)
    return target_model, target_weights


def _save_uploaded_artifacts(job_dir, content):
    artifacts_dir = Path(job_dir) / "artifacts"
    artifacts_dir.mkdir(parents=True, exist_ok=True)
    model_bytes = base64.b64decode(content["model_onnx_base64"])
    weights_bytes = base64.b64decode(content["model_weights_base64"])
    model_path = artifacts_dir / "model.onnx"
    weights_path = artifacts_dir / "model_weights.onnx.data"
    model_path.write_bytes(model_bytes)
    weights_path.write_bytes(weights_bytes)
    return model_path, weights_path


def _buffer_hardware_evidence():
    cpuinfo_path = Path("/proc/cpuinfo")
    cpuinfo = cpuinfo_path.read_text(errors="ignore") if cpuinfo_path.exists() else ""
    sev_guest_candidates = [
        Path("/dev/sev-guest"),
        Path("/sys/firmware/sev/guest"),
        Path("/sys/kernel/security/secrets/coco"),
    ]
    return {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "amd_cpu_detected": "AuthenticAMD" in cpuinfo or "AMD" in cpuinfo or "AMD" in platform.processor(),
        "sev_snp_interface_detected": any(candidate.exists() for candidate in sev_guest_candidates),
        "sev_snp_interface_candidates": [str(candidate) for candidate in sev_guest_candidates],
    }


def _buffer_software_evidence():
    return {
        "buffer_manager_code_sha256": _sha256_file(Path(__file__).resolve()),
        "repo_code_sha256": P3DX_SDK.hash_enclave_manager_code(config.base_dir),
        "config_yml_sha256": _sha256_file(Path(config.base_dir) / "config.yml"),
    }


def build_buffer_attestation_report():
    _ensure_dirs()
    report = {
        "format": "google-cvm-amd-sev-snp-buffer-placeholder-v1",
        "role": "buffer-tee",
        "nonce": P3DX_SDK.generate_nonce(),
        "created_at_unix": int(time.time()),
        "hardware": _buffer_hardware_evidence(),
        "software": _buffer_software_evidence(),
        "placeholder_note": (
            "Replace this placeholder report with a real SEV-SNP attestation retrieval path "
            "for the always-on buffer TEE."
        ),
    }
    report_path = BUFFER_ATTESTATION_DIR / "buffer_attestation_report.json"
    _json_dump(report_path, report)
    return report_path, report


def _verify_processing_attestation(report):
    reasons = []
    checks = {
        "format_present": bool(report.get("format")),
        "hardware_present": isinstance(report.get("hardware"), dict),
        "software_present": isinstance(report.get("software"), dict),
    }

    if report.get("format") != "google-cvm-amd-sev-snp-placeholder-v1":
        reasons.append("Unexpected attestation report format")

    software = report.get("software") or {}
    if not software.get("enclave_manager_code_sha256"):
        reasons.append("Missing processing TEE code hash")
    if not software.get("config_yml_sha256"):
        reasons.append("Missing processing TEE config hash")

    expected_code_hash = os.getenv("PROCESSING_EXPECTED_CODE_SHA256")
    if expected_code_hash and software.get("enclave_manager_code_sha256") != expected_code_hash:
        reasons.append("Processing TEE code hash does not match PROCESSING_EXPECTED_CODE_SHA256")

    max_age_seconds = int(os.getenv("PROCESSING_ATTESTATION_MAX_AGE_SECONDS", "120"))
    created_at = int(report.get("created_at_unix", 0))
    if not created_at:
        reasons.append("Missing processing TEE report timestamp")
    elif abs(int(time.time()) - created_at) > max_age_seconds:
        reasons.append("Processing TEE attestation report is older than the allowed max age")

    if os.getenv("REQUIRE_SEV_SNP_INTERFACE", "0") == "1":
        hardware = report.get("hardware") or {}
        if not hardware.get("sev_snp_interface_detected"):
            reasons.append("SEV-SNP interface was not detected on the processing TEE")

    return {
        "approved": not reasons,
        "checks": checks,
        "reasons": reasons,
    }


def _next_queued_job():
    queue_payload = _read_queue()
    for job_id in queue_payload.get("queued_job_ids", []):
        metadata_path = _job_metadata_path(job_id)
        if not metadata_path.exists():
            continue
        job = _load_job(job_id)
        if job.get("status") == "queued":
            return job
    return None


def _remove_job_from_queue(job_id):
    queue_payload = _read_queue()
    queue_payload["queued_job_ids"] = [
        queued_job_id for queued_job_id in queue_payload.get("queued_job_ids", [])
        if queued_job_id != job_id
    ]
    _write_queue(queue_payload)


def _queue_job(job):
    queue_payload = _read_queue()
    queue_payload.setdefault("queued_job_ids", []).append(job["job_id"])
    _write_queue(queue_payload)


def _build_confirmation_payload(job):
    artifact_base = f"{URL_SCHEME}://{BUFFER_TEE_HOST}:{BUFFER_TEE_PORT}/buffer/jobs/{job['job_id']}/artifacts"
    return {
        "job_id": job["job_id"],
        "model": "model.onnx",
        "weights": "model_weights.onnx.data",
        "dataset_id": job["dataset_id"],
        "hyperparameters": job["hyperparameters"],
        "buffer_results_callback_url": job["buffer_results_callback_url"],
        "model_download_url": f"{artifact_base}/model.onnx",
        "weights_download_url": f"{artifact_base}/model_weights.onnx.data",
        "placeholder_note": (
            "This confirmation.json is generated by the buffer TEE after approving the "
            "processing TEE attestation report."
        ),
    }


def _deliver_confirmation_to_processing(job, confirmation_payload, request_payload):
    import requests

    confirmation_path = BUFFER_OUTGOING_DIR / f"{job['job_id']}-confirmation.json"
    _json_dump(confirmation_path, confirmation_payload)

    delivery = {
        "confirmation_path": str(confirmation_path),
        "confirmation_delivery": "not_sent",
    }

    callback_url = request_payload.get("confirmation_callback_url")
    confirmation_file_path = request_payload.get("confirmation_file_path")

    if callback_url:
        buffer_debug(f"POSTing confirmation payload to processing TEE callback {callback_url}")
        response = requests.post(
            callback_url,
            json=confirmation_payload,
            timeout=30,
            **_requests_kwargs("buffer-client"),
        )
        response.raise_for_status()
        delivery["confirmation_delivery"] = "http_post"
        delivery["confirmation_callback_url"] = callback_url
    elif confirmation_file_path:
        target_path = Path(confirmation_file_path)
        _json_dump(target_path, confirmation_payload)
        delivery["confirmation_delivery"] = "shared_file_placeholder"
        delivery["confirmation_file_path"] = str(target_path)
    else:
        delivery["confirmation_delivery"] = "artifacts_only"

    return delivery


def _artifact_path(job_id, artifact_name):
    allowed_artifacts = {"model.onnx", "model_weights.onnx.data"}
    if artifact_name not in allowed_artifacts:
        raise FileNotFoundError(f"Unsupported artifact name: {artifact_name}")
    artifact_path = _job_dir(job_id) / "artifacts" / artifact_name
    if not artifact_path.exists():
        raise FileNotFoundError(f"Artifact not found: {artifact_name}")
    return artifact_path


def handle_processing_attestation_request(request_payload):
    _ensure_dirs()
    report = request_payload.get("attestation_report")
    if not report:
        raise ValueError("Missing attestation_report in processing TEE request payload")

    job = _next_queued_job()
    if not job:
        return {
            "approved": False,
            "message": "No queued jobs are available on the buffer TEE",
        }

    verification = _verify_processing_attestation(report)
    attestation_record_path = BUFFER_ATTESTATION_DIR / f"{job['job_id']}-processing_attestation.json"
    _json_dump(
        attestation_record_path,
        {
            "job_id": job["job_id"],
            "processing_tee_id": request_payload.get("processing_tee_id"),
            "received_at_unix": int(time.time()),
            "verification": verification,
            "attestation_report": report,
        },
    )

    if not verification["approved"]:
        job["status"] = "rejected"
        job["rejection_reasons"] = verification["reasons"]
        job["updated_at_unix"] = int(time.time())
        _save_job(job)
        _remove_job_from_queue(job["job_id"])
        return {
            "approved": False,
            "job_id": job["job_id"],
            "message": "Processing TEE attestation was rejected by the buffer TEE",
            "verification": verification,
        }

    confirmation_payload = _build_confirmation_payload(job)
    delivery = _deliver_confirmation_to_processing(job, confirmation_payload, request_payload)

    job["status"] = "dispatched"
    job["assigned_processing_tee_id"] = request_payload.get("processing_tee_id")
    job["updated_at_unix"] = int(time.time())
    job["confirmation_payload_path"] = delivery["confirmation_path"]
    job["delivery"] = delivery
    _save_job(job)
    _remove_job_from_queue(job["job_id"])

    return {
        "approved": True,
        "job_id": job["job_id"],
        "message": "Processing TEE attestation approved; confirmation payload delivered",
        "verification": verification,
        "delivery": delivery,
    }


def handle_processing_results(job_id, results_payload):
    _ensure_dirs()
    job = _load_job(job_id)
    results_path = _job_results_path(job_id)
    _json_dump(results_path, results_payload)
    job["status"] = "complete"
    job["updated_at_unix"] = int(time.time())
    job["results_path"] = str(results_path)
    _save_job(job)
    return {
        "status": "success",
        "job_id": job_id,
        "results_path": str(results_path),
    }


def _create_job_record(content):
    _ensure_dirs()
    dataset_id = _canonical_dataset_id(content.get("dataset_id", 1))
    job_id = content.get("job_id") or f"job-{uuid.uuid4().hex[:12]}"
    job_dir = _job_dir(job_id)
    if job_dir.exists():
        raise ValueError(f"Job directory already exists for {job_id}")

    use_placeholder_artifacts = content.get("use_placeholder_artifacts", True)
    if not use_placeholder_artifacts and not (
        content.get("model_onnx_base64") and content.get("model_weights_base64")
    ):
        raise ValueError(
            "When use_placeholder_artifacts is false, both model_onnx_base64 and "
            "model_weights_base64 must be provided"
        )

    if use_placeholder_artifacts:
        model_path, weights_path = _copy_placeholder_artifacts_to_job(job_dir, force=content.get("force", False))
    else:
        model_path, weights_path = _save_uploaded_artifacts(job_dir, content)

    job = {
        "job_id": job_id,
        "status": "queued",
        "dataset_id": dataset_id,
        "submitted_at_unix": int(time.time()),
        "updated_at_unix": int(time.time()),
        "hyperparameters": content.get("hyperparameters") or _resnet34_hyperparameters(),
        "model_file": model_path.name,
        "weights_file": weights_path.name,
        "artifact_dir": str(model_path.parent),
        "submitted_by": content.get("submitted_by", "placeholder-user"),
        "buffer_results_callback_url": content.get("buffer_results_callback_url", ""),
        "notes": content.get("notes", ""),
    }
    _save_job(job)
    _queue_job(job)
    return job


@app.route("/buffer/attestation/report", methods=["GET"])
def get_buffer_attestation_report():
    report_path, report = build_buffer_attestation_report()
    return jsonify({
        "status": "success",
        "report_path": str(report_path),
        "report": report,
    }), 200


@app.route("/buffer/jobs", methods=["POST"])
def enqueue_job():
    content = request.json if request.json else {}
    try:
        job = _create_job_record(content)
        return jsonify({
            "status": "queued",
            "job_id": job["job_id"],
            "dataset_id": job["dataset_id"],
            "artifact_dir": job["artifact_dir"],
        }), 202
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/buffer/jobs", methods=["GET"])
def list_jobs():
    _ensure_dirs()
    jobs = []
    for metadata_path in sorted(BUFFER_JOBS_DIR.glob("*/job.json")):
        jobs.append(_json_load(metadata_path))
    queue_payload = _read_queue()
    return jsonify({
        "status": "success",
        "queued_job_ids": queue_payload.get("queued_job_ids", []),
        "jobs": jobs,
    }), 200


@app.route("/buffer/jobs/<job_id>", methods=["GET"])
def get_job(job_id):
    metadata_path = _job_metadata_path(job_id)
    if not metadata_path.exists():
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404
    job = _json_load(metadata_path)
    return jsonify({"status": "success", "job": job}), 200


@app.route("/buffer/jobs/<job_id>/artifacts/<artifact_name>", methods=["GET"])
def get_job_artifact(job_id, artifact_name):
    try:
        artifact_path = _artifact_path(job_id, artifact_name)
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Artifact not found"}), 404
    return send_file(artifact_path, as_attachment=True, download_name=artifact_name)


@app.route("/buffer/processing/attestation", methods=["POST"])
def process_processing_attestation():
    content = request.json if request.json else {}
    try:
        verdict = handle_processing_attestation_request(content)
        status_code = 200 if verdict.get("approved") else 403
        return jsonify(verdict), status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


@app.route("/buffer/jobs/<job_id>/results", methods=["POST"])
def record_processing_results(job_id):
    content = request.json if request.json else {}
    try:
        result = handle_processing_results(job_id, content)
        return jsonify(result), 200
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Unknown job_id"}), 404
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400


if __name__ == "__main__":
    _ensure_dirs()
    print("=" * 60)
    print("Starting Buffer TEE Manager")
    print(f"Port: {BUFFER_TEE_PORT}")
    print("Endpoints available:")
    print("  - GET  /buffer/attestation/report")
    print("  - POST /buffer/jobs")
    print("  - GET  /buffer/jobs")
    print("  - GET  /buffer/jobs/<job_id>")
    print("  - GET  /buffer/jobs/<job_id>/artifacts/<artifact_name>")
    print("  - POST /buffer/processing/attestation")
    print("  - POST /buffer/jobs/<job_id>/results")
    print("=" * 60)
    run_kwargs = {
        "host": BUFFER_TEE_HOST if BUFFER_TEE_HOST != "127.0.0.1" else "0.0.0.0",
        "port": BUFFER_TEE_PORT,
        "debug": os.getenv("TEE_DEBUG", "0") == "1",
        "use_reloader": False,
    }
    if tee_tls.tls_enabled():
        tee_tls.ensure_tls_materials()
        buffer_debug("Starting buffer TEE HTTPS server with local placeholder certificates")
        run_kwargs["ssl_context"] = tee_tls.build_server_ssl_context("buffer-server")
    else:
        buffer_debug("Starting buffer TEE HTTP server with TLS disabled")
    app.run(**run_kwargs)
