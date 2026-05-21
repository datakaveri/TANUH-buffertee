import base64
import hashlib
import os
import json
import platform
import shutil
import sys
import subprocess
import time
import logging
import traceback
from pathlib import Path

_LOCAL_VENDOR = Path(__file__).resolve().parent / ".vendor"
if _LOCAL_VENDOR.exists() and str(_LOCAL_VENDOR) not in sys.path:
    sys.path.insert(0, str(_LOCAL_VENDOR))

from flask import Flask, jsonify, Response, request
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
import P3DX_SDK
from lib.config import config
from cryptography.fernet import Fernet


app = Flask(__name__)

# Enable CORS for all routes with configuration from config.yml
CORS(app, 
     resources={
         r"/*": {
             "origins": config.cors.origins,
             "methods": config.cors.methods,
             "allow_headers": config.cors.allow_headers,
             "expose_headers": config.cors.expose_headers,
             "supports_credentials": config.cors.supports_credentials,
             "max_age": config.cors.max_age
         }
     },
     supports_credentials=True)


# Default state when application is not running
state = {
    "step": 0,
    "maxSteps": 11,
    "title": "Inactive",
    "description": "Inactive",
}


# Flag to track if application is running
is_app_running = False

# Google Confidential VM placeholder workflow paths.
CVM_WORKFLOW_DIR = Path(config.base_dir) / "cvm_workflow"
CVM_ARTIFACTS_DIR = CVM_WORKFLOW_DIR / "artifacts"
CVM_INCOMING_DIR = CVM_WORKFLOW_DIR / "incoming"
CVM_RUNTIME_DIR = CVM_WORKFLOW_DIR / "runtime"
CVM_EVALUATION_SCRIPT = CVM_WORKFLOW_DIR / "evaluation_script.py"

# Placeholder verifier endpoint. In production this should be the remote verifier
# endpoint that receives the SEV-SNP attestation report from this Google CVM.
ATTESTATION_VERIFIER_ENDPOINT_PLACEHOLDER = "https://verifier.placeholder.example/attestation/report"

# Real confirmation receiver should POST the confirmation payload here:
# POST http://<cvm-enclave-manager-host>:4000/enclave/cvm/confirmation
CONFIRMATION_FILE_PLACEHOLDER = CVM_INCOMING_DIR / "confirmation.json"


def cvm_debug(message):
    """Emit a flush-safe debug line for the Google CVM workflow."""
    print(f"[Google-CVM workflow] {message}", flush=True)


def _ensure_vendor_path():
    """Prefer local runtime wheels installed under .vendor for ONNX testing."""
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


def _hardware_evidence():
    """Collect best-effort hardware evidence for a Google AMD SEV-SNP CVM."""
    cvm_debug("Collecting hardware evidence from OS-visible CVM interfaces")
    cpuinfo_path = Path("/proc/cpuinfo")
    cpuinfo = cpuinfo_path.read_text(errors="ignore") if cpuinfo_path.exists() else ""
    sev_guest_candidates = [
        Path("/dev/sev-guest"),
        Path("/sys/firmware/sev/guest"),
        Path("/sys/kernel/security/secrets/coco"),
    ]
    evidence = {
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "amd_cpu_detected": "AuthenticAMD" in cpuinfo or "AMD" in cpuinfo or "AMD" in platform.processor(),
        "sev_snp_interface_detected": any(candidate.exists() for candidate in sev_guest_candidates),
        "sev_snp_interface_candidates": [str(candidate) for candidate in sev_guest_candidates],
        "google_cloud_hint": Path("/sys/class/dmi/id/product_name").read_text(errors="ignore").strip()
        if Path("/sys/class/dmi/id/product_name").exists()
        else None,
    }
    cvm_debug(f"Hardware evidence collected: {evidence}")
    return evidence


def _software_evidence():
    """Collect measurements/config hashes that are safe to share with a verifier."""
    cvm_debug("Collecting software evidence: manager code hash, config hash, PCR files if present")
    evidence = {
        "enclave_manager_code_sha256": P3DX_SDK.hash_enclave_manager_code(config.base_dir),
        "config_yml_sha256": _sha256_file(Path(config.base_dir) / "config.yml"),
    }

    pcr_path = Path(config.get_path("pcr_values"))
    image_hash_path = Path(config.get_path("image_hash"))
    if pcr_path.exists():
        evidence["pcr_values"] = _json_load(pcr_path)
    if image_hash_path.exists():
        evidence["docker_image_sha256"] = image_hash_path.read_text(encoding="utf-8").strip()

    cvm_debug("Software evidence collected")
    return evidence


def build_attestation_report():
    """
    Build a placeholder attestation report.

    Production Google SEV-SNP integration should replace the placeholder section
    with an SNP_GET_REPORT ioctl through /dev/sev-guest, or the Google-supported
    attestation report retrieval path for the chosen Confidential VM product.
    """
    cvm_debug("Building attestation report with nonce, hardware evidence, and software measurements")
    nonce = P3DX_SDK.generate_nonce()
    report = {
        "format": "google-cvm-amd-sev-snp-placeholder-v1",
        "nonce": nonce,
        "created_at_unix": int(time.time()),
        "hardware": _hardware_evidence(),
        "software": _software_evidence(),
        "placeholder_note": (
            "Replace this object with the raw AMD SEV-SNP report and certificate chain "
            "before wiring to the production verifier."
        ),
    }
    report_path = CVM_RUNTIME_DIR / "attestation_report.json"
    _json_dump(report_path, report)
    cvm_debug(f"Attestation report written to {report_path}")
    return report


def send_attestation_report_to_verifier(report):
    """
    Send attestation to verifier, with a local placeholder approval path.

    Set CVM_ATTESTATION_ENDPOINT to use a real verifier. When it is unset, this
    waits 5 seconds and returns approved=True to keep local development moving.
    """
    endpoint = os.getenv("CVM_ATTESTATION_ENDPOINT", ATTESTATION_VERIFIER_ENDPOINT_PLACEHOLDER)
    cvm_debug(f"Prepared attestation report for verifier endpoint: {endpoint}")

    if endpoint == ATTESTATION_VERIFIER_ENDPOINT_PLACEHOLDER:
        cvm_debug("Placeholder verifier active; waiting 5 seconds before approving attestation")
        time.sleep(5)
        return {
            "approved": True,
            "verifier": "placeholder",
            "message": "Placeholder verifier approved after 5 second wait",
        }

    import requests

    cvm_debug("Sending attestation report to configured verifier")
    response = requests.post(endpoint, json=report, timeout=30)
    response.raise_for_status()
    verdict = response.json()
    cvm_debug(f"Verifier response received: {verdict}")
    return verdict


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


def _make_placeholder_dataset(dataset_id, sample_count=18):
    """Fabricate tiny numeric image-like datasets for ONNX Runtime evaluation."""
    import numpy as np

    rng = np.random.default_rng(7000 + dataset_id)
    features = rng.normal(0.18, 0.03, size=(sample_count, 3, 64, 64)).astype("float32")

    if dataset_id == 1:
        labels = np.asarray([idx % 2 for idx in range(sample_count)], dtype="int64")
        for idx, label in enumerate(labels):
            features[idx, :, 24:40, 24:40] += 0.55 if label == 1 else 0.05
        description = "Binary bright-center numerical image dataset"
        num_classes = 2
    elif dataset_id == 2:
        labels = np.asarray([idx % 3 for idx in range(sample_count)], dtype="int64")
        for idx, label in enumerate(labels):
            if label == 0:
                features[idx, 0, 10:18, :] += 0.45
            elif label == 1:
                features[idx, 1, :, 28:36] += 0.45
            else:
                features[idx, 2, 44:54, :] += 0.45
        description = "Three-class stripe-position numerical image dataset"
        num_classes = 3
    elif dataset_id == 3:
        labels = np.asarray([(idx // 2) % 2 for idx in range(sample_count)], dtype="int64")
        for idx, label in enumerate(labels):
            diagonal = np.eye(64, dtype="float32")
            if label == 1:
                features[idx, :, :, :] += diagonal * 0.5
            else:
                features[idx, :, :, :] += np.fliplr(diagonal) * 0.5
        description = "Binary diagonal-pattern numerical image dataset"
        num_classes = 2
    else:
        raise ValueError(f"Unsupported placeholder dataset id: {dataset_id}")

    features = np.clip(features, 0.0, 1.0)
    return {
        "dataset_id": dataset_id,
        "description": description,
        "num_classes": num_classes,
        "features": features.tolist(),
        "labels": labels.tolist(),
    }


def create_placeholder_encrypted_datasets(force=False):
    encrypted_path = CVM_ARTIFACTS_DIR / "encrypted_dataset.json"
    keys_path = CVM_ARTIFACTS_DIR / "dataset_keys.json"
    if encrypted_path.exists() and keys_path.exists() and not force:
        cvm_debug(f"Encrypted placeholder datasets already exist at {encrypted_path}")
        return encrypted_path, keys_path

    cvm_debug("Creating encrypted_dataset.json and dataset_keys.json placeholder files")
    encrypted_payload = {
        "format": "fernet-placeholder-v1",
        "note": "Production flow should fetch only the selected dataset key from Secret Manager.",
        "datasets": {},
    }
    key_payload = {
        "format": "fernet-placeholder-keys-v1",
        "note": "PLACEHOLDER: replace this file with Google Secret Manager lookups.",
        "keys": {},
    }

    for dataset_id in (1, 2, 3):
        key = Fernet.generate_key()
        cipher = Fernet(key)
        dataset = _make_placeholder_dataset(dataset_id)
        plaintext = json.dumps(dataset).encode("utf-8")
        encrypted_payload["datasets"][str(dataset_id)] = {
            "ciphertext": cipher.encrypt(plaintext).decode("utf-8"),
            "algorithm": "Fernet-AES128-CBC-HMACSHA256",
        }
        key_payload["keys"][str(dataset_id)] = key.decode("utf-8")
        cvm_debug(f"Encrypted placeholder dataset {dataset_id}")

    _json_dump(encrypted_path, encrypted_payload)
    _json_dump(keys_path, key_payload)
    return encrypted_path, keys_path


def create_placeholder_resnet34_onnx(force=False):
    model_path = CVM_ARTIFACTS_DIR / "model.onnx"
    weights_path = CVM_ARTIFACTS_DIR / "model_weights.onnx.data"
    if model_path.exists() and weights_path.exists() and not force:
        cvm_debug(f"Placeholder ONNX model already exists at {model_path}")
        return model_path, weights_path

    cvm_debug("Exporting placeholder ResNet34 with random weights to ONNX")
    _ensure_vendor_path()
    import torch
    from torchvision.models import resnet34
    import onnx

    CVM_ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    temp_model_path = CVM_ARTIFACTS_DIR / "model.inline.onnx"
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
    cvm_debug(f"ONNX model written to {model_path}")
    cvm_debug(f"External ONNX weights written to {weights_path}")
    return model_path, weights_path


def create_placeholder_confirmation(force=False, dataset_id=1):
    confirmation_path = CONFIRMATION_FILE_PLACEHOLDER
    if confirmation_path.exists() and not force:
        cvm_debug(f"Placeholder confirmation already exists at {confirmation_path}")
        return confirmation_path

    cvm_debug("Creating placeholder confirmation.json from verifier payload")
    model_path, weights_path = create_placeholder_resnet34_onnx(force=force)
    create_placeholder_encrypted_datasets(force=force)
    confirmation = {
        "model": model_path.name,
        "weights": weights_path.name,
        "dataset_id": dataset_id,
        "hyperparameters": _resnet34_hyperparameters(),
        "placeholder_note": (
            "This file stands in for the payload that the remote attestation verifier "
            "will send after approving the CVM."
        ),
    }
    _json_dump(confirmation_path, confirmation)
    cvm_debug(f"Placeholder confirmation written to {confirmation_path}")
    return confirmation_path


def wait_for_confirmation_payload(timeout_seconds=30):
    cvm_debug(f"Waiting up to {timeout_seconds}s for confirmation payload at {CONFIRMATION_FILE_PLACEHOLDER}")
    start = time.time()
    while time.time() - start < timeout_seconds:
        if CONFIRMATION_FILE_PLACEHOLDER.exists():
            confirmation = _json_load(CONFIRMATION_FILE_PLACEHOLDER)
            cvm_debug(f"Confirmation payload received: {confirmation}")
            return confirmation
        time.sleep(1)

    cvm_debug("Confirmation payload timeout reached")
    print("Shutting down without actually deallocating this placeholder VM.", flush=True)
    raise TimeoutError(f"confirmation.json not received within {timeout_seconds} seconds")


def decrypt_selected_dataset(dataset_id):
    cvm_debug(f"Selecting encrypted dataset_id={dataset_id}")
    encrypted_path = CVM_ARTIFACTS_DIR / "encrypted_dataset.json"
    keys_path = CVM_ARTIFACTS_DIR / "dataset_keys.json"
    encrypted_payload = _json_load(encrypted_path)
    key_payload = _json_load(keys_path)

    dataset_key = str(dataset_id)
    if dataset_key not in encrypted_payload["datasets"]:
        raise ValueError(f"dataset_id {dataset_id} not found in encrypted_dataset.json")
    if dataset_key not in key_payload["keys"]:
        raise ValueError(f"dataset_id {dataset_id} key not found in dataset_keys.json")

    cvm_debug("PLACEHOLDER Secret Manager lookup: reading symmetric key from dataset_keys.json")
    cipher = Fernet(key_payload["keys"][dataset_key].encode("utf-8"))
    plaintext = cipher.decrypt(encrypted_payload["datasets"][dataset_key]["ciphertext"].encode("utf-8"))
    dataset = json.loads(plaintext.decode("utf-8"))

    selected_dataset_path = CVM_RUNTIME_DIR / f"dataset_{dataset_id}_decrypted.json"
    _json_dump(selected_dataset_path, dataset)
    cvm_debug(f"Selected dataset decrypted to {selected_dataset_path}")
    return selected_dataset_path


def run_evaluation_script(confirmation, dataset_path):
    model_path = CVM_ARTIFACTS_DIR / confirmation["model"]
    weights_path = CVM_ARTIFACTS_DIR / confirmation["weights"]
    results_path = CVM_RUNTIME_DIR / "results.json"

    if not model_path.exists():
        raise FileNotFoundError(f"Model file not found: {model_path}")
    if not weights_path.exists():
        raise FileNotFoundError(f"External ONNX weights file not found: {weights_path}")

    cvm_debug(f"Compiling ONNX model by creating ONNX Runtime session in {CVM_EVALUATION_SCRIPT}")
    cvm_debug(f"Model path: {model_path}")
    cvm_debug(f"Weights path: {weights_path}")
    cvm_debug(f"Dataset path: {dataset_path}")

    env = os.environ.copy()
    vendor_path = str(Path(config.base_dir) / ".vendor")
    env["PYTHONPATH"] = vendor_path + os.pathsep + env.get("PYTHONPATH", "")

    result = subprocess.run(
        [
            sys.executable,
            str(CVM_EVALUATION_SCRIPT),
            "--model",
            str(model_path),
            "--dataset",
            str(dataset_path),
            "--results",
            str(results_path),
        ],
        cwd=config.base_dir,
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    if result.stdout:
        print(result.stdout, end="", flush=True)
    if result.stderr:
        print(result.stderr, end="", flush=True)
    if result.returncode != 0:
        raise RuntimeError(f"Evaluation script failed with exit code {result.returncode}")

    results = _json_load(results_path)
    cvm_debug(f"results.json populated: {results}")
    return results_path, results


def run_google_cvm_workflow(generate_placeholders=True, confirmation_timeout=30, force_placeholders=False):
    """Run the requested Google AMD SEV-SNP CVM placeholder workflow end to end."""
    global state, is_app_running

    is_app_running = True
    state = {
        "step": 1,
        "maxSteps": 4,
        "title": "Google CVM Attestation",
        "description": "Building and sending attestation report",
    }

    for directory in (CVM_ARTIFACTS_DIR, CVM_INCOMING_DIR, CVM_RUNTIME_DIR):
        directory.mkdir(parents=True, exist_ok=True)

    if force_placeholders and CVM_RUNTIME_DIR.exists():
        cvm_debug(f"Clearing old runtime files from {CVM_RUNTIME_DIR}")
        for item in CVM_RUNTIME_DIR.iterdir():
            if item.is_file():
                item.unlink()
            elif item.is_dir():
                shutil.rmtree(item)

    try:
        cvm_debug("Step 1/4: Verify hardware/software evidence and send attestation report")
        report = build_attestation_report()
        verdict = send_attestation_report_to_verifier(report)
        if not verdict.get("approved"):
            raise PermissionError(f"Attestation verifier did not approve this CVM: {verdict}")
        cvm_debug("Attestation approved; continuing workflow")

        state = {
            "step": 2,
            "maxSteps": 4,
            "title": "Waiting for Confirmation Payload",
            "description": "Polling placeholder confirmation.json",
        }
        cvm_debug("Step 2/4: Receive confirmation payload")
        if generate_placeholders:
            create_placeholder_confirmation(force=force_placeholders)
        confirmation = wait_for_confirmation_payload(timeout_seconds=confirmation_timeout)

        state = {
            "step": 3,
            "maxSteps": 4,
            "title": "Decrypting Selected Dataset",
            "description": "Using placeholder dataset_keys.json instead of Secret Manager",
        }
        cvm_debug("Step 3/4: Pull encrypted dataset and decrypt selected dataset")
        dataset_path = decrypt_selected_dataset(int(confirmation["dataset_id"]))

        state = {
            "step": 4,
            "maxSteps": 4,
            "title": "Evaluating ONNX Model",
            "description": "Running ONNX Runtime evaluation script",
        }
        cvm_debug("Step 4/4: Compile ONNX model, load external weights, evaluate, and write results")
        results_path, results = run_evaluation_script(confirmation, dataset_path)

        state = {
            "step": 4,
            "maxSteps": 4,
            "title": "Secure Evaluation Complete",
            "description": f"Results written to {results_path}",
        }
        cvm_debug("Google CVM placeholder workflow complete")
        return {
            "status": "success",
            "attestation": verdict,
            "confirmation_path": str(CONFIRMATION_FILE_PLACEHOLDER),
            "results_path": str(results_path),
            "results": results,
        }
    finally:
        is_app_running = False


# Removed after_request handler - flask-cors already handles CORS headers
# Adding duplicate headers causes "multiple values" error



# DEPLOY: Deploys the TEE enclave
@app.route("/enclave/deploy", methods=["POST"])
def deploy_enclave():
    jwt_file_path = config.get_path('jwt_response')
    subprocess.run(["sudo", "rm", "-rf", jwt_file_path], check=False, capture_output=True)
    
    print("STARTING deploy")
    global is_app_running, stored_bundle
    
    if is_app_running:
        print("Previous deployment detected. Restarting service to reset state...")
        try:
            P3DX_SDK.restart_enclave_manager()

            time.sleep(3)
            is_app_running = False
            stored_bundle = None
        except Exception as e:
            print(f"Warning: Failed to restart service: {str(e)}")
            response = {
                "title": "Error",
                "description": f"Previous deployment detected but failed to restart service: {str(e)}"
            }
            return jsonify(response), 500
    
    stored_bundle = None

    global state
    state = {
        "step": 1,
        "maxSteps": 11,
        "title": "Spawning Trusted Execution Environment (TEE)",
        "description": "Step 1"
    }
    
    content = request.json if request.json else {}
    compose_url = content.get("compose_url")

    if not compose_url:
        return jsonify({
            "title": "Error",
            "description": "compose_url is required in request payload"
        }), 400

    try:
        cmd = f"python3 -u deploy_enclave.py {repr(compose_url)} 2>&1 | systemd-cat -t tee-deployment"
        subprocess.Popen(
            ["sudo", "sh", "-c", cmd],
            cwd=config.base_dir
        )
        
        is_app_running = True
        response = {
            "title": "Success",
            "description": "Application execution has started."
        }
        return jsonify(response), 200
        
    except Exception as e:
        response = {
            "title": "Error",
            "description": f"Failed to start application: {str(e)}"
        }
        return jsonify(response), 500



stored_bundle = None

@app.route("/enclave/jwt", methods=["POST"])
def receive_jwt():
    try:
        content = request.json
        if not content or 'jwt' not in content:
            return jsonify({"error": "Missing jwt in request"}), 400
        return jsonify({"status": "success", "message": "JWT stored"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/enclave/jwt", methods=["GET"])
def get_jwt():
    print("Fetching JWT token...")
    jwt_file_path = config.get_path('jwt_response')
    
    if not os.path.exists(jwt_file_path):
        response = {
            "title": "Error: JWT not found",
            "description": "JWT token not available yet. Deployment in progress..."
        }
        return jsonify(response), 404
    
    try:
        result = subprocess.run(
            ['sudo', 'chmod', '644', jwt_file_path],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        with open(jwt_file_path, "r") as f:
            jwt_token = f.read().strip()
        
        if not jwt_token:
            response = {
                "title": "Error: Empty JWT",
                "description": "JWT token file is empty."
            }
            return jsonify(response), 404
        
        print(f"JWT token retrieved successfully (length: {len(jwt_token)})")
        
        response = {
            "title": "Success",
            "jwt": jwt_token
        }
        return jsonify(response), 200
        
    except subprocess.CalledProcessError as e:
        response = {
            "title": "Error: Permission denied",
            "description": f"Failed to set file permissions: {e.stderr.decode() if e.stderr else str(e)}"
        }
        return jsonify(response), 500
        
    except Exception as e:
        response = {
            "title": "Error reading JWT",
            "description": f"Failed to read JWT token: {str(e)}"
        }
        return jsonify(response), 500



# GET FRESH JWT: Returns a fresh JWT token
@app.route("/enclave/jwt/fresh", methods=["GET"])
def get_fresh_jwt():
    """Generate a fresh JWT token by deleting old JWT and executing guest attestation.
    
    Returns:
        JSON response with newly generated JWT token or error details.
    """
    print("Generating fresh JWT token...")
    
    jwt_file_path = config.get_path('jwt_response')
    private_key_path = config.get_path('private_key')
    public_key_path = config.get_path('public_key')
    keys_dir = config.paths.keys_dir
    
    original_cwd = os.getcwd()
    
    try:
        os.chdir(config.base_dir)
        os.makedirs(keys_dir, exist_ok=True)
        
        subprocess.run(
            ["sudo", "chown", "-R", f"{config.user}:{config.user}", keys_dir],
            check=False,
            capture_output=True
        )
        subprocess.run(
            ["sudo", "chmod", "-R", "755", keys_dir],
            check=False,
            capture_output=True
        )
        
        if os.path.exists(jwt_file_path):
            subprocess.run(
                ["sudo", "rm", "-rf", jwt_file_path],
                check=False,
                capture_output=True
            )
            print("Old JWT file deleted")
        
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            print("Keys not found. Generating new key pair...")
            P3DX_SDK.generate_and_save_key_pair()
            print("Key pair generated successfully")

        try:
            # Measure enclave manager code 
            P3DX_SDK.measure_enclave_manager_code_vtpm()
            print("Enclave manager code hash measured successfully")
            
            # Measure Docker image
            # link = P3DX_SDK.extract_docker_image_from_compose()
            # P3DX_SDK.measureDockervTPM(link)
            # print("Application image hash measured successfully")
        except Exception as e:
            print(f"Warning: Failed to measure code/image: {str(e)}")
        
        # new nonce generated every time a fresh endpoint is hit
        print("Generating fresh deployment nonce...")
        nonce = P3DX_SDK.generate_nonce()                  
        P3DX_SDK.save_nonce(nonce)
        P3DX_SDK.extend_nonce_to_pcr8(nonce)
        print(f"Generated deployment nonce: {nonce}")

        print("Executing guest attestation to generate new JWT...")
        P3DX_SDK.execute_guest_attestation()
        
        subprocess.run(
            ["sudo", "chown", f"{config.user}:{config.user}", jwt_file_path],
            check=False,
            capture_output=True
        )
        subprocess.run(
            ['sudo', 'chmod', '644', jwt_file_path],
            check=False,
            capture_output=True
        )
        
        with open(jwt_file_path, "r") as f:
            jwt_token = f.read().strip()
        
        if not jwt_token:
            response = {
                "title": "Error: Empty JWT",
                "description": "JWT token file is empty after generation."
            }
            return jsonify(response), 500
        
        print(f"Fresh JWT token generated successfully (length: {len(jwt_token)})")
        
        response = {
            "title": "Success",
            "jwt": jwt_token
        }
        return jsonify(response), 200
        
    except RuntimeError as e:
        response = {
            "title": "Error: JWT generation failed",
            "description": str(e)
        }
        return jsonify(response), 500
        
    except Exception as e:
        print(f"Unexpected error generating JWT: {str(e)}")
        response = {
            "title": "Error: JWT generation failed",
            "description": f"Failed to generate JWT token: {str(e)}"
        }
        return jsonify(response), 500
        
    finally:
        os.chdir(original_cwd)

# GET BUNDLE: Returns the encrypted bundle for polling
@app.route("/enclave/bundle", methods=["GET"])
def get_bundle():
    global stored_bundle
    
    bundle_file = config.get_path('encrypted_bundle')
    if os.path.exists(bundle_file):
        try:
            with open(bundle_file, 'r') as f:
                stored_bundle = json.load(f)
        except Exception:
            pass
    
    if stored_bundle:
        return jsonify({"bundle": stored_bundle}), 200
    else:
        return jsonify({"error": "Bundle not found"}), 404


@app.route("/enclave/bundle/upload", methods=["POST"])
def upload_encrypted_bundle():
    print("Receiving encrypted bundle...")
    
    try:
        content = request.json
        
        if not content:
            response = {
                "title": "Error",
                "description": "No data received"
            }
            return jsonify(response), 400
        
        bundle_dir = config.paths.bundle_dir
        os.makedirs(bundle_dir, exist_ok=True)
        
        global stored_bundle
        stored_bundle = content
        
        output_file = config.get_path('encrypted_bundle')
        
        with open(output_file, 'w') as f:
            json.dump(content, f, indent=2)
        
        os.chmod(output_file, 0o644)
        
        print(f"Encrypted bundle saved to {output_file}")
        print(f"File size: {os.path.getsize(output_file)} bytes")
        
        response = {
            "title": "Success",
            "description": f"Encrypted bundle saved successfully",
            "file_path": output_file,
            "file_size": os.path.getsize(output_file)
        }
        return jsonify(response), 200
        
    except Exception as e:
        print(f"Error saving encrypted bundle: {str(e)}")
        response = {
            "title": "Error",
            "description": f"Failed to save encrypted bundle: {str(e)}"
        }
        return jsonify(response), 500


@app.route("/enclave/cvm/run", methods=["POST"])
def run_cvm_workflow_endpoint():
    """Run the Google AMD SEV-SNP CVM placeholder attestation/evaluation workflow."""
    content = request.json if request.json else {}
    try:
        result = run_google_cvm_workflow(
            generate_placeholders=content.get("generate_placeholders", True),
            confirmation_timeout=int(content.get("confirmation_timeout", 30)),
            force_placeholders=content.get("force_placeholders", False),
        )
        return jsonify(result), 200
    except TimeoutError as e:
        return jsonify({
            "status": "timeout",
            "message": str(e),
            "placeholder_action": "Shutting down without actually deallocating this placeholder VM.",
        }), 408
    except Exception as e:
        traceback.print_exc()
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/enclave/cvm/confirmation", methods=["POST"])
def receive_cvm_confirmation():
    """
    Receive confirmation payload after remote verifier approval.

    Production verifier should POST confirmation.json here:
    POST http://<cvm-enclave-manager-host>:4000/enclave/cvm/confirmation
    """
    content = request.json
    if not content:
        return jsonify({"status": "error", "message": "Missing JSON confirmation payload"}), 400

    required_fields = {"model", "weights", "dataset_id", "hyperparameters"}
    missing = required_fields - set(content.keys())
    if missing:
        return jsonify({"status": "error", "message": f"Missing fields: {sorted(missing)}"}), 400

    _json_dump(CONFIRMATION_FILE_PLACEHOLDER, content)
    cvm_debug(f"Confirmation payload received over HTTP and saved to {CONFIRMATION_FILE_PLACEHOLDER}")
    return jsonify({
        "status": "success",
        "confirmation_path": str(CONFIRMATION_FILE_PLACEHOLDER),
    }), 200


@app.route("/enclave/cvm/results", methods=["GET"])
def get_cvm_results():
    results_path = CVM_RUNTIME_DIR / "results.json"
    if not results_path.exists():
        return jsonify({"status": "processing", "message": "results.json is not available yet"}), 404
    return jsonify(_json_load(results_path)), 200



# INFERENCE: Returns the inference as a JSON object
@app.route("/enclave/inference", methods=["GET"])
def get_inference():
    print("Fetching inference...")
    logger = logging.getLogger()
    logging.debug('STARTING INFERENCE')
    
    global state
    
    if state["step"] != 5:
        response = {
            "title": "Error: App execution incomplete",
            "description": "No inference output found. Current step: " + str(state["step"])
        }
        return jsonify(response), 403


    output_file = config.get_path('status')
    
    if os.path.exists(output_file):
        try:
            result = subprocess.run(
                ['sudo', 'chmod', '644', output_file], 
                check=True, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE
            )
            
            if result.returncode == 0:
                print(f"Successfully set permissions on file: {output_file}")
            else:
                print(f"Failed to set permissions. Error: {result.stderr.decode()}")
                
        except subprocess.CalledProcessError as e:
            print(f"Error executing sudo chmod: {e.stderr.decode()}")
    else:
        print(f"File not found: {output_file}")


    if os.path.isfile(output_file):
        with open(output_file, "r") as f:
            content = f.read()
        
        print(f"Inference file read successfully (size: {len(content)} bytes)")
        
        response = app.response_class(
            response=content,
            mimetype="application/json"
        )
        return response
    else:
        response = {
            "title": "Error: No Inference Output",
            "description": "Inference file does not exist at " + output_file
        }
        return jsonify(response), 403



# SETSTATE: Sets the state of the enclave
@app.route("/enclave/setstate", methods=["POST"])
def setState():
    global state
    global is_app_running
    print("In /enclave/setstate...")
    
    content = request.json
    if not content or "state" not in content:
        return jsonify({"status": "error", "message": "Missing 'state' in request body"}), 400
    
    state = content["state"]
    
    print(f"State updated - Step {state['step']}/{state['maxSteps']}: {state['title']}")
    
    if state["step"] == 11:
        is_app_running = False
        print("Deployment completed, resetting is_app_running flag")
    
    response = app.response_class(
        response='{"status": "ok"}', 
        status=200, 
        mimetype="application/json"
    )
    return response



# STATE: Returns the current state of the enclave
@app.route("/enclave/state", methods=["GET"])
def get_state():
    global state
    response = {
        "step": state.get("step", 0),
        "maxSteps": state.get("maxSteps", 11),
        "title": state.get("title", "Inactive"),
        "description": state.get("description", "Inactive"),
    }
    print(f"State requested - Step {response['step']}/{response['maxSteps']}")
    return jsonify(response)


# STATUS: Returns application status
@app.route("/enclave/status", methods=["GET"])
def get_app_status_endpoint():
    """Poll endpoint for application status.
    
    Returns status.json content
    """
    print("Fetching application status...")
    
    try:
        status_response = P3DX_SDK.get_app_status()
        return jsonify(status_response), 200
            
    except Exception as e:
        print(f"Error fetching status: {str(e)}")
        return jsonify({
            "status": "error",
            "error": {
                "code": "ENDPOINT_ERROR",
                "message": "Failed to fetch status",
                "details": str(e)
            }
        }), 500


# Error handler for critical errors that require service restart
@app.errorhandler(Exception)
def handle_critical_error(e):
    """Handle critical errors by restarting the service.
    
    Excludes:
    - HTTP exceptions (404, 400, etc.) - normal routing errors
    - PermissionError - file permission issues, should be handled in routes
    - OSError/IOError - file system errors, usually recoverable
    
    Only actual application crashes and unhandled exceptions trigger service restart.
    """
    # Skip HTTP exceptions - these are normal routing errors, not critical failures
    if isinstance(e, HTTPException):
        # Return proper JSON response with CORS headers for HTTP errors
        response = jsonify({
            "title": "Error",
            "description": f"{e.code} {e.name}: {e.description}"
        })
        response.status_code = e.code
        return response
    
    # Skip file permission and I/O errors - these are recoverable and should be handled in routes
    if isinstance(e, (PermissionError, OSError, IOError)):
        print(f"File system error (non-critical): {str(e)}")
        traceback.print_exc()
        response = jsonify({
            "title": "Error",
            "description": f"File system error: {str(e)}. Please check file permissions and try again."
        })
        response.status_code = 500
        return response
    
    # Only handle actual critical errors (unhandled exceptions, crashes, etc.)
    print(f"Critical error in manager: {str(e)}")
    traceback.print_exc()
    
    # Restart service on critical errors only
    # Use a flag to prevent infinite restart loops
    restart_attempted = False
    try:
        P3DX_SDK.restart_enclave_manager()
        restart_attempted = True
        print("Service restart initiated successfully")
    except Exception as restart_error:
        error_msg = str(restart_error) if restart_error else "Unknown error"
        print(f"Failed to restart service: {error_msg}")
    
    response = jsonify({
        "title": "Error",
        "description": f"Critical error occurred. {'Service restarting' if restart_attempted else 'Service restart failed'}: {str(e)}"
    })
    response.status_code = 500
    return response


if __name__ == "__main__":
    if "--run-cvm-pipeline" in sys.argv:
        force = "--force-placeholders" in sys.argv
        no_generate = "--no-generate-placeholders" in sys.argv
        timeout = 30
        for arg in sys.argv:
            if arg.startswith("--confirmation-timeout="):
                timeout = int(arg.split("=", 1)[1])
        outcome = run_google_cvm_workflow(
            generate_placeholders=not no_generate,
            confirmation_timeout=timeout,
            force_placeholders=force,
        )
        print(json.dumps(outcome, indent=2), flush=True)
        sys.exit(0)

    print("=" * 60)
    print("Starting Enclave Manager")
    print(f"Port: {config.service.port}")
    print("Endpoints available:")
    print("  - POST /enclave/deploy")
    print("  - POST /enclave/cvm/run")
    print("  - POST /enclave/cvm/confirmation")
    print("  - GET  /enclave/cvm/results")
    print("  - GET  /enclave/jwt")
    print("  - GET  /enclave/state")
    print("  - POST /enclave/setstate")
    print("  - GET  /enclave/inference")
    print("  - GET  /enclave/status")
    print("=" * 60)
    app.run(host=config.service.host, port=config.service.port, debug=True)
