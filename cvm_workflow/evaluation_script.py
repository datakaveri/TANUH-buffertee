#!/usr/bin/env python3
import argparse
import hashlib
import json
import time
from pathlib import Path

import numpy as np
import onnxruntime as ort


def debug(message):
    print(f"[evaluation_script] {message}", flush=True)


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", required=True)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--results", required=True)
    args = parser.parse_args()

    started = time.time()
    model_path = Path(args.model)
    dataset_path = Path(args.dataset)
    results_path = Path(args.results)

    debug(f"Loading decrypted dataset from {dataset_path}")
    dataset = json.loads(dataset_path.read_text(encoding="utf-8"))
    features = np.asarray(dataset["features"], dtype=np.float32)
    labels = np.asarray(dataset["labels"], dtype=np.int64)
    debug(f"Dataset id={dataset.get('dataset_id')} description={dataset.get('description')}")
    debug(f"Feature tensor shape={list(features.shape)} labels={len(labels)}")

    debug(f"Creating ONNX Runtime session for {model_path}")
    debug(f"Model SHA256={sha256_file(model_path)}")
    external_weights = model_path.parent / "model.onnx.data"
    if external_weights.exists():
        debug(f"External weights SHA256={sha256_file(external_weights)}")
    else:
        raise FileNotFoundError(f"External weights file missing: {external_weights}")

    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    input_meta = session.get_inputs()[0]
    input_name = input_meta.name
    output_names = [output.name for output in session.get_outputs()]
    debug(f"ONNX input={input_name} shape={input_meta.shape} outputs={output_names}")

    batch_size = 8
    logits_batches = []
    for offset in range(0, len(features), batch_size):
        batch = features[offset : offset + batch_size]
        debug(f"Running inference batch offset={offset} size={len(batch)}")
        logits = session.run(output_names, {input_name: batch})[0]
        logits_batches.append(np.asarray(logits))

    logits = np.concatenate(logits_batches, axis=0)
    predictions = logits.argmax(axis=1).astype(np.int64)
    accuracy = float((predictions == labels).mean()) if len(labels) else 0.0
    max_seen_class = int(max(predictions.max(initial=0), labels.max(initial=0)))
    declared_classes = int(dataset.get("num_classes") or 0)
    matrix_size = max(declared_classes, max_seen_class + 1)
    confusion = np.zeros((matrix_size, matrix_size), dtype=np.int64)
    for truth, predicted in zip(labels, predictions):
        confusion[int(truth), int(predicted)] += 1

    distribution = {
        str(class_id): int((predictions == class_id).sum())
        for class_id in range(matrix_size)
    }
    results = {
        "status": "success",
        "dataset_id": dataset.get("dataset_id"),
        "dataset_description": dataset.get("description"),
        "num_samples": int(len(labels)),
        "num_classes": int(matrix_size),
        "accuracy": accuracy,
        "prediction_distribution": distribution,
        "confusion_matrix": confusion.tolist(),
        "onnx_runtime_providers": session.get_providers(),
        "onnx_input_name": input_name,
        "onnx_output_names": output_names,
        "logits_shape": list(logits.shape),
        "elapsed_seconds": round(time.time() - started, 4),
    }

    results_path.parent.mkdir(parents=True, exist_ok=True)
    results_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    debug(f"Results written to {results_path}")


if __name__ == "__main__":
    main()
