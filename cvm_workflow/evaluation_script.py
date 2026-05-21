#!/usr/bin/env python3
"""Evaluate an ONNX model against a decrypted placeholder dataset."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def _ensure_vendor_path() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    vendor = repo_root / ".vendor"
    if vendor.exists():
        sys.path.insert(0, str(vendor))


_ensure_vendor_path()

import numpy as np
import onnxruntime as ort
from sklearn.metrics import accuracy_score, roc_auc_score


def _debug(message: str) -> None:
    print(f"[evaluation] {message}", flush=True)


def _load_json(path: Path) -> dict:
    _debug(f"Loading JSON from {path}")
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _dataset_1(features: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    _debug("Running dataset 1 preprocessing subscript: binary bright-center classification")
    return features.astype(np.float32), labels.astype(np.int64)


def _dataset_2(features: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    _debug("Running dataset 2 preprocessing subscript: 3-class stripe classification")
    return features.astype(np.float32), labels.astype(np.int64)


def _dataset_3(features: np.ndarray, labels: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    _debug("Running dataset 3 preprocessing subscript: binary diagonal-pattern classification")
    return features.astype(np.float32), labels.astype(np.int64)


DATASET_PREPROCESSORS = {
    1: _dataset_1,
    2: _dataset_2,
    3: _dataset_3,
}


def _normalise_probabilities(logits: np.ndarray, class_count: int) -> np.ndarray:
    logits = logits[:, :class_count]
    logits = logits - logits.max(axis=1, keepdims=True)
    exp_logits = np.exp(logits)
    return exp_logits / exp_logits.sum(axis=1, keepdims=True)


def _compute_auc(labels: np.ndarray, probabilities: np.ndarray) -> float | None:
    unique_labels = np.unique(labels)
    if len(unique_labels) < 2:
        _debug("AUC skipped because the selected dataset has fewer than two classes")
        return None
    if len(unique_labels) == 2:
        return float(roc_auc_score(labels, probabilities[:, 1]))
    return float(roc_auc_score(labels, probabilities, multi_class="ovr"))


def evaluate(model_path: Path, dataset_path: Path, results_path: Path) -> dict:
    dataset = _load_json(dataset_path)
    dataset_id = int(dataset["dataset_id"])
    class_count = int(dataset["num_classes"])

    if dataset_id not in DATASET_PREPROCESSORS:
        raise ValueError(f"Unsupported dataset_id {dataset_id}; expected one of 1, 2, 3")

    features = np.asarray(dataset["features"], dtype=np.float32)
    labels = np.asarray(dataset["labels"], dtype=np.int64)
    features, labels = DATASET_PREPROCESSORS[dataset_id](features, labels)

    _debug(f"Creating ONNX Runtime session for {model_path}")
    session = ort.InferenceSession(str(model_path), providers=["CPUExecutionProvider"])
    input_name = session.get_inputs()[0].name
    _debug(f"Model compiled into ONNX Runtime session; input tensor is '{input_name}'")

    _debug(f"Running inference for {len(labels)} samples")
    logits = session.run(None, {input_name: features})[0]
    probabilities = _normalise_probabilities(logits, class_count)
    predictions = probabilities.argmax(axis=1)

    results = {
        "dataset_id": dataset_id,
        "sample_count": int(len(labels)),
        "num_classes": class_count,
        "accuracy": float(accuracy_score(labels, predictions)),
        "auc": _compute_auc(labels, probabilities),
    }

    _debug(f"Writing results to {results_path}")
    results_path.parent.mkdir(parents=True, exist_ok=True)
    with results_path.open("w", encoding="utf-8") as handle:
        json.dump(results, handle, indent=2)

    _debug(f"Evaluation complete: accuracy={results['accuracy']}, auc={results['auc']}")
    return results


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate a placeholder ONNX model inside the CVM workflow")
    parser.add_argument("--model", required=True, type=Path)
    parser.add_argument("--dataset", required=True, type=Path)
    parser.add_argument("--results", required=True, type=Path)
    args = parser.parse_args()

    evaluate(args.model, args.dataset, args.results)


if __name__ == "__main__":
    main()
