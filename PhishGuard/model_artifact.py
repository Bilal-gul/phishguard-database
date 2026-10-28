"""Versioned PhishGuard model bundle serialization.

Only load artifacts produced by a trusted PhishGuard training pipeline. Joblib
uses pickle internally and loading an untrusted artifact can execute code.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

import joblib

ARTIFACT_FORMAT = "phishguard-model-bundle"
ARTIFACT_VERSION = 1
LABEL_MAPPING = {"0": "phishing", "1": "legitimate"}


def save_model_bundle(
    estimator: Any,
    destination: str | Path,
    *,
    feature_columns: list[str],
    configuration: dict[str, Any],
    metrics: dict[str, Any],
    overwrite: bool = False,
) -> Path:
    """Atomically save a versioned model bundle without replacing files by default."""
    target = Path(destination).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing model artifact: {target}")

    bundle = {
        "artifact_format": ARTIFACT_FORMAT,
        "artifact_version": ARTIFACT_VERSION,
        "estimator": estimator,
        "feature_columns": list(feature_columns),
        "label_mapping": LABEL_MAPPING.copy(),
        "configuration": configuration,
        "metrics": metrics,
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{target.name}.", suffix=".tmp", dir=target.parent
    )
    os.close(descriptor)
    temporary_path = Path(temporary_name)
    try:
        joblib.dump(bundle, temporary_path)
        if target.exists() and not overwrite:
            raise FileExistsError(f"Refusing to overwrite existing model artifact: {target}")
        os.replace(temporary_path, target)
    finally:
        temporary_path.unlink(missing_ok=True)
    return target


def load_model_artifact(path: str | Path, expected_features: list[str]) -> tuple[Any, dict[str, Any]]:
    """Load a trusted current bundle or a legacy bare estimator.

    The legacy path keeps existing installations working. New bundles are
    checked against the inference feature schema and label contract.
    """
    loaded = joblib.load(Path(path))
    if not isinstance(loaded, dict) or loaded.get("artifact_format") != ARTIFACT_FORMAT:
        return loaded, {"legacy_artifact": True}

    if loaded.get("artifact_version") != ARTIFACT_VERSION:
        raise ValueError("Unsupported PhishGuard model artifact version.")
    if loaded.get("feature_columns") != list(expected_features):
        raise ValueError("Model artifact feature schema does not match the URL feature extractor.")
    if loaded.get("label_mapping") != LABEL_MAPPING:
        raise ValueError("Model artifact label mapping does not match the inference contract.")
    estimator = loaded.get("estimator")
    if estimator is None:
        raise ValueError("Model artifact does not contain an estimator.")
    return estimator, {key: value for key, value in loaded.items() if key != "estimator"}
