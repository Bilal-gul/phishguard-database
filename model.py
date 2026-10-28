"""Evaluate a previously selected PhishGuard model on the held-out test split.

This command intentionally never fits or serializes a model. Model selection
belongs to fit.py and must not use the test set.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import pandas as pd
from sklearn.metrics import accuracy_score, classification_report, f1_score, precision_score, recall_score

from PhishGuard.feature_extractor import FEATURE_COLUMNS
from PhishGuard.model_artifact import load_model_artifact
from fit import (
    DEFAULT_ARTIFACT_PATH,
    DEFAULT_DATA_DIR,
    _assert_disjoint_groups,
    _read_groups,
    _read_xy,
)

LEGACY_ARTIFACT_PATH = DEFAULT_DATA_DIR / "best_model.pkl"


def evaluate_model(data_dir: str | Path = DEFAULT_DATA_DIR, artifact_path: str | Path | None = None) -> dict[str, Any]:
    source = Path(data_dir).expanduser().resolve()
    selected_path = Path(artifact_path).expanduser() if artifact_path else (
        DEFAULT_ARTIFACT_PATH if DEFAULT_ARTIFACT_PATH.exists() else LEGACY_ARTIFACT_PATH
    )
    X_test, y_test = _read_xy(source, "test")
    groups_train = _read_groups(source, "train", len(pd.read_csv(source / "y_train.csv")))
    groups_val = _read_groups(source, "val", len(pd.read_csv(source / "y_val.csv")))
    groups_test = _read_groups(source, "test", len(X_test))
    _assert_disjoint_groups(("train", groups_train), ("validation", groups_val), ("test", groups_test))
    estimator, metadata = load_model_artifact(selected_path, FEATURE_COLUMNS)
    if hasattr(estimator, "feature_names_in_") and list(estimator.feature_names_in_) != FEATURE_COLUMNS:
        raise ValueError("Model feature order does not match the held-out test data.")

    predictions = estimator.predict(X_test)
    return {
        "artifact": str(selected_path.resolve()),
        "metadata": metadata,
        "metrics": {
            "phishing_f1": float(f1_score(y_test, predictions, pos_label=0, zero_division=0)),
            "phishing_precision": float(precision_score(y_test, predictions, pos_label=0, zero_division=0)),
            "phishing_recall": float(recall_score(y_test, predictions, pos_label=0, zero_division=0)),
            "accuracy": float(accuracy_score(y_test, predictions)),
            "classification_report": classification_report(
                y_test, predictions, labels=[0, 1], target_names=["phishing", "legitimate"],
                output_dict=True, zero_division=0,
            ),
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--artifact", type=Path, default=None)
    args = parser.parse_args()
    print(json.dumps(evaluate_model(args.data_dir, args.artifact), indent=2, default=str))


if __name__ == "__main__":
    main()
