"""Train and select a PhishGuard model using domain-aware validation."""

from __future__ import annotations

import argparse
import json
import logging
import platform
import time
from pathlib import Path
from typing import Any

import pandas as pd
import sklearn
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    f1_score,
    make_scorer,
    precision_score,
    recall_score,
)
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold

from PhishGuard.feature_extractor import FEATURE_COLUMNS
from PhishGuard.model_artifact import save_model_bundle
from model_pipeline import build_model_configs

LOGGER = logging.getLogger("phishguard.training")
REPOSITORY_ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = REPOSITORY_ROOT / "PhishGuard" / "data"
DEFAULT_ARTIFACT_PATH = DEFAULT_DATA_DIR / "artifacts" / "phishguard_model.joblib"
LABEL_MAPPING = {0: "phishing", 1: "legitimate"}


def phishing_f1_score(y_true, y_pred) -> float:
    """F1 for phishing class 0 (positive class), with safe zero-division behavior."""
    return float(f1_score(y_true, y_pred, pos_label=0, zero_division=0))


def _read_xy(data_dir: Path, split: str) -> tuple[pd.DataFrame, pd.Series]:
    X = pd.read_csv(data_dir / f"X_{split}.csv")
    y_frame = pd.read_csv(data_dir / f"y_{split}.csv")
    if y_frame.shape[1] != 1:
        raise ValueError(f"y_{split}.csv must contain exactly one label column.")
    y = y_frame.iloc[:, 0]
    if list(X.columns) != FEATURE_COLUMNS:
        raise ValueError(f"X_{split}.csv feature columns do not match feature_extractor.FEATURE_COLUMNS.")
    _validate_labels(y, split)
    return X, y.astype(int)


def _validate_labels(labels: pd.Series, split: str) -> None:
    if labels.isna().any() or not set(labels.unique()).issubset(LABEL_MAPPING):
        raise ValueError(f"{split} labels must contain only 0 (phishing) and 1 (legitimate).")
    if set(labels.unique()) != set(LABEL_MAPPING):
        raise ValueError(f"{split} split must contain both expected classes 0 and 1.")


def _read_groups(data_dir: Path, split: str, row_count: int) -> pd.Series:
    groups_frame = pd.read_csv(data_dir / f"groups_{split}.csv")
    if groups_frame.shape[1] != 1 or len(groups_frame) != row_count:
        raise ValueError(f"groups_{split}.csv must have one column and align row-for-row with X_{split}.csv.")
    groups = groups_frame.iloc[:, 0].fillna("").astype(str)
    if (groups.str.strip() == "").any():
        raise ValueError(f"groups_{split}.csv contains missing or blank domains.")
    return groups


def _assert_disjoint_groups(*named_groups: tuple[str, pd.Series]) -> None:
    seen: dict[str, str] = {}
    for split, values in named_groups:
        for group in set(values):
            previous = seen.get(group)
            if previous:
                raise ValueError(f"Domain leakage between {previous} and {split} splits.")
            seen[group] = split


def train_and_select(
    data_dir: str | Path = DEFAULT_DATA_DIR,
    artifact_path: str | Path = DEFAULT_ARTIFACT_PATH,
    *,
    n_splits: int = 5,
    random_state: int = 42,
    estimator_configs: dict[str, dict[str, Any]] | None = None,
    overwrite_artifact: bool = False,
) -> dict[str, Any]:
    """Fit candidate searches, select by validation phishing F1, then evaluate test once."""
    source = Path(data_dir).expanduser().resolve()
    X_train, y_train = _read_xy(source, "train")
    X_val, y_val = _read_xy(source, "val")
    groups_train = _read_groups(source, "train", len(X_train))
    groups_val = _read_groups(source, "val", len(X_val))
    _assert_disjoint_groups(("train", groups_train), ("validation", groups_val))
    training_rows = len(X_train)
    training_domains = int(groups_train.nunique())

    distinct_groups = groups_train.nunique()
    if n_splits < 2 or n_splits > distinct_groups:
        raise ValueError(f"n_splits must be between 2 and the {distinct_groups} training domains.")
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    scoring = make_scorer(phishing_f1_score)
    configs = estimator_configs if estimator_configs is not None else build_model_configs(random_state)
    if not configs:
        raise ValueError("At least one estimator configuration is required.")

    selected: dict[str, Any] | None = None
    for name, config in configs.items():
        search = GridSearchCV(
            estimator=config["model"],
            param_grid=config["params"],
            cv=splitter,
            scoring=scoring,
            n_jobs=1,
            pre_dispatch=1,
            refit=True,
            error_score="raise",
        )
        # Passing groups here is essential: the splitter then keeps domains
        # intact in every inner cross-validation fold.
        search.fit(X_train, y_train, groups=groups_train)
        validation_predictions = search.predict(X_val)
        metrics = {
            "validation_phishing_f1": phishing_f1_score(y_val, validation_predictions),
            "validation_phishing_precision": float(precision_score(y_val, validation_predictions, pos_label=0, zero_division=0)),
            "validation_phishing_recall": float(recall_score(y_val, validation_predictions, pos_label=0, zero_division=0)),
            "validation_accuracy": float(accuracy_score(y_val, validation_predictions)),
        }
        candidate = {
            "name": name,
            "cv_phishing_f1": float(search.best_score_),
            "best_params": search.best_params_,
            "estimator": search.best_estimator_,
            "validation_metrics": metrics,
        }
        # Strict greater-than preserves max(candidates, key=...) semantics:
        # equal validation F1 keeps the first candidate encountered.
        if selected is None or metrics["validation_phishing_f1"] > selected["validation_metrics"]["validation_phishing_f1"]:
            selected = candidate
        LOGGER.info("Candidate %s validation phishing F1: %.4f", name, metrics["validation_phishing_f1"])
        # Keep only the current winner. Drop the search result tables, the
        # current validation predictions, and any losing fitted estimator.
        del validation_predictions, metrics, candidate, search

    if selected is None:
        raise ValueError("At least one estimator configuration is required.")

    # Training/validation arrays and groups are no longer needed after selection.
    # Load the held-out test split only for final evaluation, after selection.
    del X_train, y_train, X_val, y_val
    X_test, y_test = _read_xy(source, "test")
    groups_test = _read_groups(source, "test", len(X_test))
    _assert_disjoint_groups(
        ("train", groups_train), ("validation", groups_val), ("test", groups_test)
    )
    del groups_train, groups_val
    test_predictions = selected["estimator"].predict(X_test)
    test_metrics = {
        "test_phishing_f1": phishing_f1_score(y_test, test_predictions),
        "test_phishing_precision": float(precision_score(y_test, test_predictions, pos_label=0, zero_division=0)),
        "test_phishing_recall": float(recall_score(y_test, test_predictions, pos_label=0, zero_division=0)),
        "test_accuracy": float(accuracy_score(y_test, test_predictions)),
        "test_classification_report": classification_report(
            y_test, test_predictions, labels=[0, 1], target_names=["phishing", "legitimate"],
            zero_division=0, output_dict=True,
        ),
    }
    del X_test, y_test, groups_test, test_predictions
    configuration = {
        "random_state": random_state,
        "cv": {"class": "StratifiedGroupKFold", "n_splits": n_splits, "shuffle": True},
        "selection_metric": "validation_phishing_f1",
        "cv_metric": "phishing_f1 (positive label 0)",
        "feature_columns": FEATURE_COLUMNS,
        "selected_model": selected["name"],
        "selected_parameters": selected["best_params"],
        "training_rows": training_rows,
        "training_domains": training_domains,
        "candidate_models": {
            name: {
                "estimator": type(config["model"]).__name__,
                "parameter_grid": config["params"],
            }
            for name, config in configs.items()
        },
        "split_manifest": (
            json.loads((source / "split_manifest.json").read_text(encoding="utf-8"))
            if (source / "split_manifest.json").exists()
            else None
        ),
        "software_versions": {
            "python": platform.python_version(),
            "scikit_learn": sklearn.__version__,
            "pandas": pd.__version__,
        },
    }
    metrics = {**selected["validation_metrics"], **test_metrics, "cv_phishing_f1": selected["cv_phishing_f1"]}
    destination = save_model_bundle(
        selected["estimator"], artifact_path,
        feature_columns=FEATURE_COLUMNS,
        configuration=configuration,
        metrics=metrics,
        overwrite=overwrite_artifact,
    )
    return {"selected_model": selected["name"], "artifact_path": str(destination), "metrics": metrics, "configuration": configuration}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--artifact", type=Path, default=DEFAULT_ARTIFACT_PATH)
    parser.add_argument("--splits", type=int, default=5)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--overwrite-artifact", action="store_true", help="Replace the destination artifact.")
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    started = time.perf_counter()
    result = train_and_select(
        args.data_dir, args.artifact, n_splits=args.splits,
        random_state=args.seed, overwrite_artifact=args.overwrite_artifact,
    )
    result["elapsed_seconds"] = round(time.perf_counter() - started, 2)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
