"""Compare original and reduced PhishGuard searches without test data/artifacts.

The runner reads only the training and validation CSVs. It does not reference
test-split paths and never serializes fitted estimators.
"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, make_scorer, precision_score, recall_score
from sklearn.model_selection import GridSearchCV, ParameterGrid, StratifiedGroupKFold

from PhishGuard.feature_extractor import FEATURE_COLUMNS
from model_pipeline import build_model_configs
from optimized_model_pipeline import build_optimized_model_configs


EXPECTED_LABELS = {0, 1}


def _read_split(data_dir: Path, split: str) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Read one explicitly permitted split and verify row/schema alignment."""
    if split not in {"train", "val"}:
        raise ValueError("Only the train and validation splits are supported.")

    X = pd.read_csv(data_dir / f"X_{split}.csv")
    y_frame = pd.read_csv(data_dir / f"y_{split}.csv")
    groups_frame = pd.read_csv(data_dir / f"groups_{split}.csv")
    if list(X.columns) != FEATURE_COLUMNS:
        raise ValueError(f"X_{split}.csv columns do not match FEATURE_COLUMNS.")
    if y_frame.shape[1] != 1 or groups_frame.shape[1] != 1:
        raise ValueError(f"{split} labels and groups must each contain one column.")
    if len(X) != len(y_frame) or len(X) != len(groups_frame):
        raise ValueError(f"{split} feature, label, and group rows are not aligned.")

    y = y_frame.iloc[:, 0]
    if y.isna().any() or set(y.unique()) != EXPECTED_LABELS:
        raise ValueError(f"{split} labels must contain both classes 0 and 1 only.")
    groups = groups_frame.iloc[:, 0].fillna("").astype(str)
    if (groups.str.strip() == "").any():
        raise ValueError(f"{split} groups must contain non-empty domains.")
    return X, y.astype(int), groups


def _build_shared_splits(
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    *,
    seed: int,
    n_splits: int = 5,
) -> list[tuple[np.ndarray, np.ndarray]]:
    """Create and verify one reusable set of group-disjoint CV folds."""
    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=seed)
    folds = list(splitter.split(X, y, groups))
    group_values = groups.to_numpy()
    for train_indices, score_indices in folds:
        if set(group_values[train_indices]) & set(group_values[score_indices]):
            raise RuntimeError("A domain crosses a cross-validation fold boundary.")
        if set(y.iloc[train_indices].unique()) != EXPECTED_LABELS:
            raise ValueError("A CV training fold does not contain both expected classes.")
        if set(y.iloc[score_indices].unique()) != EXPECTED_LABELS:
            raise ValueError("A CV scoring fold does not contain both expected classes.")
    return folds


def _evaluate_strategy(
    name: str,
    configs: dict[str, dict[str, Any]],
    X_train: pd.DataFrame,
    y_train: pd.Series,
    groups_train: pd.Series,
    X_val: pd.DataFrame,
    y_val: pd.Series,
    folds: list[tuple[np.ndarray, np.ndarray]],
) -> dict[str, Any]:
    scorer = make_scorer(f1_score, pos_label=0, zero_division=0)
    family_results: list[dict[str, Any]] = []
    strategy_started = time.perf_counter()

    for family, config in configs.items():
        started = time.perf_counter()
        search = GridSearchCV(
            estimator=config["model"],
            param_grid=config["params"],
            cv=folds,
            scoring=scorer,
            n_jobs=1,
            pre_dispatch=1,
            refit=True,
            error_score="raise",
        )
        search.fit(X_train, y_train, groups=groups_train)
        predictions = search.best_estimator_.predict(X_val)
        family_results.append({
            "family": family,
            "candidate_count": len(ParameterGrid(config["params"])),
            "best_params": search.best_params_,
            "cv_phishing_f1": float(search.best_score_),
            "validation_phishing_f1": float(f1_score(y_val, predictions, pos_label=0, zero_division=0)),
            "validation_phishing_precision": float(
                precision_score(y_val, predictions, pos_label=0, zero_division=0)
            ),
            "validation_phishing_recall": float(
                recall_score(y_val, predictions, pos_label=0, zero_division=0)
            ),
            "elapsed_seconds": round(time.perf_counter() - started, 3),
        })

    selected = max(family_results, key=lambda item: item["validation_phishing_f1"])
    return {
        "name": name,
        "candidate_count": sum(item["candidate_count"] for item in family_results),
        "selected_family_by_validation_phishing_f1": selected["family"],
        "selected_validation_phishing_f1": selected["validation_phishing_f1"],
        "elapsed_seconds": round(time.perf_counter() - strategy_started, 3),
        "families": family_results,
    }


def _write_report_exclusively(report_path: Path, report: dict[str, Any]) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    # Exclusive creation prevents accidental replacement of an earlier report.
    with report_path.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")


def run_comparison(
    data_dir: str | Path,
    report_path: str | Path,
    *,
    seed: int = 42,
) -> dict[str, Any]:
    """Run both searches on identical train-only CV folds and validation data."""
    source = Path(data_dir).expanduser().resolve()
    destination = Path(report_path).expanduser().resolve()
    if destination.exists():
        raise FileExistsError(f"Refusing to overwrite comparison report: {destination}")

    X_train, y_train, groups_train = _read_split(source, "train")
    X_val, y_val, groups_val = _read_split(source, "val")
    if list(X_val.columns) != list(X_train.columns):
        raise ValueError("Training and validation feature orders differ.")
    if set(groups_train) & set(groups_val):
        raise ValueError("A domain occurs in both training and validation data.")

    folds = _build_shared_splits(X_train, y_train, groups_train, seed=seed, n_splits=5)
    strategies = (
        ("original_31", build_model_configs(seed)),
        ("optimized_18", build_optimized_model_configs(seed)),
    )
    results = [
        _evaluate_strategy(
            name, configs, X_train, y_train, groups_train, X_val, y_val, folds
        )
        for name, configs in strategies
    ]
    report = {
        "data_scope": "train and validation only",
        "seed": seed,
        "cv": {
            "class": "StratifiedGroupKFold",
            "n_splits": 5,
            "shuffle": True,
            "shared_precomputed_splits": True,
            "n_jobs": 1,
            "scoring": "phishing F1 (positive label 0)",
        },
        "training_rows": len(X_train),
        "training_domains": int(groups_train.nunique()),
        "validation_rows": len(X_val),
        "validation_domains": int(groups_val.nunique()),
        "strategies": results,
    }
    _write_report_exclusively(destination, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    report = run_comparison(args.data_dir, args.report, seed=args.seed)
    print(json.dumps(report, indent=2))
    print(f"Report written to {args.report.expanduser().resolve()}")


if __name__ == "__main__":
    main()
