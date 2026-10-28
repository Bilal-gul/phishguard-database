"""Bounded, train-only runtime benchmark for representative PhishGuard models.

This command samples only X_train/y_train/groups_train, performs no artifact
serialization, and runs each estimator case in a monitored child process.
"""

from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from pathlib import Path
from queue import Empty
from typing import Any

import numpy as np
import pandas as pd
import psutil
from sklearn.metrics import make_scorer
from sklearn.model_selection import GridSearchCV, StratifiedGroupKFold

from PhishGuard.feature_extractor import FEATURE_COLUMNS
from fit import phishing_f1_score
from model_pipeline import build_model_configs


BENCHMARK_PARAMS: dict[str, dict[str, list[Any]]] = {
    "logistic_regression": {
        "model__C": [10], "model__penalty": ["l2"], "model__solver": ["lbfgs"], "model__max_iter": [2000],
    },
    "knn": {
        "model__n_neighbors": [30], "model__weights": ["distance"], "model__metric": ["euclidean"],
    },
    "decision_tree": {
        "model__max_depth": [25], "model__min_samples_leaf": [5], "model__criterion": ["gini"],
    },
    "extra_trees": {
        "model__n_estimators": [200], "model__max_depth": [25],
        "model__min_samples_leaf": [2], "model__max_features": ["sqrt"],
    },
    "random_forest": {
        "model__n_estimators": [200], "model__max_depth": [25],
        "model__min_samples_leaf": [2], "model__max_features": ["sqrt"],
    },
}


def _write_report(path: Path, report: dict[str, Any], *, first_write: bool = False) -> None:
    mode = "x" if first_write else "w"
    with path.open(mode, encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def _load_training_labels(data_dir: Path) -> tuple[pd.Series, pd.Series]:
    """Read only training labels and domains; validation/test paths are never opened."""
    labels_path = data_dir / "y_train.csv"
    groups_path = data_dir / "groups_train.csv"
    labels_frame = pd.read_csv(labels_path)
    groups_frame = pd.read_csv(groups_path)
    if labels_frame.shape[1] != 1 or groups_frame.shape[1] != 1:
        raise ValueError("Training label and group CSVs must each contain one column.")
    labels = labels_frame.iloc[:, 0].astype(int)
    groups = groups_frame.iloc[:, 0].fillna("").astype(str)
    if len(labels) != len(groups) or (groups.str.strip() == "").any():
        raise ValueError("Training labels and groups must align and contain non-empty domains.")
    if set(labels.unique()) != {0, 1}:
        raise ValueError("Training split must contain both label 0 and label 1.")
    return labels, groups


def _select_grouped_subset(
    data_dir: Path,
    labels: pd.Series,
    groups: pd.Series,
    fraction: float,
    seed: int,
) -> tuple[pd.DataFrame, pd.Series, pd.Series]:
    if not 0 < fraction < 1:
        raise ValueError("Sample fraction must be strictly between 0 and 1.")
    label_values = labels.to_numpy()
    group_codes, _ = pd.factorize(groups, sort=False)
    group_sizes = np.bincount(group_codes)
    phishing_sizes = np.bincount(
        group_codes, weights=(label_values == 0).astype(np.int64)
    ).astype(np.int64)
    legitimate_sizes = group_sizes - phishing_sizes

    # Sample whole domains while independently capping each label at its
    # full-training proportion target. The seeded permutation makes selection
    # reproducible; labels are never split within a domain.
    target_by_label = np.bincount(label_values, minlength=2) * fraction
    rng = np.random.default_rng(seed)
    group_order = rng.permutation(len(group_sizes))
    selected_group_mask = np.zeros(len(group_sizes), dtype=bool)
    selected_by_label = np.zeros(2, dtype=np.int64)
    for group_id in group_order:
        group_counts = np.array([phishing_sizes[group_id], legitimate_sizes[group_id]])
        if np.all(selected_by_label + group_counts <= target_by_label):
            selected_group_mask[group_id] = True
            selected_by_label += group_counts

    sample_indices = np.flatnonzero(selected_group_mask[group_codes])
    wanted = np.sort(sample_indices)

    feature_path = data_dir / "X_train.csv"
    chunks: list[pd.DataFrame] = []
    offset = 0
    for chunk in pd.read_csv(feature_path, chunksize=25_000):
        if list(chunk.columns) != FEATURE_COLUMNS:
            raise ValueError("X_train.csv feature columns do not match the extractor schema.")
        end = offset + len(chunk)
        left = np.searchsorted(wanted, offset, side="left")
        right = np.searchsorted(wanted, end, side="left")
        if left < right:
            chunks.append(chunk.iloc[wanted[left:right] - offset])
        offset = end
    if offset != len(labels):
        raise ValueError("X_train.csv rows do not align with y_train.csv and groups_train.csv.")

    sampled_X = pd.concat(chunks, ignore_index=True)
    sampled_y = labels.iloc[wanted].reset_index(drop=True)
    sampled_groups = groups.iloc[wanted].reset_index(drop=True)
    if set(sampled_y.unique()) != {0, 1}:
        raise ValueError(f"Selected {fraction:.1%} domain fold does not contain both labels.")
    return sampled_X, sampled_y, sampled_groups


def _fit_worker(
    estimator: Any,
    params: dict[str, list[Any]],
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    seed: int,
    result_queue: Any,
) -> None:
    try:
        started = time.perf_counter()
        search = GridSearchCV(
            estimator=estimator,
            param_grid=params,
            cv=StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=seed),
            scoring=make_scorer(phishing_f1_score),
            n_jobs=1,
            pre_dispatch=1,
            refit=True,
            error_score="raise",
        )
        search.fit(X, y, groups=groups)
        result = {
            "status": "completed",
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "mean_cv_phishing_f1": float(search.best_score_),
        }
    except BaseException as exc:  # Return a small safe error summary to the parent.
        result = {"status": "error", "error_type": type(exc).__name__}
    result_queue.put(result)


def _run_bounded_case(
    estimator: Any,
    params: dict[str, list[Any]],
    X: pd.DataFrame,
    y: pd.Series,
    groups: pd.Series,
    seed: int,
    timeout_seconds: int,
    max_process_bytes: int,
) -> dict[str, Any]:
    context = mp.get_context("spawn")
    result_queue = context.Queue(maxsize=1)
    process = context.Process(target=_fit_worker, args=(estimator, params, X, y, groups, seed, result_queue))
    started = time.perf_counter()
    process.start()
    peak_tree_bytes = 0
    stop_reason = None
    parent_process = psutil.Process(os.getpid())
    child_process = psutil.Process(process.pid)
    while process.is_alive():
        elapsed = time.perf_counter() - started
        try:
            tree_rss = parent_process.memory_info().rss + child_process.memory_info().rss
            peak_tree_bytes = max(peak_tree_bytes, tree_rss)
        except psutil.Error:
            tree_rss = 0
        if tree_rss > max_process_bytes:
            stop_reason = "process_tree_rss_limit"
            process.terminate()
            break
        if elapsed >= timeout_seconds:
            stop_reason = "case_timeout"
            process.terminate()
            break
        process.join(timeout=0.2)

    process.join(timeout=5)
    if process.is_alive():
        process.kill()
        process.join()

    result: dict[str, Any]
    try:
        result = result_queue.get(timeout=2)
    except Empty:
        result = {"status": "stopped" if stop_reason else "worker_failed"}
    finally:
        result_queue.close()
        result_queue.join_thread()

    result["elapsed_seconds"] = round(time.perf_counter() - started, 3)
    result["peak_process_tree_rss_bytes"] = peak_tree_bytes
    if stop_reason:
        result["status"] = stop_reason
    elif process.exitcode not in (0, None) and result.get("status") == "completed":
        result["status"] = "worker_failed"
    return result


def run_benchmark(args: argparse.Namespace) -> dict[str, Any]:
    data_dir = args.data_dir.expanduser().resolve()
    report_path = args.report.expanduser().resolve()
    report_path.parent.mkdir(parents=True, exist_ok=True)
    expected_scope = "X_train.csv, y_train.csv, groups_train.csv only"
    if report_path.exists():
        if not args.resume_report:
            raise FileExistsError(f"Refusing to overwrite benchmark report: {report_path}")
        report = json.loads(report_path.read_text(encoding="utf-8"))
        if report.get("data_scope") != expected_scope or report.get("status") not in {"interrupted", "partial"}:
            raise ValueError("--resume-report only resumes an interrupted/partial PhishGuard train-only report.")
        if report.get("seed") != args.seed or report.get("n_jobs") != 1:
            raise ValueError("Resume arguments do not match the existing report.")
        report["status"] = "running"
        report.pop("stop_reason", None)
        _write_report(report_path, report)
    else:
        report = {
            "status": "running",
            "data_scope": expected_scope,
            "seed": args.seed,
            "cv": {"class": "StratifiedGroupKFold", "n_splits": 5, "shuffle": True},
            "n_jobs": 1,
            "limits": {
                "case_timeout_seconds": args.case_timeout_seconds,
                "max_process_tree_rss_gib": args.max_process_memory_gib,
            },
            "cases": [],
        }
        _write_report(report_path, report, first_write=True)

    available_gib = psutil.virtual_memory().available / (1024**3)
    report["available_memory_at_start_gib"] = round(available_gib, 2)
    if available_gib < args.min_available_memory_gib:
        report.update(status="stopped", stop_reason="insufficient_available_memory")
        _write_report(report_path, report)
        return report

    labels, groups = _load_training_labels(data_dir)
    report["training_rows"] = len(labels)
    report["training_domains"] = int(groups.nunique())
    report["training_label_counts"] = {str(key): int(value) for key, value in labels.value_counts().sort_index().items()}
    configs = build_model_configs(args.seed)
    max_process_bytes = int(args.max_process_memory_gib * 1024**3)

    for fraction in args.sample_fractions:
        X_sample, y_sample, groups_sample = _select_grouped_subset(
            data_dir, labels, groups, fraction, args.seed
        )
        sample_info = {
            "fraction": fraction,
            "rows": len(y_sample),
            "domains": int(groups_sample.nunique()),
            "label_counts": {str(key): int(value) for key, value in y_sample.value_counts().sort_index().items()},
        }
        for family, params in BENCHMARK_PARAMS.items():
            already_completed = any(
                item.get("fraction") == fraction
                and item.get("family") == family
                and item.get("status") == "completed"
                for item in report["cases"]
            )
            if already_completed:
                continue
            case = {**sample_info, "family": family, "parameters": params}
            print(
                f"Benchmarking {fraction:.1%} sample: {family}, rows={len(y_sample)}, "
                f"domains={groups_sample.nunique()} ...",
                flush=True,
            )
            result = _run_bounded_case(
                configs[family]["model"], params, X_sample, y_sample, groups_sample,
                args.seed, args.case_timeout_seconds, max_process_bytes,
            )
            case.update(result)
            report["cases"].append(case)
            _write_report(report_path, report)
            print(
                f"  {result['status']}: {result['elapsed_seconds']:.1f}s, "
                f"peak process-tree RSS={result['peak_process_tree_rss_bytes'] / 1024**3:.2f} GiB",
                flush=True,
            )
            if result["status"] != "completed":
                report.update(status="partial", stop_reason=f"{family}_{result['status']}")
                _write_report(report_path, report)
                return report
        del X_sample, y_sample, groups_sample

    report["status"] = "completed"
    _write_report(report_path, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, required=True)
    parser.add_argument("--sample-fractions", type=float, nargs="+", default=[0.02, 0.05])
    parser.add_argument("--cv-splits", type=int, default=5, choices=[5])
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-jobs", type=int, default=1, choices=[1])
    parser.add_argument("--train-only", action="store_true", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--resume-report", action="store_true")
    parser.add_argument("--case-timeout-seconds", type=int, default=90)
    parser.add_argument("--max-process-memory-gib", type=float, default=4.0)
    parser.add_argument("--min-available-memory-gib", type=float, default=3.0)
    args = parser.parse_args()
    if any(fraction <= 0 or fraction >= 1 for fraction in args.sample_fractions):
        parser.error("sample fractions must be strictly between 0 and 1")

    result = run_benchmark(args)
    print(f"Report: {args.report.expanduser().resolve()}")
    print(f"Status: {result['status']}")
    if result.get("stop_reason"):
        print(f"Stop reason: {result['stop_reason']}")
    if result["status"] != "completed":
        sys.exit(2)


if __name__ == "__main__":
    main()
