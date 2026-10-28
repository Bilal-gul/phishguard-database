import numpy as np
import pandas as pd
import pytest
from pathlib import Path

import training.compare_search_spaces as comparison
from PhishGuard.feature_extractor import FEATURE_COLUMNS


def _write_synthetic_split(data_dir, split, domain_count):
    labels = np.repeat(np.arange(domain_count) % 2, 2)
    groups = np.repeat([f"{split}-domain-{i}" for i in range(domain_count)], 2)
    X = pd.DataFrame(0, index=range(len(labels)), columns=FEATURE_COLUMNS)
    X.to_csv(data_dir / f"X_{split}.csv", index=False)
    pd.Series(labels, name="Labels").to_csv(data_dir / f"y_{split}.csv", index=False)
    pd.Series(groups, name="FullDomain").to_csv(data_dir / f"groups_{split}.csv", index=False)


def test_shared_cv_splits_are_reproducible_and_domain_disjoint():
    domain_count = 50
    groups = pd.Series(np.repeat([f"domain-{i}" for i in range(domain_count)], 2))
    y = pd.Series(np.repeat(np.arange(domain_count) % 2, 2))
    X = pd.DataFrame({"feature": np.zeros(len(y))})

    first = comparison._build_shared_splits(X, y, groups, seed=17)
    second = comparison._build_shared_splits(X, y, groups, seed=17)

    assert len(first) == len(second) == 5
    group_values = groups.to_numpy()
    for (train_a, score_a), (train_b, score_b) in zip(first, second):
        np.testing.assert_array_equal(train_a, train_b)
        np.testing.assert_array_equal(score_a, score_b)
        assert not set(group_values[train_a]) & set(group_values[score_a])


def test_comparison_uses_shared_folds_and_only_train_validation_files(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _write_synthetic_split(data_dir, "train", 50)
    _write_synthetic_split(data_dir, "val", 10)
    read_paths = []
    original_read_csv = pd.read_csv

    def audited_read_csv(path, *args, **kwargs):
        read_paths.append(str(path))
        assert Path(path).name not in {"X_test.csv", "y_test.csv", "groups_test.csv"}
        return original_read_csv(path, *args, **kwargs)

    class DummyEstimator:
        def predict(self, X):
            return np.zeros(len(X), dtype=int)

    fit_calls = []

    class FakeGridSearchCV:
        def __init__(self, *, estimator, param_grid, cv, scoring, n_jobs, pre_dispatch, refit, error_score):
            self.cv = cv
            self.param_grid = param_grid
            self.best_estimator_ = DummyEstimator()
            assert n_jobs == 1
            assert pre_dispatch == 1
            assert refit is True
            assert error_score == "raise"
            assert scoring is not None

        def fit(self, X, y, *, groups):
            fit_calls.append((self.cv, len(X), len(y), len(groups)))
            self.best_score_ = 0.75
            self.best_params_ = {"synthetic": True}
            return self

    monkeypatch.setattr(pd, "read_csv", audited_read_csv)
    monkeypatch.setattr(comparison, "GridSearchCV", FakeGridSearchCV)

    report = comparison.run_comparison(data_dir, tmp_path / "report.json", seed=17)

    assert len(fit_calls) == 10  # Five families for each of two strategies.
    shared_folds = fit_calls[0][0]
    assert all(call[0] is shared_folds for call in fit_calls)
    assert all(call[1:] == (100, 100, 100) for call in fit_calls)
    assert len(read_paths) == 6
    assert {path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1] for path in read_paths} == {
        "X_train.csv", "y_train.csv", "groups_train.csv",
        "X_val.csv", "y_val.csv", "groups_val.csv",
    }
    assert [strategy["candidate_count"] for strategy in report["strategies"]] == [31, 18]
    assert all(len(strategy["families"]) == 5 for strategy in report["strategies"])
    assert all("validation_phishing_precision" in family for strategy in report["strategies"] for family in strategy["families"])
    assert all("validation_phishing_recall" in family for strategy in report["strategies"] for family in strategy["families"])


def test_existing_report_is_refused_before_reading_data(tmp_path, monkeypatch):
    report_path = tmp_path / "existing.json"
    report_path.write_text("keep me", encoding="utf-8")

    def forbidden_read(*args, **kwargs):
        pytest.fail("Data must not be read when the report already exists.")

    monkeypatch.setattr(comparison, "_read_split", forbidden_read)

    with pytest.raises(FileExistsError):
        comparison.run_comparison(tmp_path / "missing-data", report_path)

    assert report_path.read_text(encoding="utf-8") == "keep me"
