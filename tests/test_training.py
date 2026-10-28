import joblib
import numpy as np
import pandas as pd
import weakref
from pathlib import Path
from sklearn.dummy import DummyClassifier
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.tree import DecisionTreeClassifier

import fit as fit_module
from PhishGuard.feature_extractor import FEATURE_COLUMNS
from PhishGuard.model_artifact import load_model_artifact
from fit import phishing_f1_score, train_and_select
from model import evaluate_model


def _write_split_data(directory):
    for split, domain_count in (("train", 36), ("val", 12), ("test", 12)):
        domain_labels = np.arange(domain_count) % 2
        labels = np.repeat(domain_labels, 2)
        domains = [f"{split}-{index}.example" for index in range(domain_count) for _ in range(2)]
        features = pd.DataFrame(0.0, index=range(len(labels)), columns=FEATURE_COLUMNS)
        features[FEATURE_COLUMNS[0]] = labels
        features.to_csv(directory / f"X_{split}.csv", index=False)
        pd.Series(labels, name="Labels").to_csv(directory / f"y_{split}.csv", index=False)
        pd.Series(domains, name="FullDomain").to_csv(directory / f"groups_{split}.csv", index=False)


def test_training_serializes_the_validation_selected_estimator(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _write_split_data(data_dir)
    configs = {
        "tree": {"model": DecisionTreeClassifier(random_state=3), "params": {"max_depth": [2]}},
        "baseline": {"model": DummyClassifier(strategy="most_frequent"), "params": {"strategy": ["most_frequent"]}},
    }
    artifact = tmp_path / "new-model.joblib"

    result = train_and_select(data_dir, artifact, n_splits=3, estimator_configs=configs)

    assert result["selected_model"] == "tree"
    estimator, metadata = load_model_artifact(artifact, FEATURE_COLUMNS)
    assert type(estimator).__name__ == "DecisionTreeClassifier"
    assert metadata["configuration"]["selected_model"] == "tree"
    assert metadata["configuration"]["cv"]["class"] == "StratifiedGroupKFold"


def test_artifact_writer_does_not_replace_existing_file_by_default(tmp_path):
    target = tmp_path / "existing.joblib"
    joblib.dump({"keep": True}, target)
    from PhishGuard.model_artifact import save_model_bundle
    import pytest

    with pytest.raises(FileExistsError):
        save_model_bundle(DummyClassifier(), target, feature_columns=FEATURE_COLUMNS, configuration={}, metrics={})
    assert joblib.load(target) == {"keep": True}


def test_each_inner_cross_validation_fold_keeps_domains_together():
    labels = np.repeat(np.arange(15) % 2, 2)
    groups = np.repeat([f"domain-{index}" for index in range(15)], 2)
    splitter = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=42)
    for train_idx, validation_idx in splitter.split(np.zeros((30, 1)), labels, groups):
        assert not set(groups[train_idx]) & set(groups[validation_idx])


def test_phishing_f1_uses_class_zero_as_the_positive_class():
    # Class 1 F1 is 0.8 here; class 0 phishing F1 is 2/3.
    assert phishing_f1_score([0, 0, 1, 1], [0, 1, 1, 1]) == 2 / 3


def test_training_defers_test_loading_releases_losing_estimators_and_keeps_first_tie(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _write_split_data(data_dir)
    validation_predictions = []
    test_loaded_after_selection = []
    estimator_refs = {}
    search_settings = []
    original_read_xy = fit_module._read_xy
    original_read_groups = fit_module._read_groups

    def tracked_read_xy(source, split):
        if split == "test":
            assert validation_predictions == ["first", "second"]
            assert estimator_refs["first"]() is not None
            assert estimator_refs["second"]() is None
            test_loaded_after_selection.append("features-and-labels")
        X, y = original_read_xy(source, split)
        X[FEATURE_COLUMNS[0]] = {"train": 0.0, "val": 11.0, "test": 22.0}[split]
        return X, y

    def tracked_read_groups(source, split, row_count):
        if split == "test":
            assert validation_predictions == ["first", "second"]
            test_loaded_after_selection.append("groups")
        return original_read_groups(source, split, row_count)

    class FakeEstimator:
        def __init__(self, name):
            self.name = name

        def predict(self, X):
            if X.iloc[0, 0] == 11.0:
                validation_predictions.append(self.name)
            return np.zeros(len(X), dtype=int)

    class FakeGridSearchCV:
        def __init__(self, *, estimator, param_grid, cv, scoring, n_jobs, pre_dispatch, refit, error_score):
            self.family = estimator
            search_settings.append({
                "cv": cv,
                "scoring": scoring,
                "n_jobs": n_jobs,
                "pre_dispatch": pre_dispatch,
                "refit": refit,
                "error_score": error_score,
            })

        def fit(self, X, y, *, groups):
            assert len(X) == len(y) == len(groups)
            self.best_estimator_ = FakeEstimator(self.family)
            estimator_refs[self.family] = weakref.ref(self.best_estimator_)
            self.best_score_ = 0.5
            self.best_params_ = {"candidate": self.family}
            return self

        def predict(self, X):
            return self.best_estimator_.predict(X)

    monkeypatch.setattr(fit_module, "_read_xy", tracked_read_xy)
    monkeypatch.setattr(fit_module, "_read_groups", tracked_read_groups)
    monkeypatch.setattr(fit_module, "GridSearchCV", FakeGridSearchCV)
    monkeypatch.setattr(
        fit_module,
        "save_model_bundle",
        lambda estimator, destination, **kwargs: Path(destination),
    )

    configs = {
        "first": {"model": "first", "params": [{}]},
        "second": {"model": "second", "params": [{}]},
    }
    artifact = tmp_path / "synthetic-candidate.joblib"
    result = train_and_select(data_dir, artifact, n_splits=5, estimator_configs=configs)

    assert result["selected_model"] == "first"
    assert test_loaded_after_selection == ["features-and-labels", "groups"]
    assert len(search_settings) == 2
    for settings in search_settings:
        assert isinstance(settings["cv"], StratifiedGroupKFold)
        assert settings["cv"].n_splits == 5
        assert settings["cv"].random_state == 42
        assert settings["scoring"]._score_func is phishing_f1_score
        assert settings["n_jobs"] == 1
        assert settings["pre_dispatch"] == 1
        assert settings["refit"] is True


def test_evaluation_uses_model_as_is_and_does_not_refit(tmp_path):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    _write_split_data(data_dir)
    X = pd.read_csv(data_dir / "X_train.csv")
    y = pd.read_csv(data_dir / "y_train.csv").iloc[:, 0]
    estimator = DecisionTreeClassifier(max_depth=2, random_state=4).fit(X, y)
    artifact = tmp_path / "evaluation-model.joblib"
    from PhishGuard.model_artifact import save_model_bundle
    save_model_bundle(
        estimator, artifact, feature_columns=FEATURE_COLUMNS,
        configuration={"selected_model": "tree"}, metrics={},
    )

    result = evaluate_model(data_dir, artifact)

    assert result["metrics"]["phishing_f1"] == 1.0
    assert result["metadata"]["configuration"]["selected_model"] == "tree"
