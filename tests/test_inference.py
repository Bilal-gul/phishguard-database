import numpy as np
import pytest
import joblib
import pandas as pd

import PhishGuard.predict as prediction_module
from PhishGuard.feature_extractor import FEATURE_COLUMNS
from PhishGuard.model_artifact import ARTIFACT_FORMAT, load_model_artifact, save_model_bundle
from PhishGuard.predict import resolve_model_path


class FakeModel:
    classes_ = np.array([0, 1])
    feature_names_in_ = np.array(FEATURE_COLUMNS)

    def predict(self, X):
        assert list(X.columns) == FEATURE_COLUMNS
        return np.array([0])

    def predict_proba(self, X):
        return np.array([[0.8, 0.2]])


def test_prediction_maps_class_probabilities(monkeypatch):
    monkeypatch.setattr(prediction_module, "model", FakeModel())
    result = prediction_module.predict_url("https://example.com/login")
    assert result["prediction"] == 0
    assert result["result"] == "PHISHING"
    assert result["phishing_probability"] == 80.0
    assert result["legitimate_probability"] == 20.0


def test_prediction_probability_mapping_uses_class_labels_not_array_order(monkeypatch):
    class ReversedClassModel(FakeModel):
        classes_ = np.array([1, 0])

        def predict_proba(self, X):
            return np.array([[0.2, 0.8]])

    monkeypatch.setattr(prediction_module, "model", ReversedClassModel())
    result = prediction_module.predict_url("https://example.com/login")
    assert result["phishing_probability"] == 80.0
    assert result["legitimate_probability"] == 20.0


def test_prediction_rejects_malformed_model_probabilities(monkeypatch):
    class InvalidProbabilityModel(FakeModel):
        def predict_proba(self, X):
            return np.array([[0.8, 0.3]])

    monkeypatch.setattr(prediction_module, "model", InvalidProbabilityModel())
    with pytest.raises(ValueError, match="sum to one"):
        prediction_module.predict_url("https://example.com/")


def _fitted_model():
    from sklearn.dummy import DummyClassifier

    X = pd.DataFrame(0, index=range(4), columns=FEATURE_COLUMNS)
    X[FEATURE_COLUMNS[0]] = [0, 0, 1, 1]
    return DummyClassifier(strategy="prior").fit(X, [0, 0, 1, 1])


def test_model_path_prefers_bundle_falls_back_to_legacy_and_honors_override(tmp_path):
    data = tmp_path / "data"
    legacy = data / "best_model.pkl"
    bundle = data / "artifacts" / "phishguard_model.joblib"
    legacy.parent.mkdir(parents=True)
    legacy.touch()
    assert resolve_model_path(tmp_path) == legacy

    bundle.parent.mkdir(parents=True)
    bundle.touch()
    assert resolve_model_path(tmp_path) == bundle
    assert resolve_model_path(tmp_path, "data/best_model.pkl") == legacy
    assert resolve_model_path(tmp_path, "data/runtime_model.joblib") == data / "runtime_model.joblib"


def test_inference_loads_a_versioned_bundle_and_checks_its_schema(tmp_path, monkeypatch):
    artifact = tmp_path / "bundle.joblib"
    save_model_bundle(
        _fitted_model(), artifact, feature_columns=FEATURE_COLUMNS,
        configuration={"selected_model": "test"}, metrics={},
    )
    monkeypatch.setattr(prediction_module, "MODEL_PATH", artifact)
    monkeypatch.setattr(prediction_module, "model", None)
    monkeypatch.setattr(prediction_module, "MODEL_METADATA", {})

    result = prediction_module.predict_url("https://example.com/")

    assert result["prediction"] == 0
    assert prediction_module.MODEL_METADATA["artifact_format"] == ARTIFACT_FORMAT
    with pytest.raises(ValueError, match="feature schema"):
        load_model_artifact(artifact, FEATURE_COLUMNS[:-1])


def test_inference_keeps_support_for_a_trusted_legacy_pickle(tmp_path, monkeypatch):
    artifact = tmp_path / "legacy.pkl"
    joblib.dump(_fitted_model(), artifact)
    monkeypatch.setattr(prediction_module, "MODEL_PATH", artifact)
    monkeypatch.setattr(prediction_module, "model", None)
    monkeypatch.setattr(prediction_module, "MODEL_METADATA", {})

    result = prediction_module.predict_url("https://example.com/")

    assert result["prediction"] == 0
    assert prediction_module.MODEL_METADATA == {"legacy_artifact": True}
