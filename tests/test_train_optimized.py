from pathlib import Path

from sklearn.model_selection import ParameterGrid

import training.train_optimized as train_optimized


def test_optimized_runner_passes_fixed_protocol_and_new_artifact_path(tmp_path, monkeypatch):
    calls = []

    def fake_train_and_select(**kwargs):
        calls.append(kwargs)
        return {"artifact_path": str(kwargs["artifact_path"])}

    monkeypatch.setattr(train_optimized, "train_and_select", fake_train_and_select)

    result = train_optimized.run_optimized_training(tmp_path / "synthetic-data", tmp_path / "candidate-artifacts")

    assert len(calls) == 1
    call = calls[0]
    candidate_count = sum(len(ParameterGrid(item["params"])) for item in call["estimator_configs"].values())
    assert candidate_count == 18
    assert call["n_splits"] == 5
    assert call["random_state"] == 42
    assert call["overwrite_artifact"] is False
    artifact_path = Path(call["artifact_path"])
    assert artifact_path.name == "phishguard_optimized18.joblib"
    assert artifact_path.parent.is_dir()
    assert not artifact_path.exists()
    assert artifact_path.parent.parent.name == "candidate-artifacts"
    assert result["artifact_path"] == str(artifact_path)


def test_candidate_path_reservation_is_unique_and_never_reuses_existing_artifact(tmp_path):
    first = train_optimized._new_candidate_artifact_path(tmp_path / "candidates")
    second = train_optimized._new_candidate_artifact_path(tmp_path / "candidates")

    assert first != second
    assert first.parent != second.parent
    assert not first.exists()
    assert not second.exists()
