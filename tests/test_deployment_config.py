from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "PhishGuard"


def test_runtime_image_copies_model_loader_and_data_directory():
    dockerfile = (APP / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY model_artifact.py ." in dockerfile
    assert "COPY data ./data" in dockerfile
    assert ".dockerignore limits this copy to inference models" in dockerfile.lower()


def test_docker_context_allows_only_runtime_models_and_excludes_candidates():
    dockerignore = (APP / ".dockerignore").read_text(encoding="utf-8")
    assert "data/*" in dockerignore
    assert "!data/best_model.pkl" in dockerignore
    assert "!data/runtime_model.joblib" in dockerignore
    assert "!data/artifacts/" in dockerignore
    assert "data/artifacts/*" in dockerignore
    assert "!data/artifacts/phishguard_model.joblib" in dockerignore
    assert "!data/artifacts/candidates/" not in dockerignore
    assert "!data/artifacts/candidates/*" not in dockerignore
    assert "!data/X_train.csv" not in dockerignore
    assert "!data/features_data.csv" not in dockerignore


def test_compose_forwards_optional_model_path_override():
    compose = (APP / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'PHISHGUARD_MODEL_PATH: "${PHISHGUARD_MODEL_PATH:-}"' in compose
    env_example = (APP / ".env.example").read_text(encoding="utf-8")
    assert "PHISHGUARD_MODEL_PATH=data/runtime_model.joblib" in env_example
    release_guide = (APP / "MODEL_RELEASE.md").read_text(encoding="utf-8")
    assert "data/runtime_model.joblib" in release_guide
    assert "data/artifacts/candidates/optimized18-<release-tag>" not in release_guide


def test_runtime_model_slot_remains_git_ignored():
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "**/data/*" in gitignore
    assert "!PhishGuard/data/runtime_model.joblib" not in gitignore
