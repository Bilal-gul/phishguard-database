"""Opt-in training entry point for the separate 18-candidate search.

This command always writes to a fresh run directory under the candidate
artifact root. It never enables artifact overwrite and does not change the
default 31-candidate command in ``fit.py``.
"""

from __future__ import annotations

import argparse
import json
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sklearn.model_selection import ParameterGrid

from fit import DEFAULT_ARTIFACT_PATH, DEFAULT_DATA_DIR, train_and_select
from optimized_model_pipeline import build_optimized_model_configs


SEED = 42
N_SPLITS = 5
DEFAULT_CANDIDATE_ROOT = DEFAULT_DATA_DIR / "artifacts" / "candidates"
LEGACY_MODEL_PATH = DEFAULT_DATA_DIR / "best_model.pkl"


def _new_candidate_artifact_path(candidate_root: str | Path) -> Path:
    """Reserve a fresh per-run directory and return its not-yet-created model path."""
    root = Path(candidate_root).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    for _ in range(5):
        run_directory = root / f"optimized18-seed{SEED}-{timestamp}-{uuid.uuid4().hex}"
        try:
            run_directory.mkdir(exist_ok=False)
        except FileExistsError:
            continue
        artifact = run_directory / "phishguard_optimized18.joblib"
        if artifact.exists():
            raise FileExistsError(f"Unexpected existing candidate artifact: {artifact}")
        return artifact
    raise FileExistsError("Could not reserve a unique candidate artifact directory.")


def run_optimized_training(
    data_dir: str | Path = DEFAULT_DATA_DIR,
    candidate_root: str | Path = DEFAULT_CANDIDATE_ROOT,
) -> dict[str, Any]:
    """Run the approved optimized search into a unique, non-production path."""
    configs = build_optimized_model_configs(SEED)
    candidate_count = sum(len(ParameterGrid(config["params"])) for config in configs.values())
    if candidate_count != 18:
        raise RuntimeError(f"Expected the optimized search to contain 18 candidates, got {candidate_count}.")

    artifact_path = _new_candidate_artifact_path(candidate_root)
    if artifact_path in {DEFAULT_ARTIFACT_PATH.resolve(), LEGACY_MODEL_PATH.resolve()}:
        raise RuntimeError("Candidate artifact path resolves to a protected model path.")

    return train_and_select(
        data_dir=data_dir,
        artifact_path=artifact_path,
        n_splits=N_SPLITS,
        random_state=SEED,
        estimator_configs=configs,
        overwrite_artifact=False,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data-dir", type=Path, default=DEFAULT_DATA_DIR)
    parser.add_argument("--candidate-root", type=Path, default=DEFAULT_CANDIDATE_ROOT)
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    result = run_optimized_training(args.data_dir, args.candidate_root)
    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
