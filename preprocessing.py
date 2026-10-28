"""Reproducibly split extracted URL features by registrable domain."""

from __future__ import annotations

import argparse
import json
from dataclasses import dataclass
from pathlib import Path

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from PhishGuard.feature_extractor import FEATURE_COLUMNS

REPOSITORY_ROOT = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = REPOSITORY_ROOT / "PhishGuard" / "data"


@dataclass(frozen=True)
class SplitConfig:
    test_size: float = 0.008
    validation_size: float = 0.011
    random_state: int = 42


def make_group_splits(
    frame: pd.DataFrame,
    *,
    config: SplitConfig = SplitConfig(),
) -> dict[str, tuple[pd.DataFrame, pd.Series, pd.Series]]:
    """Create train/validation/test rows with no FullDomain overlap."""
    required = {"URLs", "FullDomain", "Labels"}
    missing = required.difference(frame.columns)
    if missing:
        raise ValueError(f"Input dataset is missing required columns: {sorted(missing)}")
    if not 0 < config.test_size < 1 or not 0 < config.validation_size < 1:
        raise ValueError("test_size and validation_size must be between 0 and 1.")

    groups = frame["FullDomain"].fillna("").astype(str)
    if (groups.str.strip() == "").any():
        raise ValueError("FullDomain must be present for every row to prevent group leakage.")
    if frame["Labels"].isna().any() or not set(frame["Labels"].unique()).issubset({0, 1}):
        raise ValueError("Labels must contain only non-null values 0 (phishing) and 1 (legitimate).")
    feature_columns = [column for column in frame.columns if column not in required]
    if feature_columns != FEATURE_COLUMNS:
        raise ValueError("Input feature columns do not match feature_extractor.FEATURE_COLUMNS and their order.")

    X = frame.loc[:, feature_columns]
    y = frame["Labels"].astype(int)
    outer = GroupShuffleSplit(n_splits=1, test_size=config.test_size, random_state=config.random_state)
    train_val_idx, test_idx = next(outer.split(X, y, groups))

    train_val_x = X.iloc[train_val_idx]
    train_val_y = y.iloc[train_val_idx]
    train_val_groups = groups.iloc[train_val_idx]
    inner = GroupShuffleSplit(
        n_splits=1,
        test_size=config.validation_size,
        random_state=config.random_state,
    )
    train_idx, validation_idx = next(inner.split(train_val_x, train_val_y, train_val_groups))

    result = {
        "train": (train_val_x.iloc[train_idx].copy(), train_val_y.iloc[train_idx].copy(), train_val_groups.iloc[train_idx].copy()),
        "validation": (train_val_x.iloc[validation_idx].copy(), train_val_y.iloc[validation_idx].copy(), train_val_groups.iloc[validation_idx].copy()),
        "test": (X.iloc[test_idx].copy(), y.iloc[test_idx].copy(), groups.iloc[test_idx].copy()),
    }
    for split_name, (_, labels, _) in result.items():
        if set(labels.unique()) != {0, 1}:
            raise ValueError(
                f"Generated {split_name} split does not contain both labels; adjust split sizes or inspect group labels."
            )
    sets = {name: set(split[2]) for name, split in result.items()}
    if sets["train"] & sets["validation"] or sets["train"] & sets["test"] or sets["validation"] & sets["test"]:
        raise RuntimeError("Domain leakage detected between generated splits.")
    return result


def write_splits(
    frame: pd.DataFrame,
    output_dir: str | Path,
    *,
    config: SplitConfig = SplitConfig(),
    overwrite: bool = False,
) -> Path:
    """Write split CSVs; refuse to replace existing files unless requested."""
    destination = Path(output_dir).expanduser().resolve()
    names = (
        "X_train.csv", "y_train.csv", "groups_train.csv",
        "X_val.csv", "y_val.csv", "groups_val.csv",
        "X_test.csv", "y_test.csv", "groups_test.csv", "split_manifest.json",
    )
    existing = [destination / name for name in names if (destination / name).exists()]
    if existing and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing split files in {destination}; pass --overwrite to replace them.")
    splits = make_group_splits(frame, config=config)
    destination.mkdir(parents=True, exist_ok=True)
    for split_name, (features, labels, groups) in splits.items():
        suffix = "val" if split_name == "validation" else split_name
        features.to_csv(destination / f"X_{suffix}.csv", index=False)
        labels.to_csv(destination / f"y_{suffix}.csv", index=False)
        groups.to_frame(name="FullDomain").to_csv(destination / f"groups_{suffix}.csv", index=False)
    manifest = {
        "seed": config.random_state,
        "test_size_by_domain_fraction": config.test_size,
        "validation_size_by_remaining_domain_fraction": config.validation_size,
        "feature_columns": FEATURE_COLUMNS,
        "splits": {
            name: {
                "rows": len(labels),
                "domains": int(groups.nunique()),
                "label_counts": {str(label): int(count) for label, count in labels.value_counts().sort_index().items()},
            }
            for name, (_, labels, groups) in splits.items()
        },
    }
    (destination / "split_manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8"
    )
    return destination


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_DATA_DIR / "features_data.csv")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_DATA_DIR / "splits")
    parser.add_argument("--test-size", type=float, default=SplitConfig.test_size)
    parser.add_argument("--validation-size", type=float, default=SplitConfig.validation_size)
    parser.add_argument("--seed", type=int, default=SplitConfig.random_state)
    parser.add_argument("--overwrite", action="store_true", help="Replace split CSVs at the output path.")
    args = parser.parse_args()

    frame = pd.read_csv(args.input)
    destination = write_splits(
        frame,
        args.output_dir,
        config=SplitConfig(args.test_size, args.validation_size, args.seed),
        overwrite=args.overwrite,
    )
    print(f"Wrote group-separated train/validation/test splits to {destination}")


if __name__ == "__main__":
    main()
