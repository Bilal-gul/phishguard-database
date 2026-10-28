import pandas as pd
import pytest

from PhishGuard.feature_extractor import FEATURE_COLUMNS
from preprocessing import SplitConfig, make_group_splits, write_splits


def _dataset():
    rows = []
    for index in range(30):
        label = index % 2
        for sample in range(2):
            row = {column: 0 for column in FEATURE_COLUMNS}
            row[FEATURE_COLUMNS[0]] = label
            rows.append({"URLs": f"https://d{index}.example/{label}/{sample}", "FullDomain": f"d{index}.example", **row, "Labels": label})
    return pd.DataFrame(rows)


def test_group_splits_are_disjoint_and_reproducible():
    frame = _dataset()
    config = SplitConfig(test_size=0.2, validation_size=0.2, random_state=12)
    first = make_group_splits(frame, config=config)
    second = make_group_splits(frame, config=config)
    for name in first:
        pd.testing.assert_frame_equal(first[name][0], second[name][0])
        pd.testing.assert_series_equal(first[name][2], second[name][2])

    groups = {name: set(values[2]) for name, values in first.items()}
    assert not groups["train"] & groups["validation"]
    assert not groups["train"] & groups["test"]
    assert not groups["validation"] & groups["test"]


def test_split_writer_refuses_to_overwrite_existing_files(tmp_path):
    output = tmp_path / "splits"
    write_splits(_dataset(), output, config=SplitConfig(0.2, 0.2, 12))
    with pytest.raises(FileExistsError, match="overwrite"):
        write_splits(_dataset(), output, config=SplitConfig(0.2, 0.2, 12))
