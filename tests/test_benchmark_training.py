import pandas as pd

from PhishGuard.feature_extractor import FEATURE_COLUMNS
from training.benchmark_training import _select_grouped_subset


def test_benchmark_subset_is_stratified_and_keeps_domains_intact(tmp_path):
    data_dir = tmp_path / "train"
    data_dir.mkdir()
    domains = [f"domain-{index}.example" for index in range(100) for _ in range(2)]
    labels = [index % 2 for index in range(100) for _ in range(2)]
    pd.Series(labels, name="Labels").to_csv(data_dir / "y_train.csv", index=False)
    pd.Series(domains, name="FullDomain").to_csv(data_dir / "groups_train.csv", index=False)
    features = pd.DataFrame(0, index=range(len(labels)), columns=FEATURE_COLUMNS)
    features[FEATURE_COLUMNS[0]] = labels
    features.to_csv(data_dir / "X_train.csv", index=False)
    y = pd.Series(labels)
    groups = pd.Series(domains)

    X_sub, y_sub, groups_sub = _select_grouped_subset(data_dir, y, groups, 0.2, 42)

    assert len(X_sub) == len(y_sub) == len(groups_sub)
    assert set(y_sub.unique()) == {0, 1}
    assert groups_sub.nunique() == len(groups_sub) // 2
    assert X_sub.columns.tolist() == FEATURE_COLUMNS


def test_benchmark_sampling_preserves_class_proportions_and_is_deterministic(tmp_path):
    data_dir = tmp_path / "train"
    data_dir.mkdir()
    # Every domain is single-label, allowing close class-ratio matching while
    # still asserting that the sampler only selects whole domains.
    domains = [f"phish-{index}.example" for index in range(70)]
    labels = [0] * 70
    domains += [f"legit-{index}.example" for index in range(130)]
    labels += [1] * 130
    pd.Series(labels, name="Labels").to_csv(data_dir / "y_train.csv", index=False)
    pd.Series(domains, name="FullDomain").to_csv(data_dir / "groups_train.csv", index=False)
    pd.DataFrame(0, index=range(200), columns=FEATURE_COLUMNS).to_csv(
        data_dir / "X_train.csv", index=False
    )
    y = pd.Series(labels)
    groups = pd.Series(domains)

    first = _select_grouped_subset(data_dir, y, groups, 0.4, 42)
    second = _select_grouped_subset(data_dir, y, groups, 0.4, 42)

    X_sub, y_sub, groups_sub = first
    assert X_sub.equals(second[0])
    assert y_sub.equals(second[1])
    assert groups_sub.equals(second[2])
    assert y_sub.value_counts().sort_index().to_dict() == {0: 28, 1: 52}
    assert groups_sub.nunique() == len(groups_sub)
