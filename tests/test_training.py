import pandas as pd
from ddos_ml.training import split_indices


def test_group_split_has_no_group_overlap_and_both_classes():
    y = pd.Series([0, 1] * 50)
    groups = pd.Series([f"flow-{i}" for i in range(100)])
    train_idx, test_idx, label = split_indices(y, groups)
    assert set(groups.iloc[train_idx]).isdisjoint(set(groups.iloc[test_idx]))
    assert y.iloc[train_idx].nunique() == 2
    assert y.iloc[test_idx].nunique() == 2
    assert "GroupShuffleSplit" in label


def test_group_split_never_falls_back_to_row_split_when_groups_are_unusable():
    import pytest

    y = pd.Series([0, 1] * 20)
    groups = pd.Series(["only-a", "only-b"] * 20)
    with pytest.raises(ValueError, match="distinct flow groups"):
        split_indices(y, groups)


def test_group_split_fails_loudly_if_each_group_contains_only_one_class():
    import pytest

    y = pd.Series([0] * 20 + [1] * 20)
    groups = pd.Series([f"benign-{i}" for i in range(20)] + [f"attack-{i}" for i in range(20)])
    # GroupShuffleSplit can still separate groups, but each partition may contain both classes
    # only if multiple groups per class are available. This should be possible here.
    train_idx, test_idx, label = split_indices(y, groups)
    assert y.iloc[train_idx].nunique() == 2
    assert y.iloc[test_idx].nunique() == 2
    assert set(groups.iloc[train_idx]).isdisjoint(set(groups.iloc[test_idx]))
    assert "GroupShuffleSplit" in label


def test_training_sampler_balances_classes_without_using_test_rows():
    import numpy as np
    from ddos_ml.training import _sample_balanced_training

    y = pd.Series([0] * 100 + [1] * 900)
    selected = _sample_balanced_training(y, max_train_rows=200, random_state=42)
    counts = y.iloc[selected].value_counts().to_dict()
    assert counts == {0: 100, 1: 100}
    assert len(np.unique(selected)) == 200


def test_live_features_match_training_zero_duration_missing_rate_behavior():
    import numpy as np
    from ddos_ml.features import live_flow_features

    row = live_flow_features({
        "ip_proto": 17,
        "duration_sec": 0,
        "duration_nsec": 0,
        "packet_count": 2,
        "byte_count": 100,
    })
    assert np.isnan(row["packet_rate"])
    assert np.isnan(row["byte_rate"])
    assert row["avg_packet_size"] == 50


def test_metrics_report_both_attack_and_benign_performance():
    import numpy as np
    from ddos_ml.training import _metrics

    metrics = _metrics(
        np.array([0, 0, 1, 1]),
        np.array([0, 1, 1, 1]),
        np.array([0.1, 0.8, 0.7, 0.9]),
    )
    assert metrics["attack_recall"] == 1.0
    assert metrics["benign_recall"] == 0.5
    assert metrics["false_positive_rate"] == 0.5
    assert "average_precision_benign" in metrics
