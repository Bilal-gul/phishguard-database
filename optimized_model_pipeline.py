"""Opt-in 18-candidate search configuration for offline experiments.

The existing 31-candidate configuration in :mod:`model_pipeline` remains the
default. Pass ``build_optimized_model_configs(seed)`` explicitly to
``fit.train_and_select(estimator_configs=...)`` to use this alternative.
"""

from __future__ import annotations

from typing import Any

from model_pipeline import build_model_configs


def build_optimized_model_configs(random_state: int = 42) -> dict[str, dict[str, Any]]:
    """Return a separate, deterministic 18-candidate configuration.

    This function only defines estimators and parameter combinations; it does
    not load data, fit models, or alter the default training configuration.
    """
    configs = build_model_configs(random_state)

    # Keep all three regularization strengths from the original search.
    configs["logistic_regression"]["params"] = {
        "model__C": [0.1, 1, 10],
        "model__penalty": ["l2"],
        "model__solver": ["lbfgs"],
        "model__max_iter": [2000],
    }

    # Keep the two larger neighborhoods and both weighting strategies.
    configs["knn"]["params"] = {
        "model__n_neighbors": [15, 30],
        "model__weights": ["uniform", "distance"],
        "model__metric": ["euclidean"],
    }

    # Three preselected depth/leaf pairs sample shallow, regularized-mid,
    # and deeper/less-regularized trees without searching the full product.
    configs["decision_tree"]["params"] = [
        {"model__max_depth": [5], "model__min_samples_leaf": [5], "model__criterion": ["gini"]},
        {"model__max_depth": [15], "model__min_samples_leaf": [20], "model__criterion": ["gini"]},
        {"model__max_depth": [25], "model__min_samples_leaf": [5], "model__criterion": ["gini"]},
    ]

    # For each forest, retain both estimator counts at two paired tree
    # complexity settings. Other depth/leaf interactions are intentionally
    # excluded from this opt-in reduced search.
    forest_grid = [
        {
            "model__n_estimators": [n_estimators],
            "model__max_depth": [max_depth],
            "model__min_samples_leaf": [min_samples_leaf],
            "model__max_features": ["sqrt"],
        }
        for n_estimators in (100, 200)
        for max_depth, min_samples_leaf in ((15, 5), (25, 2))
    ]
    configs["extra_trees"]["params"] = forest_grid
    configs["random_forest"]["params"] = [dict(candidate) for candidate in forest_grid]

    return configs
