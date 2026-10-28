"""Candidate model definitions used by the offline training pipeline."""

from sklearn.ensemble import ExtraTreesClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.neighbors import KNeighborsClassifier
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier


def build_model_configs(random_state: int = 42):
    """Return reproducibly seeded estimator and parameter-grid definitions."""
    return {
        "logistic_regression": {
            "model": Pipeline([
                ("scaler", StandardScaler()),
                ("model", LogisticRegression(random_state=random_state)),
            ]),
            "params": {
                "model__C": [0.1, 1, 10],
                "model__penalty": ["l2"],
                "model__solver": ["lbfgs"],
                "model__max_iter": [2000],
            },
        },
        "knn": {
            "model": Pipeline([
                ("scaler", StandardScaler()),
                ("model", KNeighborsClassifier()),
            ]),
            "params": {
                "model__n_neighbors": [5, 15, 30],
                "model__weights": ["uniform", "distance"],
                "model__metric": ["euclidean"],
            },
        },
        "decision_tree": {
            "model": Pipeline([("model", DecisionTreeClassifier(random_state=random_state))]),
            "params": {
                "model__max_depth": [5, 15, 25],
                "model__min_samples_leaf": [5, 20],
                "model__criterion": ["gini"],
            },
        },
        "extra_trees": {
            "model": Pipeline([("model", ExtraTreesClassifier(random_state=random_state))]),
            "params": {
                "model__n_estimators": [100, 200],
                "model__max_depth": [15, 25],
                "model__min_samples_leaf": [2, 5],
                "model__max_features": ["sqrt"],
            },
        },
        "random_forest": {
            "model": Pipeline([("model", RandomForestClassifier(random_state=random_state))]),
            "params": {
                "model__n_estimators": [100, 200],
                "model__max_depth": [15, 25],
                "model__min_samples_leaf": [2, 5],
                "model__max_features": ["sqrt"],
            },
        },
    }


# Retain the previous public name for existing imports.
basic_model = build_model_configs()
