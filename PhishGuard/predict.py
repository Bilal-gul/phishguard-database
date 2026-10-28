"""PhishGuard prediction service.

Loads the trained model once and exposes predict_url() for both CLI and FastAPI.
Expected labels: 0 = phishing, 1 = legitimate.
"""

import os
from pathlib import Path

import pandas as pd

try:  # Support both Docker's flat module layout and repository package imports.
    from .feature_extractor import FEATURE_COLUMNS, extract_url_features
    from .model_artifact import load_model_artifact
except ImportError:  # pragma: no cover - exercised by the Docker module layout
    from feature_extractor import FEATURE_COLUMNS, extract_url_features
    from model_artifact import load_model_artifact

BASE_DIR = Path(__file__).resolve().parent
LEGACY_MODEL_PATH = BASE_DIR / "data" / "best_model.pkl"
DEFAULT_BUNDLE_PATH = BASE_DIR / "data" / "artifacts" / "phishguard_model.joblib"


def resolve_model_path(base_dir: str | Path, configured_path: str | None = None) -> Path:
    """Prefer the versioned bundle, retain the legacy default, allow an override."""
    base = Path(base_dir).resolve()
    if configured_path:
        override = Path(configured_path).expanduser()
        return override.resolve() if override.is_absolute() else (base / override).resolve()
    bundle = base / "data" / "artifacts" / "phishguard_model.joblib"
    legacy = base / "data" / "best_model.pkl"
    return bundle if bundle.exists() else legacy


MODEL_PATH = resolve_model_path(BASE_DIR, os.getenv("PHISHGUARD_MODEL_PATH"))

model = None
MODEL_METADATA: dict = {}


def _load_model():
    global model, MODEL_METADATA
    if model is not None:
        return model
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Model file not found: {MODEL_PATH}. Place a trusted model artifact at the configured path."
        )
    loaded_model, metadata = load_model_artifact(MODEL_PATH, FEATURE_COLUMNS)
    if not hasattr(loaded_model, "predict") or not hasattr(loaded_model, "predict_proba"):
        raise TypeError("Configured model artifact must provide predict and predict_proba methods.")
    if hasattr(loaded_model, "feature_names_in_") and list(loaded_model.feature_names_in_) != FEATURE_COLUMNS:
        raise ValueError("Configured model feature order does not match the URL feature extractor.")
    model = loaded_model
    MODEL_METADATA = metadata
    return model


def predict_url(url: str) -> dict:
    """Predict whether a URL is phishing and return class probabilities."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL cannot be empty.")

    cleaned_url = url.strip()
    extracted = extract_url_features(cleaned_url)

    missing = [name for name in FEATURE_COLUMNS if name not in extracted]
    if missing:
        raise ValueError(f"Extractor is missing model features: {missing}")

    X = pd.DataFrame(
        [{name: extracted[name] for name in FEATURE_COLUMNS}],
        columns=FEATURE_COLUMNS,
    )

    predictor = _load_model()
    prediction = int(predictor.predict(X)[0])
    if prediction not in (0, 1):
        raise ValueError(f"Expected model prediction 0 or 1, got {prediction}.")
    probabilities = predictor.predict_proba(X)[0]
    classes = list(predictor.classes_)

    if 0 not in classes or 1 not in classes:
        raise ValueError(
            f"Expected model classes [0, 1], got {classes}. "
            "Check the label mapping used during model training."
        )

    phishing_probability = float(probabilities[classes.index(0)])
    legitimate_probability = float(probabilities[classes.index(1)])
    if not all(pd.notna(value) and 0 <= value <= 1 for value in (phishing_probability, legitimate_probability)):
        raise ValueError("Model returned invalid class probabilities.")
    if abs(phishing_probability + legitimate_probability - 1.0) > 1e-6:
        raise ValueError("Model class probabilities do not sum to one.")
    phishing_probability *= 100
    legitimate_probability *= 100

    return {
        "url": cleaned_url,
        "prediction": prediction,
        "result": "LEGITIMATE" if prediction == 1 else "PHISHING",
        "phishing_probability": round(phishing_probability, 2),
        "legitimate_probability": round(legitimate_probability, 2),
        "full_domain": extracted.get("FullDomain"),
    }


def main() -> None:
    url = input("URL: ").strip()
    try:
        result = predict_url(url)
    except (ValueError, TypeError) as exc:
        print(f"Could not analyze URL: {exc}")
        return

    print("=" * 50)
    print("                 URL PREDICTION")
    print("=" * 50)
    print(f"URL        : {result['url']}")
    print(f"Domain     : {result['full_domain']}")
    print(f"Result     : {result['result']}")
    print(f"Phishing   : {result['phishing_probability']:.2f}%")
    print(f"Legitimate : {result['legitimate_probability']:.2f}%")
    print("=" * 50)


if __name__ == "__main__":
    main()
