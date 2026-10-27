"""PhishGuard prediction service.

Loads the trained model once and exposes predict_url() for both CLI and FastAPI.
Expected labels: 0 = phishing, 1 = legitimate.
"""

from pathlib import Path

import joblib
import pandas as pd

from feature_extractor import FEATURE_COLUMNS, extract_url_features

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "data" / "best_model.pkl"

if not MODEL_PATH.exists():
    raise FileNotFoundError(
        f"Model file not found: {MODEL_PATH}. "
        "Place best_model.pkl inside the project's data/ directory."
    )

model = joblib.load(MODEL_PATH)


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

    prediction = int(model.predict(X)[0])
    probabilities = model.predict_proba(X)[0]
    classes = list(model.classes_)

    if 0 not in classes or 1 not in classes:
        raise ValueError(
            f"Expected model classes [0, 1], got {classes}. "
            "Check the label mapping used during model training."
        )

    phishing_probability = float(probabilities[classes.index(0)]) * 100
    legitimate_probability = float(probabilities[classes.index(1)]) * 100

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
