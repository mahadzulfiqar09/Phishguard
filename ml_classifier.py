"""
ml_classifier.py - Machine Learning Classification Module
Loads the trained RandomForest model and produces a phishing probability
for a given URL, based on its lexical features. Falls back gracefully
with an Info-level note if the model file hasn't been trained yet.
"""

import os
import joblib

from modules.lexical_analysis import extract_ml_features

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models", "phishguard_model.pkl")

_model_cache = None


def _load_model():
    global _model_cache
    if _model_cache is not None:
        return _model_cache
    if not os.path.exists(MODEL_PATH):
        return None
    _model_cache = joblib.load(MODEL_PATH)
    return _model_cache


def classify(url):
    """
    Returns a list with a single finding dict summarizing the ML verdict,
    plus its own 'points' contribution to the overall risk score.
    """
    bundle = _load_model()

    if bundle is None:
        return [{
            "check": "ML Classification", "severity": "Info", "status": "Model Not Trained",
            "detail": "Run 'python modules/train_model.py' to enable the ML classifier", "points": 0,
        }]

    model = bundle["model"]
    feature_names = bundle["feature_names"]

    features = extract_ml_features(url)
    vector = [[features[f] for f in feature_names]]

    proba = model.predict_proba(vector)[0]
    phishing_prob = proba[1]  # class 1 = phishing

    if phishing_prob >= 0.75:
        severity, status, points = "Critical", f"{phishing_prob:.0%} phishing probability", 30
    elif phishing_prob >= 0.5:
        severity, status, points = "High", f"{phishing_prob:.0%} phishing probability", 20
    elif phishing_prob >= 0.25:
        severity, status, points = "Low", f"{phishing_prob:.0%} phishing probability", 5
    else:
        severity, status, points = "Info", f"{phishing_prob:.0%} phishing probability", 0

    return [{
        "check": "ML Classification", "severity": severity, "status": status,
        "detail": "RandomForest model prediction based on 12 lexical URL features", "points": points,
    }]


if __name__ == "__main__":
    test_url = input("Enter URL to classify: ")
    for r in classify(test_url):
        print(f"[{r['severity']}] {r['check']}: {r['status']} (+{r['points']} pts)")
