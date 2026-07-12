"""
train_model.py - ML Classifier Training Script
Trains a lightweight RandomForest classifier on the lexical features
extracted from URLs (see modules/lexical_analysis.py:extract_ml_features).

NOTE ON THE TRAINING DATA:
This script generates a synthetic dataset by sampling feature values from
distributions that reflect well-documented differences between phishing
and legitimate URLs (e.g. phishing URLs tend to be longer, use more
suspicious keywords, and lack HTTPS more often). This keeps the project
fully self-contained with no external dataset download required.

For production-grade accuracy, replace `generate_synthetic_dataset()`
below with a real labeled dataset (e.g. the PhishTank or UCI Phishing
Websites datasets) loaded via pandas.read_csv().
"""

import random
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import joblib
import os

FEATURE_NAMES = [
    "url_length", "has_ip", "has_at_symbol", "subdomain_count",
    "hyphen_count", "has_https", "keyword_count", "is_shortened",
    "has_suspicious_tld", "digit_count", "dot_count", "path_length",
]

random.seed(42)
np.random.seed(42)


def _sample_legit():
    return {
        "url_length": max(10, int(np.random.normal(28, 8))),
        "has_ip": 0,
        "has_at_symbol": 0,
        "subdomain_count": max(0, int(np.random.normal(0.5, 0.6))),
        "hyphen_count": max(0, int(np.random.normal(0.3, 0.5))),
        "has_https": np.random.choice([1, 1, 1, 0], p=[0.6, 0.2, 0.15, 0.05]),
        "keyword_count": np.random.choice([0, 0, 0, 1], p=[0.7, 0.15, 0.1, 0.05]),
        "is_shortened": 0,
        "has_suspicious_tld": 0,
        "digit_count": max(0, int(np.random.normal(0.5, 1.0))),
        "dot_count": max(1, int(np.random.normal(1.5, 0.5))),
        "path_length": max(0, int(np.random.normal(8, 6))),
    }


def _sample_phishing():
    return {
        "url_length": max(15, int(np.random.normal(65, 20))),
        "has_ip": np.random.choice([0, 1], p=[0.75, 0.25]),
        "has_at_symbol": np.random.choice([0, 1], p=[0.85, 0.15]),
        "subdomain_count": max(0, int(np.random.normal(2.2, 1.2))),
        "hyphen_count": max(0, int(np.random.normal(2.0, 1.3))),
        "has_https": np.random.choice([1, 0], p=[0.45, 0.55]),
        "keyword_count": max(0, int(np.random.normal(2.0, 1.2))),
        "is_shortened": np.random.choice([0, 1], p=[0.7, 0.3]),
        "has_suspicious_tld": np.random.choice([0, 1], p=[0.6, 0.4]),
        "digit_count": max(0, int(np.random.normal(4.0, 2.5))),
        "dot_count": max(1, int(np.random.normal(3.5, 1.2))),
        "path_length": max(0, int(np.random.normal(25, 15))),
    }


def generate_synthetic_dataset(n_per_class=1500):
    rows, labels = [], []
    for _ in range(n_per_class):
        rows.append(_sample_legit())
        labels.append(0)  # 0 = legitimate
    for _ in range(n_per_class):
        rows.append(_sample_phishing())
        labels.append(1)  # 1 = phishing

    X = np.array([[r[f] for f in FEATURE_NAMES] for r in rows])
    y = np.array(labels)
    return X, y


def train_and_save(model_path="models/phishguard_model.pkl"):
    X, y = generate_synthetic_dataset()
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)

    clf = RandomForestClassifier(n_estimators=150, max_depth=10, random_state=42)
    clf.fit(X_train, y_train)

    preds = clf.predict(X_test)
    acc = accuracy_score(y_test, preds)
    print(f"[+] Model trained. Test accuracy: {acc:.2%}")
    print(classification_report(y_test, preds, target_names=["Legitimate", "Phishing"]))

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump({"model": clf, "feature_names": FEATURE_NAMES}, model_path)
    print(f"[+] Model saved to: {model_path}")
    return acc


if __name__ == "__main__":
    train_and_save()
