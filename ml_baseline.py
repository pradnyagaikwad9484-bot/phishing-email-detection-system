"""Optional experimental ML baseline. Requires scikit-learn.

Use only with a properly licensed, representative labeled dataset. The bundled
synthetic sample is for demonstrating the workflow, not claiming accuracy.
"""
from pathlib import Path
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

def train_baseline(csv_path: str):
    df = pd.read_csv(csv_path).fillna("")
    if not {"body", "label"}.issubset(df.columns):
        raise ValueError("Dataset must contain 'body' and 'label' columns.")
    labels = df["label"].astype(str).str.lower().map({
        "phishing": 1, "malicious": 1, "1": 1, "legitimate": 0, "safe": 0, "0": 0
    })
    valid = labels.notna()
    df, labels = df.loc[valid], labels.loc[valid]
    if labels.nunique() < 2 or len(df) < 8:
        raise ValueError("Need at least 8 labeled examples and both classes.")
    X = (df["subject"].astype(str) + " " + df["body"].astype(str))
    X_train, X_test, y_train, y_test = train_test_split(
        X, labels, test_size=0.25, random_state=42, stratify=labels
    )
    model = Pipeline([
        ("tfidf", TfidfVectorizer(ngram_range=(1, 2), max_features=10000, stop_words="english")),
        ("classifier", LogisticRegression(max_iter=1000, class_weight="balanced"))
    ])
    model.fit(X_train, y_train)
    predictions = model.predict(X_test)
    return model, classification_report(y_test, predictions, zero_division=0), confusion_matrix(y_test, predictions)
