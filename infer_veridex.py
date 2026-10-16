"""
VeriDex anomaly model inference.
Input must contain the same 26 numeric feature columns used during training.
This model flags unusual feature patterns; it does NOT prove a URL is malicious or benign.
"""
import sys
import joblib
import pandas as pd
import numpy as np

MODEL_PATH = "veridex_anomaly_model.joblib"

def predict_csv(input_csv, output_csv="veridex_predictions.csv"):
    bundle = joblib.load(MODEL_PATH)
    model = bundle["model"]
    features = bundle["feature_columns"]
    url_col = bundle.get("url_column", "url")

    # Supports ordinary CSV feature input. If the dataset file is actually Excel
    # content with a .csv extension, use pd.read_excel(input_csv) instead.
    try:
        df = pd.read_csv(r"C:\Users\SHREYA S\OneDrive\Documents\veridex_training_dataset_with_keywords.csv")
    except UnicodeDecodeError:
        df = pd.read_excel(input_csv)

    missing = [c for c in features if c not in df.columns]
    if missing:
        raise ValueError(
            "Missing required feature columns: " + ", ".join(missing) +
            ". Use the same feature extractor/schema used during training."
        )

    X = df[features].replace([np.inf, -np.inf], np.nan)
    raw = model.predict(X)
    scores = model.decision_function(X)

    result = pd.DataFrame()
    if url_col and url_col in df.columns:
        result["url"] = df[url_col]
    result["anomaly_score"] = scores
    result["model_result"] = [
        "ANOMALY - REVIEW REQUIRED" if p == -1 else "NOT FLAGGED BY ANOMALY MODEL"
        for p in raw
    ]
    result["warning"] = (
        "Anomaly detection only; not a verified phishing/benign classification."
    )
    result.to_csv(output_csv, index=False)
    print(result.head(20).to_string(index=False))
    print(f"\nSaved predictions to: {output_csv}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python infer_veridex.py input_features.csv [output.csv]")
        raise SystemExit(2)
    predict_csv(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "veridex_predictions.csv")
