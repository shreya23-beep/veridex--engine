"""
VeriDex AI - Universal Model Training & ONNX Exporter Pipeline
Trains on CSV datasets (e.g. data/veridex_dataset.csv) containing 26 features:
- Lexical, structural, statistical entropy, and intent columns
- Balanced binary labels: 0 = Benign/Safe, 1 = Scam/Phishing/Threat
Compiles the model into an optimized ONNX runtime artifact for sub-millisecond on-device execution.
"""

import os
import json
import csv
from typing import Optional, Dict, Any
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

from .feature_extractor import extract_features, features_to_vector, FEATURE_COLUMNS

DEFAULT_DATASET_CSV = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "veridex_dataset.csv"
)

def load_data_from_csv(csv_path: str = DEFAULT_DATASET_CSV):
    """
    Loads feature vectors and scam labels directly from a CSV file.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"Dataset CSV not found at: {csv_path}")

    X = []
    y = []
    urls = []

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            url = row.get("url", f"url_{idx}")
            urls.append(url)

            # Extract 26 numerical features from row columns if available
            has_all_feats = all(col in row for col in FEATURE_COLUMNS)
            if has_all_feats:
                vector = [float(row[col]) for col in FEATURE_COLUMNS]
            else:
                # If row only contains URL, calculate features on the fly
                feats = extract_features(url)
                vector = features_to_vector(feats)

            # Determine label
            if "label" in row and row["label"].strip() != "":
                label = int(float(row["label"]))
            elif "is_scam" in row and row["is_scam"].strip() != "":
                val = row["is_scam"].strip().lower()
                label = 1 if val in ("1", "true", "scam", "threat", "phish") else 0
            else:
                label = 0

            X.append(vector)
            y.append(label)

    # If dataset contains only safe samples, augment with threat suite for robust binary classification
    if len(y) > 0 and y.count(1) == 0:
        backup_csv = os.path.join(os.path.dirname(csv_path), "veridex_dataset_old_backup.csv")
        threat_loaded = 0
        if os.path.exists(backup_csv):
            with open(backup_csv, mode="r", encoding="utf-8") as bf:
                b_reader = csv.DictReader(bf)
                for b_idx, b_row in enumerate(b_reader):
                    b_label = int(float(b_row.get("label", 0)))
                    if b_label == 1:
                        b_url = b_row.get("url", f"threat_{b_idx}")
                        b_vec = [float(b_row[col]) for col in FEATURE_COLUMNS] if all(col in b_row for col in FEATURE_COLUMNS) else features_to_vector(extract_features(b_url))
                        X.append(b_vec)
                        y.append(1)
                        urls.append(b_url)
                        threat_loaded += 1
        if threat_loaded == 0:
            fallback_threats = [
                "https://scam.com", "http://phishing-portal.org/login", "http://crypto-drainer-app.com/connect",
                "http://account-verification-portal-urgent.com/login.php", "http://webmail-security-update-center.xyz/auth/verify",
                "http://user-session-renew-expired-alert.top/signin", "http://secure-client-identity-verification.work/action",
                "http://update-billing-information-prompt.click/confirm", "http://password-reset-validation-token.club/index.html",
                "http://urgent-account-suspension-reversal.live/step1", "http://customer-support-ticket-verification.rest/resolve",
                "http://system-speedup-utility.top/download/setup.exe", "http://free-driver-update-installer.work/patch.exe",
                "http://cracked-software-pack.cam/installer.scr", "http://windows-essential-security-patch.xyz/update.bat",
                "http://free-game-activation-tool.monster/setup.msi", "http://clean-pc-registry-tool.club/optimizer.exe",
                "http://download-antivirus-update-free.icu/scanner.apk", "http://claim-free-rewards-survey2026.xyz/win?click=99",
                "http://instant-crypto-airdrop-usdt.buzz/claim?wallet=connect", "http://congratulations-lucky-shopper-winner.top/gift",
                "http://exclusive-winner-gift-claim.club/survey.php", "http://wallet-seed-phrase-validation.ru/restore",
                "http://double-your-bitcoin-investment.cam/deposit", "http://free-iphone-giveaway-today.rest/claim-now",
                "http://secure-client-auth.ngrok.io/login", "http://banking-update-notification.duckdns.org/verify",
                "http://account-recovery-system.000webhostapp.com/auth", "http://urgent-verification-form.glitch.me/form",
                "http://customer-identity-proofing.pages.dev/signin", "http://security-update-session.firebaseapp.com/confirm",
                "http://x9f8k210pqw-dga.top/api/gate.php", "http://qzwxrty1098.cc/bot/beacon?id=4921",
                "http://a7b8c9d0e1f2.buzz/landing/redirect", "http://m7k9p2x4w1.monster/tracker/ping",
                "http://z8x7c6v5b4.xyz/payload/script.js", "http://192.168.1.105/bankofamerica/secure-auth.html",
                "http://104.244.42.1:8080/portal/login.php", "http://203.0.113.195:8443/secure/client.html",
                "http://45.33.32.156:1337/admin/auth", "http://paypa1-security-verification.com/login",
                "http://chase-bank-customer-support-update.top/account/verify", "http://appleid-verify-locked-account.support.xyz/auth",
                "http://binance-airdrop-free-tokens.buzz/claim?wallet=crypto", "http://paypal.com.account-verification-service.xyz/signin",
                "http://xn--pypal-4ve.com/account/security-restore", "http://xn--appl-wqa.com/appleid/verify"
            ]
            for t_url in fallback_threats:
                t_vec = features_to_vector(extract_features(t_url))
                X.append(t_vec)
                y.append(1)
                urls.append(t_url)

    return np.array(X, dtype=np.float32), np.array(y, dtype=np.int64), urls

def train_and_export_model(csv_path: Optional[str] = None, output_dir: str = "models") -> Dict[str, Any]:
    """
    Loads data from the CSV file, fits the Random Forest model, calculates
    performance metrics, and exports the model to ONNX runtime format.
    """
    if csv_path is None:
        csv_path = DEFAULT_DATASET_CSV

    os.makedirs(output_dir, exist_ok=True)
    print(f"[CSV TRAINER] Loading dataset from CSV: {csv_path}...")

    X, y, urls = load_data_from_csv(csv_path)
    print(f"[CSV TRAINER] Loaded {len(X)} rows from CSV ({sum(y == 0)} Safe, {sum(y == 1)} Scam).")

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    print(f"[CSV TRAINER] Training samples: {len(X_train)}, Testing samples: {len(X_test)}")

    rf = RandomForestClassifier(
        n_estimators=120,
        max_depth=12,
        random_state=42,
        class_weight="balanced"
    )
    rf.fit(X_train, y_train)

    y_pred = rf.predict(X_test)
    y_proba = rf.predict_proba(X_test)[:, 1]

    acc = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred)
    rec = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    roc_auc = roc_auc_score(y_test, y_proba)

    metrics = {
        "accuracy": round(float(acc) * 100, 2),
        "precision": round(float(prec) * 100, 2),
        "recall": round(float(rec) * 100, 2),
        "f1_score": round(float(f1) * 100, 2),
        "roc_auc": round(float(roc_auc) * 100, 2),
        "total_training_samples": len(X),
        "features_count": len(FEATURE_COLUMNS),
        "source_dataset_csv": os.path.basename(csv_path),
        "model_architecture": "RandomForest-120 (Trained from CSV Dataset)",
        "scope": "Universal Web Verification (CSV Dataset Driven)"
    }

    print("\n[CSV TRAINER] Evaluation Results:")
    for k, v in metrics.items():
        print(f"  • {k}: {v}")

    # Save schema & metrics
    with open(os.path.join(output_dir, "model_metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    with open(os.path.join(output_dir, "feature_names.json"), "w") as f:
        json.dump(FEATURE_COLUMNS, f, indent=2)

    # Save joblib fallback
    joblib_path = os.path.join(output_dir, "veridex_model.joblib")
    joblib.dump(rf, joblib_path)

    # Export to ONNX
    print("[CSV TRAINER] Exporting model to ONNX runtime format...")
    initial_type = [("float_input", FloatTensorType([None, len(FEATURE_COLUMNS)]))]
    onnx_model = convert_sklearn(
        rf,
        initial_types=initial_type,
        target_opset=12,
        options={type(rf): {"zipmap": False}}
    )

    onnx_path = os.path.join(output_dir, "veridex_model.onnx")
    with open(onnx_path, "wb") as f:
        f.write(onnx_model.SerializeToString())

    print(f"[CSV TRAINER] ONNX export complete: {onnx_path} ({os.path.getsize(onnx_path) / 1024:.2f} KB)")
    return metrics

if __name__ == "__main__":
    train_and_export_model()
