"""
VeriDex AI - Universal On-Device ONNX Runtime Inference & Explainability Engine
Executes ultra-low latency (< 5ms) on-device machine learning predictions,
classifying ANY arbitrary URL (blogs, educational sites, forums, news, e-commerce,
file downloads, generic scams, or brand impersonations) with Explainable AI.
"""

import os
import time
import json
import numpy as np
import onnxruntime as ort
import joblib

from .feature_extractor import (
    extract_features,
    features_to_vector,
    classify_url_category,
    FEATURE_COLUMNS
)
from .typosquat_detector import analyze_typosquatting
from .brand_resolver import resolve_legitimate_website

MODELS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "models")
ONNX_MODEL_PATH = os.path.join(MODELS_DIR, "veridex_model.onnx")
JOBLIB_MODEL_PATH = os.path.join(MODELS_DIR, "veridex_model.joblib")

class OnDeviceMLEngine:
    """
    Autonomous On-Device Machine Learning Engine for Universal URL Verification.
    Executes entirely offline using ONNX Runtime with CPU acceleration.
    """

    def __init__(self):
        self.session = None
        self.sklearn_model = None
        self.model_type = "UNKNOWN"
        self._load_model()

    def _load_model(self):
        """Loads ONNX runtime session or falls back to scikit-learn model."""
        if os.path.exists(ONNX_MODEL_PATH):
            try:
                opts = ort.SessionOptions()
                opts.intra_op_num_threads = 2
                opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
                self.session = ort.InferenceSession(ONNX_MODEL_PATH, opts, providers=["CPUExecutionProvider"])
                self.input_name = self.session.get_inputs()[0].name
                self.model_type = "ONNX Runtime (Universal On-Device Engine)"
                print(f"[ML_ENGINE] Successfully initialized {self.model_type}")
                return
            except Exception as e:
                print(f"[ML_ENGINE] ONNX load warning: {e}. Falling back to Joblib.")

        if os.path.exists(JOBLIB_MODEL_PATH):
            try:
                self.sklearn_model = joblib.load(JOBLIB_MODEL_PATH)
                self.model_type = "Scikit-Learn Random Forest (Local Engine)"
                print(f"[ML_ENGINE] Loaded fallback model: {self.model_type}")
            except Exception as e:
                print(f"[ML_ENGINE] Error loading joblib model: {e}")

    def inspect_url(self, url: str) -> dict:
        """
        Performs multi-layered universal on-device inspection for ANY URL:
        1. Brand Typosquatting / Homoglyph heuristics
        2. Universal 26-dimensional feature extraction
        3. Local ONNX ML prediction
        4. Domain & Intent Categorization
        5. Explainable AI (XAI) risk & trust factor synthesis
        """
        start_time = time.perf_counter()
        raw_url = url.strip()

        # 1. Typosquat analysis
        typosquat = analyze_typosquatting(raw_url)

        # 2. Extract 26 features
        features = extract_features(raw_url)
        vector = features_to_vector(features)
        input_data = np.array([vector], dtype=np.float32)

        # 3. Model Inference
        ml_probability = 0.0
        ml_prediction = 0

        if self.session is not None:
            try:
                outputs = self.session.run(None, {self.input_name: input_data})
                ml_prediction = int(outputs[0][0])
                if len(outputs) > 1 and len(outputs[1]) > 0:
                    probs = outputs[1][0]
                    if isinstance(probs, dict):
                        ml_probability = float(probs.get(1, 0.0))
                    elif hasattr(probs, "__len__"):
                        ml_probability = float(probs[1]) if len(probs) > 1 else float(probs[0])
                else:
                    ml_probability = 1.0 if ml_prediction == 1 else 0.0
            except Exception as e:
                print(f"[ML_ENGINE] ONNX inference exception: {e}")
                if self.sklearn_model:
                    ml_prediction = int(self.sklearn_model.predict(input_data)[0])
                    ml_probability = float(self.sklearn_model.predict_proba(input_data)[0][1])
        elif self.sklearn_model is not None:
            ml_prediction = int(self.sklearn_model.predict(input_data)[0])
            ml_probability = float(self.sklearn_model.predict_proba(input_data)[0][1])

        # Latency
        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 4. Universal Intent Categorization
        url_classification = classify_url_category(raw_url, features, typosquat)

        # 5. Multi-layer Risk Scoring Synthesis
        combined_risk_score = ml_probability * 100.0

        # Heuristic overrides for high-confidence universal threat vectors
        if url_classification.get("risk_nature") == "CONFIRMED_THREAT":
            combined_risk_score = max(combined_risk_score, 99.0)
        elif url_classification.get("risk_nature") == "HIGH_RISK":
            combined_risk_score = max(combined_risk_score, 92.0)

        if typosquat["is_typosquat"]:
            if typosquat["severity"] == "CRITICAL":
                combined_risk_score = max(combined_risk_score, 98.0)
            elif typosquat["severity"] == "HIGH":
                combined_risk_score = max(combined_risk_score, 90.0)
            elif typosquat["severity"] == "MEDIUM":
                combined_risk_score = max(combined_risk_score, 72.0)

        # Explicit scam keyword in domain or path (e.g. scam.com, phish-login)
        if features["scam_keyword_count"] >= 1:
            combined_risk_score = max(combined_risk_score, 92.0)

        # Executable binary delivery check
        if features["has_executable_payload"] == 1:
            combined_risk_score = max(combined_risk_score, 88.0)

        # Free tunnel / DynDNS paired with authentication keywords
        if features["is_free_hosting_or_tunnel"] == 1 and features["auth_keyword_count"] > 0:
            combined_risk_score = max(combined_risk_score, 92.0)

        # Generic credential harvesting on suspicious TLD
        if features["auth_keyword_count"] >= 2 and features["is_suspicious_tld"] == 1:
            combined_risk_score = max(combined_risk_score, 89.0)

        # Direct IP address
        if features["has_ip_address"] == 1:
            combined_risk_score = max(combined_risk_score, 85.0)

        # Trusted institutions (e.g. .edu, .gov with HTTPS) get verified safe boost
        if url_classification.get("type_badge") == "TRUSTED_INSTITUTION" and not typosquat["is_typosquat"] and features["has_executable_payload"] == 0 and url_classification.get("risk_nature") not in ("CONFIRMED_THREAT", "HIGH_RISK", "MALWARE_RISK"):
            combined_risk_score = min(combined_risk_score, 8.0)

        # 6. Explainable AI (XAI) Synthesis
        risk_factors = []
        trust_signals = []

        # Threat indicators
        if url_classification.get("risk_nature") == "CONFIRMED_THREAT":
            risk_factors.append(f"Blatant Threat Signature: {url_classification.get('description')}")
        if typosquat["is_typosquat"]:
            risk_factors.append(f"Brand Impersonation: {typosquat['reason']}")
        if features["has_executable_payload"] == 1:
            risk_factors.append("Payload Delivery: URL points directly to an executable binary (.exe, .bat, .apk, .msi) which can execute arbitrary code.")
        if features["is_free_hosting_or_tunnel"] == 1 and features["auth_keyword_count"] > 0:
            risk_factors.append("Tunnel Phishing: Authentication portal hosted on ephemeral tunnel / free dynamic DNS infrastructure.")
        if features["is_punycode"] == 1:
            risk_factors.append("Punycode / IDN Homograph: Uses deceptive look-alike international glyphs.")
        if features["has_ip_address"] == 1:
            risk_factors.append("Bare IP Host: Website is hosted on a bare numeric IP without registered domain DNS.")
        if features["is_suspicious_tld"] == 1:
            risk_factors.append("High-Abuse TLD: Domain uses an extension frequently abused for automated spam campaigns.")
        if features["is_url_shortener"] == 1:
            risk_factors.append("URL Shortener Mask: Destination is obscured behind a URL redirection service.")
        if features["has_at_symbol"] == 1:
            risk_factors.append("URL Obfuscation: '@' character detected, which can mask the true destination.")
        if features["has_double_slash"] == 1:
            risk_factors.append("Path Redirection: Double slashes '//' inside path indicate redirect manipulation.")
        if features["auth_keyword_count"] >= 2 and features["is_suspicious_tld"] == 1:
            risk_factors.append(f"Generic Credential Trap: Contains {features['auth_keyword_count']} authentication keywords on disposable domain.")
        if features["scam_keyword_count"] >= 1:
            risk_factors.append(f"Malicious / Scam Signature: URL contains scam/fraud identifier keyword(s).")
        if features["entropy_domain"] > 3.8:
            risk_factors.append(f"High Domain Entropy ({features['entropy_domain']}): Indicates algorithmic randomness or DGA generation.")
        if features["has_non_standard_port"] == 1:
            risk_factors.append("Non-Standard Port: Connects over an unusual port rather than standard web ports 80/443.")
        if features["is_https"] == 0:
            risk_factors.append("Unencrypted Connection: Missing HTTPS protocol transport encryption.")

        # Trust signals for safe websites
        if url_classification.get("type_badge") == "TRUSTED_INSTITUTION":
            trust_signals.append("High-Trust Domain: Verified institutional extension (.edu / .gov / .org).")
        if features["is_https"] == 1:
            trust_signals.append("Transport Security: Encrypted via modern HTTPS protocol.")
        if features["entropy_domain"] <= 3.4 and features["entropy_domain"] >= 2.0:
            trust_signals.append("Natural Vocabulary: Balanced lexical entropy matching human-readable language.")
        if features["auth_keyword_count"] == 0 and features["scam_keyword_count"] == 0:
            trust_signals.append("Clean Intent: No deceptive urgency, fake prizes, or credential harvesting keywords.")
        if features["has_executable_payload"] == 0 and features["is_url_shortener"] == 0:
            trust_signals.append("Transparent Destination: Direct link without executable attachments or URL masking.")

        # 7. Check for authentic brand suggestion (legal original website)
        spoofed_brand = typosquat.get("spoofed_brand")
        legitimate_suggestion = resolve_legitimate_website(raw_url, spoofed_brand=spoofed_brand)
        if legitimate_suggestion:
            risk_factors.insert(
                0,
                f"Replica Target: Impersonates {legitimate_suggestion['spoofed_brand']}. Authentic verified portal is {legitimate_suggestion['official_url']}."
            )

        # Verdict assignment
        if combined_risk_score >= 70:
            verdict = "PHISHING / THREAT DETECTED"
            threat_color = "#ef4444"  # Red
        elif combined_risk_score >= 40:
            verdict = "SUSPICIOUS / CAUTION"
            threat_color = "#f59e0b"  # Amber
        else:
            verdict = "SAFE & VERIFIED"
            threat_color = "#22c55e"  # Green
            if not risk_factors:
                risk_factors = trust_signals if trust_signals else ["Clean lexical structure, no threat signatures or manipulation patterns found."]

        return {
            "url": raw_url,
            "verdict": verdict,
            "threat_color": threat_color,
            "risk_score": round(combined_risk_score, 1),
            "confidence": round(max(ml_probability, 1.0 - ml_probability) * 100, 1),
            "is_threat": combined_risk_score >= 50,
            "latency_ms": latency_ms,
            "engine": self.model_type,
            "classification": url_classification,
            "risk_factors": risk_factors,
            "trust_signals": trust_signals,
            "typosquat_details": typosquat,
            "legitimate_website_suggestion": legitimate_suggestion,
            "features": features
        }

# Global singleton engine instance
engine = OnDeviceMLEngine()
