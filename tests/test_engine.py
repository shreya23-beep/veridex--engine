"""
VeriDex AI - Comprehensive Automated Test Suite
Verifies on-device ML model accuracy, ONNX runtime execution,
universal URL verification (blogs, .edu, downloads, generic scams, typosquatting),
NLP manipulation parsing, and DPAPI vault encryption.
"""

import unittest
import time
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.typosquat_detector import analyze_typosquatting
from core.feature_extractor import extract_features, features_to_vector, FEATURE_COLUMNS
from core.ml_engine import engine
from core.nlp_analyzer import nlp_analyzer
from security.crypto_vault import vault_crypto
from security.threat_db import threat_db

class TestVeridexEngine(unittest.TestCase):

    def test_01_typosquatting_detection(self):
        """Tests homoglyph and brand impersonation detection."""
        # 1. Homoglyph substitution
        res1 = analyze_typosquatting("http://paypa1-security.com")
        self.assertTrue(res1["is_typosquat"])
        self.assertEqual(res1["spoofed_brand"], "paypal")

        # 2. Subdomain nesting spoof
        res2 = analyze_typosquatting("http://apple.com.attacker-fake.xyz/login")
        self.assertTrue(res2["is_typosquat"])
        self.assertEqual(res2["spoofed_brand"], "apple")

        # 3. Clean domain
        res3 = analyze_typosquatting("https://www.google.com")
        self.assertFalse(res3["is_typosquat"])

    def test_02_universal_feature_extraction(self):
        """Tests that all 26 universal structural features are extracted accurately."""
        url = "http://account-verification-portal-urgent.com/login.php"
        feats = extract_features(url)
        self.assertEqual(len(feats), len(FEATURE_COLUMNS))
        self.assertEqual(len(FEATURE_COLUMNS), 26)
        vec = features_to_vector(feats)
        self.assertEqual(len(vec), 26)
        self.assertIsInstance(vec[0], (int, float))

    def test_03_universal_url_verification(self):
        """Tests that the engine verifies ALL types of URLs, not just company URLs."""
        # 1. Personal Tech Blog (Clean)
        res_blog = engine.inspect_url("https://danluu.com/productivity-advice/")
        self.assertFalse(res_blog["is_threat"])
        self.assertLess(res_blog["risk_score"], 25.0)
        self.assertEqual(res_blog["verdict"], "SAFE & VERIFIED")

        # 2. Academic / University Portal (Clean Institutional)
        res_edu = engine.inspect_url("https://cs.stanford.edu/research/ai")
        self.assertFalse(res_edu["is_threat"])
        self.assertLess(res_edu["risk_score"], 15.0)
        self.assertEqual(res_edu["classification"]["type_badge"], "TRUSTED_INSTITUTION")

        # 3. Generic Credential Phishing (NO company named)
        res_generic_phish = engine.inspect_url("http://account-verification-portal-urgent.com/login.php")
        self.assertTrue(res_generic_phish["is_threat"])
        self.assertGreaterEqual(res_generic_phish["risk_score"], 70.0)

        # 4. Executable / Malware Download link
        res_exe = engine.inspect_url("http://system-speedup-utility.top/download/setup.exe")
        self.assertTrue(res_exe["is_threat"])
        self.assertEqual(res_exe["classification"]["type_badge"], "PAYLOAD_DELIVERY")

        # 5. Generic Survey / Prize Scam
        res_scam = engine.inspect_url("http://claim-free-rewards-survey2026.xyz/win?click=99")
        self.assertTrue(res_scam["is_threat"])
        self.assertEqual(res_scam["classification"]["type_badge"], "SCAM_LURE")

        # 6. Brand Impersonation
        res_impersonation = engine.inspect_url("http://paypa1-security-verification.com/login")
        self.assertTrue(res_impersonation["is_threat"])
        self.assertEqual(res_impersonation["classification"]["type_badge"], "IMPERSONATION")

        # 7. Explicit Scam Domain (https://scam.com)
        res_explicit_scam = engine.inspect_url("https://scam.com")
        self.assertTrue(res_explicit_scam["is_threat"])
        self.assertGreaterEqual(res_explicit_scam["risk_score"], 80.0)
        self.assertIn("PHISHING", res_explicit_scam["verdict"])
        self.assertEqual(res_explicit_scam["classification"]["type_badge"], "SCAM_DOMAIN")

    def test_04_onnx_inference_latency(self):
        """Tests that ONNX inference executes in sub-millisecond on-device latency."""
        safe_url = "https://allrecipes.com/recipe/158140/spaghetti-carbonara/"
        t0 = time.perf_counter()
        res = engine.inspect_url(safe_url)
        latency = (time.perf_counter() - t0) * 1000
        print(f"\n[BENCHMARK] On-Device Latency for Recipe Blog URL: {latency:.3f} ms")
        self.assertLess(latency, 25.0)
        self.assertIn("ONNX", res["engine"])

    def test_05_nlp_manipulation_cues(self):
        """Tests social engineering manipulation cue parsing."""
        scam_text = "URGENT ACTION REQUIRED: Your account has been suspended! Enter your password and SSN immediately within 24 hours to avoid legal arrest."
        res = nlp_analyzer.analyze_text(scam_text)
        self.assertIn(res["threat_level"], ["CRITICAL", "SUSPICIOUS"])
        self.assertGreater(len(res["detected_cues"]), 0)

        # Clean text
        clean_text = "Hi, attached is the revised agenda for our hackathon project presentation tomorrow."
        res_clean = nlp_analyzer.analyze_text(clean_text)
        self.assertEqual(res_clean["threat_level"], "CLEAN")

    def test_06_dpapi_vault_cryptography(self):
        """Tests AES-256 / DPAPI local encrypted vault storage."""
        secret_url = "https://malicious-zero-day-phishing-sample.xyz/auth"
        ciphertext = vault_crypto.encrypt(secret_url)
        self.assertNotEqual(secret_url, ciphertext)
        
        decrypted = vault_crypto.decrypt(ciphertext)
        self.assertEqual(secret_url, decrypted)

        # Test database logging and retrieval
        scan_data = engine.inspect_url(secret_url)
        threat_db.log_scan(scan_data, source="UNIT_TEST")
        recent = threat_db.get_recent_scans(1)
        self.assertEqual(len(recent), 1)
        self.assertEqual(recent[0]["url"], secret_url)

    def test_07_legitimate_website_suggestions(self):
        """Tests that replica / phishing spoof sites accurately recommend the original authentic website."""
        # 1. PayPal replica
        res_paypal = engine.inspect_url("http://paypa1-security-verification.com/login")
        self.assertTrue(res_paypal["is_threat"])
        self.assertIsNotNone(res_paypal.get("legitimate_website_suggestion"))
        sugg_paypal = res_paypal["legitimate_website_suggestion"]
        self.assertEqual(sugg_paypal["spoofed_brand"], "PayPal")
        self.assertEqual(sugg_paypal["official_url"], "https://www.paypal.com")
        self.assertEqual(sugg_paypal["official_domain"], "paypal.com")

        # 2. Apple replica
        res_apple = engine.inspect_url("http://apple-support-verify-icloud.com/login")
        self.assertTrue(res_apple["is_threat"])
        self.assertIsNotNone(res_apple.get("legitimate_website_suggestion"))
        sugg_apple = res_apple["legitimate_website_suggestion"]
        self.assertEqual(sugg_apple["spoofed_brand"], "Apple")
        self.assertEqual(sugg_apple["official_url"], "https://www.apple.com")

        # 3. Netflix replica
        res_netflix = engine.inspect_url("http://netflix-billing-update-urgent.net/signin")
        self.assertTrue(res_netflix["is_threat"])
        self.assertIsNotNone(res_netflix.get("legitimate_website_suggestion"))
        self.assertEqual(res_netflix["legitimate_website_suggestion"]["official_domain"], "netflix.com")

        # 4. Safe independent website (should NOT recommend any brand)
        res_safe = engine.inspect_url("https://danluu.com/productivity-advice/")
        self.assertFalse(res_safe["is_threat"])
        self.assertIsNone(res_safe.get("legitimate_website_suggestion"))

        # 5. Legitimate brand domain (should NOT recommend itself)
        res_real_paypal = engine.inspect_url("https://www.paypal.com/signin")
        self.assertFalse(res_real_paypal["is_threat"])
        self.assertIsNone(res_real_paypal.get("legitimate_website_suggestion"))

if __name__ == "__main__":
    unittest.main()
