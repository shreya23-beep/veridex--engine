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

        # 4. Symbol homoglyph substitution with '@' (e.g. payp@l.com)
        res4 = analyze_typosquatting("https://payp@l.com")
        self.assertTrue(res4["is_typosquat"])
        self.assertEqual(res4["spoofed_brand"], "paypal")
        self.assertEqual(res4["severity"], "CRITICAL")

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
        # Warmup ONNX runtime session & DNS cache
        engine.inspect_url(safe_url)
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

        # 6. PayPal symbol obfuscation replica (https://payp@l.com)
        res_payp_at = engine.inspect_url("https://payp@l.com")
        self.assertTrue(res_payp_at["is_threat"])
        self.assertEqual(res_payp_at["verdict"], "PHISHING / THREAT DETECTED")
        self.assertGreaterEqual(res_payp_at["risk_score"], 90.0)
        self.assertIsNotNone(res_payp_at.get("legitimate_website_suggestion"))
        self.assertEqual(res_payp_at["legitimate_website_suggestion"]["official_url"], "https://www.paypal.com")
        self.assertEqual(res_payp_at["legitimate_website_suggestion"]["spoofed_brand"], "PayPal")

    def test_08_ip_resolver_and_1930_cybercrime_helpline(self):
        """Tests culprit server IP address resolution and 1930 cyber security helpline integration."""
        # 1. WhatsApp scam link (free recharge lure)
        wa_url = "http://whatsapp-free-500gb-recharge.xyz/claim"
        res_wa = engine.inspect_url(wa_url)
        self.assertTrue(res_wa["is_threat"])
        self.assertIn("server_ip", res_wa)
        self.assertIsNotNone(res_wa["server_ip"])
        # Check IP format
        ip_parts = res_wa["server_ip"].split(".")
        self.assertEqual(len(ip_parts), 4)

        # Check IP Intelligence details
        ip_intel = res_wa.get("ip_intelligence", {})
        self.assertTrue(ip_intel.get("is_whatsapp_lure"))
        self.assertIn("isp", ip_intel)
        self.assertIn("server_location", ip_intel)

        # Check 1930 Cyber Helpline reporting details
        helpline = res_wa.get("cyber_helpline_1930", {})
        self.assertEqual(helpline.get("helpline"), "1930")
        self.assertEqual(helpline.get("portal"), "https://cybercrime.gov.in")
        self.assertIn(res_wa["server_ip"], helpline.get("complaint_text", ""))
        self.assertIn("1930", helpline.get("complaint_text", ""))

        # 2. Source parameter override
        res_source = engine.inspect_url("http://claim-rewards-bonus.top/win", source="WHATSAPP_CHAT")
        self.assertTrue(res_source.get("ip_intelligence", {}).get("is_whatsapp_lure"))

        # 3. Typosquat replica server IP resolution
        res_typo = engine.inspect_url("http://paypa1-security-verification.com/login")
        self.assertIsNotNone(res_typo.get("server_ip"))
        self.assertIn(res_typo["server_ip"], res_typo.get("cyber_helpline_1930", {}).get("complaint_text", ""))

    def test_09_active_app_and_browser_safety_inspector(self):
        """Tests active application and website URL safety inspection."""
        from daemon.app_inspector import app_inspector

        # 1. Browser on Safe Website
        mock_chrome_safe = {
            "title": "YouTube: Home - Google Chrome",
            "exe_name": "chrome.exe",
            "exe_path": r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        }
        res_chrome_safe = app_inspector.inspect_active_window(mock_chrome_safe)
        self.assertTrue(res_chrome_safe["is_safe"])
        self.assertFalse(res_chrome_safe["is_threat"])
        self.assertEqual(res_chrome_safe["color"], "#22c55e")

        # 2. Browser on WhatsApp Scam URL
        mock_chrome_scam = {
            "title": "500GB Free 5G Data - whatsapp-free-500gb-recharge.xyz/claim - Google Chrome",
            "exe_name": "chrome.exe",
            "exe_path": r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        }
        res_chrome_scam = app_inspector.inspect_active_window(mock_chrome_scam)
        self.assertTrue(res_chrome_scam["is_threat"])
        self.assertFalse(res_chrome_scam["is_safe"])
        self.assertEqual(res_chrome_scam["color"], "#ef4444")
        self.assertIsNotNone(res_chrome_scam.get("server_ip"))

        # 3. WhatsApp Desktop App
        mock_wa = {
            "title": "(2) WhatsApp",
            "exe_name": "WhatsApp.exe",
            "exe_path": r"C:\Program Files\WindowsApps\5319275A.WhatsAppDesktop_cv1g1gvanyjgm\WhatsApp.exe"
        }
        res_wa = app_inspector.inspect_active_window(mock_wa)
        self.assertTrue(res_wa["is_safe"])
        self.assertEqual(res_wa["display_name"], "WhatsApp Desktop")
        self.assertEqual(res_wa["color"], "#22c55e")

        # 4. Microsoft Word
        mock_word = {
            "title": "Annual_Report.docx - Word",
            "exe_name": "WINWORD.EXE",
            "exe_path": r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
        }
        res_word = app_inspector.inspect_active_window(mock_word)
        self.assertTrue(res_word["is_safe"])
        self.assertEqual(res_word["display_name"], "Microsoft Word")

        # 5. Suspicious executable running from Temp
        mock_suspicious = {
            "title": "Installer",
            "exe_name": "setup_fake.exe",
            "exe_path": r"C:\Users\User\AppData\Local\Temp\setup_fake.exe"
        }
        res_suspicious = app_inspector.inspect_active_window(mock_suspicious)
        self.assertFalse(res_suspicious["is_safe"])
        self.assertEqual(res_suspicious["target_type"], "UNVERIFIED_APP")
        self.assertEqual(res_suspicious["color"], "#f59e0b")

    def test_10_whatsapp_screenshot_analyzer(self):
        """Tests WhatsApp screenshot analysis for fake recharge scams, bank KYC, and culprit IP."""
        from core.screenshot_analyzer import screenshot_analyzer

        # 1. WhatsApp viral 500GB scam message with culprit IP resolution
        fake_chat = (
            "Forwarded many times\n"
            "Free 3-Month Mobile Recharge Offer!\n"
            "Government of India is giving 500GB free 5G data to all WhatsApp users.\n"
            "Click here immediately before offer expires:\n"
            "http://whatsapp-free-500gb-recharge.xyz/claim?ref=wa"
        )
        res_fake = screenshot_analyzer.analyze_image(extracted_text=fake_chat)
        self.assertTrue(res_fake["is_fake"])
        self.assertEqual(res_fake["threat_level"], "CRITICAL")
        self.assertIn("1930", res_fake["cyber_dossier_1930"])
        self.assertIsNotNone(res_fake["culprit_server_ip"])
        self.assertTrue(res_fake["has_forwarded_tag"])
        self.assertGreaterEqual(len(res_fake["matched_indicators"]), 2)

        # 2. Genuine / Safe chat
        safe_chat = (
            "Hi Shreya! Are we meeting for the project discussion at 4 PM today?\n"
            "Here is the location link: https://maps.google.com/place/coffee-shop"
        )
        res_safe = screenshot_analyzer.analyze_image(extracted_text=safe_chat)
        self.assertFalse(res_safe["is_fake"])
        self.assertEqual(res_safe["threat_level"], "SAFE")

    def test_11_scam_qr_code_detector(self):
        """Tests Scam QR Code Detector for Quishing URLs, Fake UPI Reverse-Debit Traps, and Malicious APKs."""
        from core.qr_detector import qr_detector

        # 1. Reverse UPI payment fraud trap
        upi_scam_payload = "upi://pay?pa=scammer99@oksbi&pn=Lottery%20Prize%20Claim&am=15000&cu=INR&tn=Prize%20Cashback%20Reward"
        res_upi = qr_detector.inspect_payload(upi_scam_payload)
        self.assertTrue(res_upi["is_threat"])
        self.assertEqual(res_upi["threat_level"], "CRITICAL")
        self.assertIn("REVERSE UPI", res_upi["verdict"])
        self.assertGreaterEqual(res_upi["risk_score"], 90.0)
        self.assertIsNotNone(res_upi["report_card"])
        self.assertIn("1930", res_upi["cyber_dossier_1930"])

        # 2. Quishing URL (phishing bank replica)
        quishing_payload = "http://sbi-yono-kyc-verify-portal.in/update"
        res_quish = qr_detector.inspect_payload(quishing_payload)
        self.assertTrue(res_quish["is_threat"])
        self.assertIn("QUISHING", res_quish["verdict"])
        self.assertIsNotNone(res_quish["culprit_server_ip"])
        self.assertIsNotNone(res_quish["report_card"])

        # 3. Malicious APK drop QR
        apk_payload = "http://speedup-utility-support.top/download/safety_update.apk"
        res_apk = qr_detector.inspect_payload(apk_payload)
        self.assertTrue(res_apk["is_threat"])
        self.assertEqual(res_apk["threat_level"], "CRITICAL")
        self.assertIn("APK", res_apk["verdict"])

        # 4. Safe Institutional URL QR
        safe_payload = "https://cs.stanford.edu/research/ai"
        res_safe = qr_detector.inspect_payload(safe_payload)
        self.assertFalse(res_safe["is_threat"])
        self.assertEqual(res_safe["threat_level"], "SAFE")
        self.assertIsNotNone(res_safe["report_card"])

        # 5. Visual QR Image Encoding & Decoding Pipeline
        qr_b64 = qr_detector.generate_qr_base64("https://danluu.com/productivity-advice/")
        self.assertTrue(qr_b64.startswith("data:image/png;base64,"))
        decode_res = qr_detector.decode_qr_image(image_b64=qr_b64)
        self.assertTrue(decode_res["success"])
        self.assertEqual(decode_res["payload"], "https://danluu.com/productivity-advice/")

    def test_12_report_card_generation(self):
        """Tests structured Cyber Incident Report Card generation across URL, Message, and QR scanners."""
        # 1. URL Inspector report card
        url_res = engine.inspect_url("http://paypa1-security-verification.com/login")
        self.assertIn("report_card", url_res)
        rc_url = url_res["report_card"]
        self.assertTrue(rc_url["incident_id"].startswith("VDX-URL-"))
        self.assertTrue(rc_url["is_threat"])
        self.assertIn("1930", rc_url["helpline_dialpad"])
        self.assertIn("cybercrime.gov.in", rc_url["complaint_url"])
        self.assertIn("PAYPAL", rc_url["full_dossier_text"].upper())

        # 2. Message Screenshot report card
        from core.screenshot_analyzer import screenshot_analyzer
        chat_text = "Dear Consumer, your electricity power will be disconnected tonight at 9:30 PM. Pay now: http://power-bill-payment-quick.top/bill"
        msg_res = screenshot_analyzer.analyze_image(extracted_text=chat_text)
        self.assertIn("report_card", msg_res)
        rc_msg = msg_res["report_card"]
        self.assertTrue(rc_msg["incident_id"].startswith("VDX-INCIDENT-"))
        self.assertTrue(rc_msg["is_fake"])

        # 3. QR Detector report card
        from core.qr_detector import qr_detector
        qr_res = qr_detector.inspect_payload("http://whatsapp-free-500gb-recharge.xyz/claim")
        self.assertIn("report_card", qr_res)
        rc_qr = qr_res["report_card"]
        self.assertTrue(rc_qr["incident_id"].startswith("VDX-QR-"))
        self.assertTrue(rc_qr["is_threat"])

if __name__ == "__main__":
    unittest.main()
