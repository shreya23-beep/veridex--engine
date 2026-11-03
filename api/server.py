"""
VeriDex AI - Local REST API Server & Dashboard Host
Provides zero-cloud local endpoints for on-device inference,
real-time clipboard monitoring, and the web cyber-defense dashboard.
"""

from __future__ import annotations
import os
import time
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from core.ml_engine import engine
from core.nlp_analyzer import nlp_analyzer
from core.screenshot_analyzer import screenshot_analyzer
from core.qr_detector import qr_detector
from security.threat_db import threat_db
from daemon.clipboard_watcher import interceptor

app = FastAPI(
    title="VeriDex AI - On-Device Scam Protection API",
    description="100% Private, Offline & Zero-Cloud Security Engine",
    version="2.0.0"
)

# Enable CORS for local client apps and extensions
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/static") or request.url.path == "/":
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Request Models
class URLScanRequest(BaseModel):
    url: str
    source: Optional[str] = "WEB_DASHBOARD"

class TextScanRequest(BaseModel):
    text: str
    source: Optional[str] = "NLP_INSPECTOR"

class WhitelistRequest(BaseModel):
    domain: str
    notes: Optional[str] = ""

class BlacklistRequest(BaseModel):
    pattern: str
    notes: Optional[str] = ""

class ScreenshotScanRequest(BaseModel):
    image_base64: Optional[str] = None
    text: Optional[str] = None
    filename: Optional[str] = "screenshot.png"

class QRScanRequest(BaseModel):
    image_base64: Optional[str] = None
    payload: Optional[str] = None
    filename: Optional[str] = "qr_code.png"

# API Endpoints
@app.get("/api/health")
def health():
    return {
        "status": "ONLINE",
        "mode": "OFFLINE_ZERO_CLOUD",
        "engine": engine.model_type,
        "privacy": "Windows DPAPI / AES-256 Encrypted Vault"
    }

@app.post("/api/scan/url")
def scan_url(req: URLScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    
    # 1. Check custom user whitelist first
    domain_part = req.url.split("/")[2] if "//" in req.url else req.url.split("/")[0]
    whitelist = threat_db.get_whitelist()
    if any(w in domain_part.lower() for w in whitelist):
        return {
            "url": req.url,
            "verdict": "WHITELISTED & SAFE",
            "threat_color": "#22c55e",
            "risk_score": 0.0,
            "confidence": 100.0,
            "is_threat": False,
            "latency_ms": 0.1,
            "engine": "User Whitelist Policy",
            "risk_factors": ["Domain explicitly whitelisted by user."]
        }

    # 2. Check custom user blacklist
    blacklist = threat_db.get_blacklist()
    if any(b in req.url.lower() for b in blacklist):
        res = {
            "url": req.url,
            "verdict": "BLACKLISTED THREAT",
            "threat_color": "#ef4444",
            "risk_score": 100.0,
            "confidence": 100.0,
            "is_threat": True,
            "latency_ms": 0.1,
            "engine": "User Blacklist Policy",
            "risk_factors": ["URL matched custom user blacklist pattern."]
        }
        threat_db.log_scan(res, source=req.source)
        return res

    # 3. On-Device Machine Learning & Typosquat Inspection
    result = engine.inspect_url(req.url, source=req.source)
    
    # Log to encrypted vault
    threat_db.log_scan(result, source=req.source)
    return result

@app.post("/api/scan/text")
def scan_text(req: TextScanRequest):
    import re
    from core.ip_resolver import resolve_ip_intelligence
    start = time.perf_counter()
    result = nlp_analyzer.analyze_text(req.text)
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    result["latency_ms"] = latency_ms

    # Extract any embedded URLs in message text (e.g. from WhatsApp / SMS)
    url_match = re.search(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", req.text)
    if url_match:
        embedded_url = url_match.group(0)
        url_scan = engine.inspect_url(
            embedded_url,
            source=req.source or "WHATSAPP_TEXT",
            context_text=req.text
        )
        is_threat = url_scan["is_threat"] or result.get("threat_level") in ("CRITICAL", "SUSPICIOUS")
        ip_intel = url_scan.get("ip_intelligence") or resolve_ip_intelligence(
            embedded_url,
            is_threat=is_threat,
            source=req.source or "WHATSAPP_TEXT",
            context_text=req.text
        )
        result["embedded_url"] = embedded_url
        result["server_ip"] = ip_intel["server_ip"]
        result["ip_intelligence"] = ip_intel
        result["cyber_helpline_1930"] = ip_intel["cyber_helpline_1930"]

        if url_scan["is_threat"]:
            result["threat_level"] = "CRITICAL"
            result["risk_score"] = max(result.get("risk_score", 0), url_scan["risk_score"])
            result["summary"] = (
                f"CRITICAL THREAT: Embedded link flagged as {url_scan['verdict']}. "
                f"Culprit server IP traced to {ip_intel['server_ip']} ({ip_intel['isp']}). "
                f"Reportable to Cyber Security Helpline 1930."
            )

    return result

@app.get("/api/vault/stats")
def vault_stats():
    return threat_db.get_vault_statistics()

@app.get("/api/vault/logs")
def vault_logs(limit: int = 50):
    return threat_db.get_recent_scans(limit=limit)

@app.post("/api/vault/whitelist")
def add_whitelist(req: WhitelistRequest):
    success = threat_db.add_whitelist(req.domain, req.notes)
    return {"success": success}

@app.post("/api/vault/blacklist")
def add_blacklist(req: BlacklistRequest):
    success = threat_db.add_blacklist(req.pattern, req.notes)
    return {"success": success}

@app.post("/api/vault/clear")
def clear_vault():
    threat_db.clear_vault()
    return {"success": True, "message": "Vault logs cleared."}

@app.post("/api/interceptor/toggle")
def toggle_interceptor(enable: bool):
    if enable:
        interceptor.start()
        return {"status": "ACTIVE", "running": True}
    else:
        interceptor.stop()
        return {"status": "STOPPED", "running": False}

@app.get("/api/interceptor/status")
def interceptor_status():
    return {"running": interceptor.running}

@app.get("/api/benchmark")
def run_benchmark():
    test_urls = [
        "https://www.google.com/search?q=veridex",
        "http://paypa1-security-verification.com/login",
        "https://github.com/torvalds/linux",
        "http://chase-bank-customer-support-update.top/account/verify",
        "https://apple.com/iphone-16-pro"
    ]
    latencies = []
    for _ in range(10):
        for u in test_urls:
            t0 = time.perf_counter()
            engine.inspect_url(u)
            latencies.append((time.perf_counter() - t0) * 1000)
    
    return {
        "iterations": len(latencies),
        "min_latency_ms": round(min(latencies), 3),
        "avg_latency_ms": round(sum(latencies) / len(latencies), 3),
        "max_latency_ms": round(max(latencies), 3),
        "p95_latency_ms": round(sorted(latencies)[int(len(latencies) * 0.95)], 3),
        "engine": engine.model_type
    }

# WhatsApp Chat Screenshot & Visual Fraud Analyzer Endpoints
@app.post("/api/analyze/screenshot")
async def analyze_screenshot_upload(
    file: Optional[UploadFile] = File(None),
    text: Optional[str] = Form(None)
):
    image_bytes = None
    filename = "whatsapp_screenshot.png"
    if file:
        image_bytes = await file.read()
        filename = file.filename or filename
    result = screenshot_analyzer.analyze_image(
        image_bytes=image_bytes,
        extracted_text=text,
        filename=filename
    )
    return result

@app.post("/api/analyze/screenshot/json")
def analyze_screenshot_json(req: ScreenshotScanRequest):
    import base64
    image_bytes = None
    if req.image_base64:
        raw_b64 = req.image_base64
        if "base64," in raw_b64:
            raw_b64 = raw_b64.split("base64,")[1]
        try:
            image_bytes = base64.b64decode(raw_b64)
        except Exception:
            pass
    result = screenshot_analyzer.analyze_image(
        image_bytes=image_bytes,
        extracted_text=req.text,
        filename=req.filename or "whatsapp_screenshot.png"
    )
    return result

# Scam QR Code & Quishing Detector Endpoints
@app.post("/api/scan/qr")
async def scan_qr_upload(
    file: Optional[UploadFile] = File(None),
    payload: Optional[str] = Form(None)
):
    image_bytes = None
    filename = "qr_code.png"
    if file:
        image_bytes = await file.read()
        filename = file.filename or filename
    result = qr_detector.analyze_qr(
        image_bytes=image_bytes,
        manual_payload=payload,
        filename=filename
    )
    return result

@app.post("/api/scan/qr/json")
def scan_qr_json(req: QRScanRequest):
    result = qr_detector.analyze_qr(
        image_b64=req.image_base64,
        manual_payload=req.payload,
        filename=req.filename or "qr_code.png"
    )
    return result

@app.get("/api/qr/presets")
def qr_presets():
    presets = [
        {
            "id": "quishing_kyc",
            "title": "Quishing Phishing Scam QR (SBI NetBanking Impersonation)",
            "type": "QUISHING_URL",
            "payload": "http://sbi-yono-kyc-verify-portal.in/update",
            "description": "Scam QR disguised as urgent bank KYC update. Redirects victim to credential harvester.",
            "image_b64": qr_detector.generate_qr_base64("http://sbi-yono-kyc-verify-portal.in/update")
        },
        {
            "id": "upi_debit_trap",
            "title": "Fake UPI 'Receive Money' Scam (Reverse Debit Trap)",
            "type": "UPI_PAYMENT",
            "payload": "upi://pay?pa=scammer99@oksbi&pn=Lottery%20Prize%20Claim&am=15000&cu=INR&tn=Prize%20Cashback%20Reward",
            "description": "Scammer claims scanning this sends you ₹15,000 lottery cash. Actually debits ₹15,000 from your account upon PIN entry.",
            "image_b64": qr_detector.generate_qr_base64("upi://pay?pa=scammer99@oksbi&pn=Lottery%20Prize%20Claim&am=15000&cu=INR&tn=Prize%20Cashback%20Reward")
        },
        {
            "id": "malicious_apk",
            "title": "Malicious Android APK Download QR",
            "type": "MALWARE_APK",
            "payload": "http://speedup-utility-support.top/download/safety_update.apk",
            "description": "Quishing link dropping an untrusted Android APK designed to intercept OTPs.",
            "image_b64": qr_detector.generate_qr_base64("http://speedup-utility-support.top/download/safety_update.apk")
        },
        {
            "id": "safe_portal",
            "title": "Genuine Safe Institutional Portal QR",
            "type": "SAFE_URL",
            "payload": "https://cs.stanford.edu/research/ai",
            "description": "Authentic academic research portal with zero malicious payload.",
            "image_b64": qr_detector.generate_qr_base64("https://cs.stanford.edu/research/ai")
        }
    ]
    return {"presets": presets}

# CSV Dataset & Batch Scam Scanning Endpoints
@app.post("/api/scan/csv")
def scan_csv_endpoint(custom_path: Optional[str] = None):
    from core.csv_detector import scan_csv_dataset, DEFAULT_CSV_PATH
    path = custom_path if (custom_path and os.path.exists(custom_path)) else DEFAULT_CSV_PATH
    summary = scan_csv_dataset(csv_path=path, save_output=True)
    return summary

@app.post("/api/model/retrain")
def retrain_model_endpoint(custom_path: Optional[str] = None):
    import importlib
    import core.typosquat_detector
    import core.brand_resolver
    import core.feature_extractor
    import core.ml_engine
    from core.trainer import train_and_export_model, DEFAULT_DATASET_CSV
    path = custom_path if (custom_path and os.path.exists(custom_path)) else DEFAULT_DATASET_CSV
    metrics = train_and_export_model(csv_path=path)
    # Hot-reload modules & ONNX model in engine
    importlib.reload(core.typosquat_detector)
    importlib.reload(core.brand_resolver)
    importlib.reload(core.feature_extractor)
    importlib.reload(core.ml_engine)
    engine._load_model()
    return {
        "status": "SUCCESS",
        "message": f"Random Forest & ONNX engine successfully retrained from {os.path.basename(path)}!",
        "metrics": metrics
    }

@app.get("/api/model/reload")
@app.post("/api/model/reload")
def reload_engine_endpoint():
    import importlib
    import core.typosquat_detector
    import core.brand_resolver
    import core.feature_extractor
    import core.ml_engine
    importlib.reload(core.typosquat_detector)
    importlib.reload(core.brand_resolver)
    importlib.reload(core.feature_extractor)
    importlib.reload(core.ml_engine)
    engine._load_model()
    return {
        "status": "SUCCESS",
        "message": "Engine modules and ONNX runtime successfully reloaded!"
    }

@app.get("/api/dataset/preview")
def dataset_preview(limit: int = 25):
    from core.csv_detector import DEFAULT_CSV_PATH
    import csv
    if not os.path.exists(DEFAULT_CSV_PATH):
        return {"rows": []}
    rows = []
    with open(DEFAULT_CSV_PATH, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, r in enumerate(reader):
            if idx >= limit:
                break
            rows.append(r)
    return {"rows": rows, "total_preview": len(rows), "file": os.path.basename(DEFAULT_CSV_PATH)}

# Static Dashboard Files Mount
UI_STATIC_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui", "web")
if os.path.exists(UI_STATIC_DIR):
    app.mount("/static", StaticFiles(directory=UI_STATIC_DIR), name="static")

@app.get("/")
def serve_index():
    index_file = os.path.join(UI_STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return {"message": "VeriDex AI Engine Running. Web UI files building..."}

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8484))
    uvicorn.run("api.server:app", host="0.0.0.0", port=port, log_level="info")
