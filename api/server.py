"""
VeriDex AI - Local REST API Server & Dashboard Host
Provides zero-cloud local endpoints for on-device inference,
real-time clipboard monitoring, and the web cyber-defense dashboard.
"""

import os
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from core.ml_engine import engine
from core.nlp_analyzer import nlp_analyzer
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
    result = engine.inspect_url(req.url)
    
    # Log to encrypted vault
    threat_db.log_scan(result, source=req.source)
    return result

@app.post("/api/scan/text")
def scan_text(req: TextScanRequest):
    start = time.perf_counter()
    result = nlp_analyzer.analyze_text(req.text)
    latency_ms = round((time.perf_counter() - start) * 1000, 2)
    result["latency_ms"] = latency_ms
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

# CSV Dataset & Batch Scam Scanning Endpoints
@app.post("/api/scan/csv")
def scan_csv_endpoint(custom_path: Optional[str] = None):
    from core.csv_detector import scan_csv_dataset, DEFAULT_CSV_PATH
    path = custom_path if (custom_path and os.path.exists(custom_path)) else DEFAULT_CSV_PATH
    summary = scan_csv_dataset(csv_path=path, save_output=True)
    return summary

@app.post("/api/model/retrain")
def retrain_model_endpoint(custom_path: Optional[str] = None):
    from core.trainer import train_and_export_model, DEFAULT_DATASET_CSV
    path = custom_path if (custom_path and os.path.exists(custom_path)) else DEFAULT_DATASET_CSV
    metrics = train_and_export_model(csv_path=path)
    # Hot-reload ONNX model in engine
    engine._load_model()
    return {
        "status": "SUCCESS",
        "message": f"Random Forest & ONNX engine successfully retrained from {os.path.basename(path)}!",
        "metrics": metrics
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
