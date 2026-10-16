"""
VeriDex AI - Launcher for Web Cyber-Defense Dashboard & REST API
Starts the local zero-cloud API server and opens the interactive dashboard.
"""

import sys
import os
import webbrowser
import uvicorn

sys.path.insert(0, os.path.dirname(__file__))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

def main():
    port = 8484
    host = "127.0.0.1"
    url = f"http://{host}:{port}"
    print("=" * 65)
    print("VERIDEX AI — AUTONOMOUS ON-DEVICE SCAM PROTECTION ENGINE")
    print("=" * 65)
    print("Mode:         100% Private, Offline & Zero-Cloud Reliance")
    print("AI Backend:   ONNX Runtime (CPU Hardware Accelerated)")
    print("Local Vault:  Windows DPAPI & AES-256 Encrypted SQLite")
    print(f"Dashboard:    {url}")
    print("=" * 65)

    # Automatically launch default browser
    try:
        webbrowser.open(url)
    except Exception:
        pass

    # Run uvicorn server
    uvicorn.run("api.server:app", host=host, port=port, log_level="info")

if __name__ == "__main__":
    main()
