# VeriDex AI: Autonomous On-Device Scam Protection

> **100% Private, Offline & Zero-Cloud Reliance**  
> Developed for the **BGSIT Hackathon** — *Theme: Digital Safety and Cybersecurity*  
> **Team:** Shreya S, Shirali S, Shreya S, Sinchana M  

---

## Problem Statement Alignment
Modern users, especially non-technical users, face phishing, typosquatting, and AI-generated social engineering attacks. Existing security solutions suffer from severe drawbacks:
- **Reactive Cloud Blacklists:** Static lists miss newly registered AI-generated scam domains.
- **Privacy Violations:** Cloud extensions transmit users' raw browsing URLs to centralized servers.
- **Alert Fatigue:** Invasive warning screens force users to bypass protections entirely.

**VeriDex AI** solves this by running an **autonomous on-device machine learning inference engine (ONNX Runtime)** coupled with **local NLP manipulation cue parsing** and an **encrypted local vault (Windows DPAPI / AES-256)**. Zero browsing data ever leaves the host machine.

---

## Technical Architecture & Stack Mapping

```
                                [ User Browsing / Clipboard / Email ]
                                                  │
                                                  ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                          VERIDEX AI ENGINE (100% On-Device)                            │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  1. REAL-TIME INTERCEPTION LAYER                                                       │
│     • Windows Clipboard Guard (`daemon/clipboard_watcher.py`)                           │
│     • Zero-Cloud REST API (`api/server.py` on localhost:8484)                          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  2. FEATURE EXTRACTION & NLP ANALYSIS                                                  │
│     • 26 Universal Lexical, Structural & Entropy Dimensions (`core/feature_extractor.py`)│
│     • Intent Categorization: Blogs, .edu, Downloads, Generic Phishing, Spoofing       │
│     • Brand Permutation & Homoglyph Engine (`core/typosquat_detector.py`)              │
│     • Manipulation Cue Parser: Urgency, Fear, Greed (`core/nlp_analyzer.py`)           │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  3. ON-DEVICE MACHINE LEARNING INFERENCE                                               │
│     • ONNX Runtime CPU Hardware Acceleration (`core/ml_engine.py`)                     │
│     • Universal Random Forest ONNX model in `models/veridex_model.onnx` (34.9 KB)      │
│     • Sub-millisecond Execution Latency (< 1 ms per URL)                               │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  4. LOCAL PRIVACY & DATA SECURITY                                                      │
│     • Windows DPAPI (CryptProtectData) + AES-256 (`security/crypto_vault.py`)           │
│     • Encrypted SQLite Threat Vault (`security/threat_db.py`)                          │
└────────────────────────────────────────────────────────────────────────────────────────┘
                                                  │
                                                  ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT FRONT-END INTERFACES                               │
├────────────────────────────────────────────────────────────────────────────────────────┤
│  • Modern Cyber-Defense Web Dashboard (`http://localhost:8484`)                        │
│  • Native Windows Desktop Application (`ui/desktop_app.py`)                           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## Quick Start Guide

### 1. Launch the Interactive Web Cyber-Defense Dashboard
Runs the local API server and automatically opens the interactive dashboard in your browser:
```bash
python run_web_dashboard.py
```
*Access via:* `http://127.0.0.1:8484`

### 2. Launch the Native Windows Desktop Application
Starts the dark-slate desktop app with real-time clipboard monitoring and toast alerts:
```bash
python run_desktop_app.py
```

### 3. Run Batch Scam Detection from CSV Dataset
Reads the 26-feature dataset from `data/veridex_dataset.csv`, scans all rows on-device, and outputs `veridex_scam_detection_results.csv`:
```bash
python run_csv_scan.py
```

### 4. Run Real-Time Hardware Benchmark
Tests 200 on-device inferences and computes min, p50, and p95 latency percentiles:
```bash
python benchmark.py
```

### 5. Run the Automated Test Suite
Executes unit tests covering ONNX inference, typosquatting, NLP, and encrypted vault operations:
```bash
python -m unittest tests/test_engine.py
```

---

## Core Capabilities

### 1. Brand Impersonation & Typosquatting Detection
- Targets 40+ high-value brands (PayPal, Apple, Google, Chase, Binance, Steam, etc.).
- Catches homoglyph substitutions (`0` -> `o`, `1` -> `l`), Punycode (`xn--`), and compound disguises (e.g. `paypa1-security-verification.com` or `paypal.com.evil-domain.xyz`).

### 2. 20-Dimensional URL Feature Extraction
- **Lexical:** Character counts, domain length, path depth, token counts.
- **Statistical:** Shannon entropy of domain and path (detects algorithmically generated domains / DGAs).
- **Structural:** IP host presence, double slashes, `@` obfuscation, suspicious TLD categorization (`.xyz`, `.top`, `.ru`, `.buzz`, etc.).

### 3. NLP Manipulation Cue Analysis
- Scans message content for psychological persuasion tactics:
  - **Urgency Pressure:** *"Immediate action required within 24 hours"*
  - **Fear & Intimidation:** *"Account suspended, court summons, legal penalty"*
  - **Financial Greed:** *"Exclusive crypto lottery winner, claim 5,000 USDT"*
  - **Credential Harvesting:** *"Enter password, SSN, seed phrase to verify"*

### 4. Zero-Cloud Privacy & Windows DPAPI Storage
- Cryptographic keys are protected using Windows DPAPI (`win32crypt.CryptProtectData`).
- URLs and forensic logs are encrypted at rest with AES-256 in `data/veridex_vault.db`.
- No browsing history or metadata is ever transmitted over the network.

### 5. Authentic Legal Website Recommendation Advisor
- Detects when a phishing/replica URL targets an established organization (e.g. PayPal, Apple, Chase, Google, Microsoft, Amazon, Netflix, Steam, Binance).
- Automatically suggests the authentic legal website (e.g., `https://www.paypal.com`), displays the verified domain, and offers a safe one-click navigation link.
- Fully supported across the **Web Cyber Dashboard**, **Native Windows App**, and **CSV Batch Scanner Export**.
