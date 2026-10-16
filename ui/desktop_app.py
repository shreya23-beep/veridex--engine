"""
VeriDex AI - Native Windows Desktop Application
Autonomous On-Device Scam Protection Client
Integrates ONNX Runtime ML engine, NLP manipulation analysis,
AES-256 / DPAPI local encrypted vault, and real-time clipboard protection.
"""

import sys
import os
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# Ensure path includes root
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from core.ml_engine import engine
from core.nlp_analyzer import nlp_analyzer
from security.threat_db import threat_db
from daemon.clipboard_watcher import interceptor

# Crema Warm Minimalist Palette
COLOR_BG = "#FAF8F5"       # Warm crema base
COLOR_CARD = "#FFFFFF"     # Clean warm white card
COLOR_INPUT = "#F6F3ED"    # Input & subtle card background
COLOR_BRAND = "#8C6842"    # Warm bronze / caramel accent
COLOR_GREEN = "#2B6E4E"    # Deep sage green
COLOR_RED = "#C53929"      # Terracotta red
COLOR_AMBER = "#B4691B"    # Honey amber
COLOR_TEXT = "#241E19"     # Deep espresso text
COLOR_MUTED = "#756A63"    # Warm coffee taupe

class VeridexDesktopApp:
    def __init__(self, root):
        self.root = root
        self.root.title("VeriDex AI — Autonomous On-Device Scam Protection")
        self.root.geometry("880x680")
        self.root.minsize(800, 600)
        self.root.config(bg=COLOR_BG)

        self._build_header()
        self._build_notebook()
        self._build_footer()

        # Start clipboard interceptor by default
        interceptor.on_threat_callback = self._on_clipboard_threat
        interceptor.start()

    def _build_header(self):
        header_frame = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=12)
        header_frame.pack(fill="x")

        # Title & Branding
        title_box = tk.Frame(header_frame, bg=COLOR_BG)
        title_box.pack(side="left")

        title_label = tk.Label(
            title_box, text="VERIDEX AI", font=("Arial", 16, "bold"),
            fg=COLOR_TEXT, bg=COLOR_BG
        )
        title_label.pack(anchor="w")

        subtitle_label = tk.Label(
            title_box, text="Autonomous On-Device Scam Protection • 100% Offline & Zero-Cloud Reliance",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_BG
        )
        subtitle_label.pack(anchor="w")

        # Status Badges
        badge_box = tk.Frame(header_frame, bg=COLOR_BG)
        badge_box.pack(side="right")

        onnx_badge = tk.Label(
            badge_box, text="ONNX Runtime (CPU)", font=("Arial", 9, "bold"),
            fg=COLOR_BRAND, bg="#F4ECE1", padx=10, pady=4
        )
        onnx_badge.pack(side="left", padx=5)

        dpapi_badge = tk.Label(
            badge_box, text="DPAPI / AES-256 Vault", font=("Arial", 9, "bold"),
            fg=COLOR_GREEN, bg="#EDF5F0", padx=10, pady=4
        )
        dpapi_badge.pack(side="left", padx=5)

    def _build_notebook(self):
        # Configure Notebook Style
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#EDE7DC", foreground=COLOR_TEXT,
                        padding=[15, 8], font=("Arial", 10, "bold"), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", COLOR_CARD)],
                  foreground=[("selected", COLOR_BRAND)])

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=10)

        # Tab 1: URL Scanner
        self.tab_url = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_url, text="  URL Inspector  ")
        self._build_url_tab()

        # Tab 2: NLP Manipulation Analyzer
        self.tab_nlp = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_nlp, text="  NLP Manipulation Cues  ")
        self._build_nlp_tab()

        # Tab 3: Encrypted Vault
        self.tab_vault = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_vault, text="  Encrypted Threat Vault  ")
        self._build_vault_tab()

        # Tab 4: CSV Dataset Scanner
        self.tab_csv = tk.Frame(self.notebook, bg=COLOR_CARD, padx=20, pady=15)
        self.notebook.add(self.tab_csv, text="  CSV Scam Detector  ")
        self._build_csv_tab()

    def _build_url_tab(self):
        # Input Section
        lbl = tk.Label(self.tab_url, text="Enter Target URL to Inspect (On-Device Inference):",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(anchor="w", pady=(0, 6))

        input_box = tk.Frame(self.tab_url, bg=COLOR_CARD)
        input_box.pack(fill="x", pady=(0, 10))

        self.url_entry = tk.Entry(input_box, font=("Arial", 11), bg=COLOR_INPUT,
                                  fg=COLOR_TEXT, insertbackground=COLOR_TEXT, relief="flat")
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=6, padx=(0, 10))
        self.url_entry.insert(0, "http://paypa1-security-verification.com/login")

        scan_btn = tk.Button(input_box, text="Inspect On-Device", font=("Arial", 10, "bold"),
                             bg="#241E19", fg="white", activebackground="#3C342C",
                             relief="flat", padx=16, command=self._scan_url_click)
        scan_btn.pack(side="right")

        # Preset Samples: Universal URL Spectrum
        preset_frame = tk.Frame(self.tab_url, bg=COLOR_CARD)
        preset_frame.pack(fill="x", pady=(0, 15))

        tk.Label(preset_frame, text="Universal Presets:", font=("Arial", 9, "bold"),
                 fg=COLOR_MUTED, bg=COLOR_CARD).pack(side="left", padx=(0, 8))

        presets = [
            ("Personal Blog", "https://danluu.com/productivity-advice/"),
            ("Recipe Site", "https://allrecipes.com/recipe/158140/spaghetti-carbonara/"),
            ("University (.edu)", "https://cs.stanford.edu/research/ai"),
            ("Scam.com", "https://scam.com"),
            ("Generic Phish", "http://account-verification-portal-urgent.com/login.php"),
            ("Malware .exe", "http://system-speedup-utility.top/download/setup.exe"),
            ("PayPal Spoof", "http://paypa1-security-verification.com/login")
        ]
        for name, u in presets:
            btn = tk.Button(preset_frame, text=name, font=("Arial", 8), bg="#F6F3ED",
                            fg=COLOR_TEXT, relief="flat", padx=6, pady=2,
                            command=lambda target=u: self._load_preset(target))
            btn.pack(side="left", padx=3)

        # Verdict Display Card
        self.verdict_frame = tk.Frame(self.tab_url, bg=COLOR_INPUT, padx=15, pady=15, relief="flat")
        self.verdict_frame.pack(fill="x", pady=10)

        self.verdict_label = tk.Label(
            self.verdict_frame, text="Status: Ready for inspection (Universal Web Support)",
            font=("Arial", 13, "bold"), fg=COLOR_GREEN, bg=COLOR_INPUT
        )
        self.verdict_label.pack(anchor="w")

        self.meta_label = tk.Label(
            self.verdict_frame, text="Latency: -- | Engine: ONNX Runtime | Privacy: 100% Offline",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_INPUT
        )
        self.meta_label.pack(anchor="w", pady=(4, 0))

        # Authentic Legal Website Suggestion Frame (Hidden by default, shown for replica scams)
        self.replica_official_url = None
        self.replica_frame = tk.Frame(
            self.tab_url, bg="#EDF5F0", padx=14, pady=12, relief="flat",
            highlightbackground="#BCD9C8", highlightthickness=1
        )

        self.replica_title = tk.Label(
            self.replica_frame, text="Authentic Official Website Available",
            font=("Arial", 10, "bold"), fg=COLOR_GREEN, bg="#EDF5F0"
        )
        self.replica_title.pack(anchor="w")

        self.replica_desc = tk.Label(
            self.replica_frame, text="",
            font=("Arial", 9), fg=COLOR_TEXT, bg="#EDF5F0", wraplength=700, justify="left"
        )
        self.replica_desc.pack(anchor="w", pady=(2, 6))

        self.replica_open_btn = tk.Button(
            self.replica_frame, text="Open Verified Official Website ->",
            font=("Arial", 9, "bold"), bg=COLOR_GREEN, fg="white", activebackground="#23593E",
            relief="flat", padx=12, pady=4, cursor="hand2", command=self._open_suggested_official_url
        )
        self.replica_open_btn.pack(anchor="w")

        # Explainable AI (XAI) Box
        tk.Label(self.tab_url, text="Explainable AI (XAI) Risk Factors:",
                 font=("Arial", 10, "bold"), fg=COLOR_BRAND, bg=COLOR_CARD).pack(anchor="w", pady=(10, 4))

        self.xai_text = scrolledtext.ScrolledText(
            self.tab_url, height=7, bg=COLOR_INPUT, fg=COLOR_TEXT,
            font=("Consolas", 10), insertbackground=COLOR_TEXT, relief="flat"
        )
        self.xai_text.pack(fill="both", expand=True)

    def _build_nlp_tab(self):
        lbl = tk.Label(self.tab_nlp, text="Paste Suspicious Email, SMS, or Fake Website Text:",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(anchor="w", pady=(0, 6))

        self.nlp_entry = scrolledtext.ScrolledText(
            self.tab_nlp, height=7, bg=COLOR_INPUT, fg=COLOR_TEXT,
            font=("Consolas", 10), insertbackground=COLOR_TEXT, relief="flat"
        )
        self.nlp_entry.pack(fill="x", pady=(0, 10))
        self.nlp_entry.insert("1.0", "URGENT NOTICE: Your PayPal account is frozen. Confirm your password and verify SSN within 24 hours to prevent permanent account suspension!")

        btn_row = tk.Frame(self.tab_nlp, bg=COLOR_CARD)
        btn_row.pack(fill="x", pady=(0, 10))

        nlp_btn = tk.Button(btn_row, text="Analyze Manipulation Cues", font=("Arial", 10, "bold"),
                            bg="#241E19", fg="white", activebackground="#3C342C",
                            relief="flat", padx=16, pady=4, command=self._scan_nlp_click)
        nlp_btn.pack(side="left")

        # NLP Verdict
        self.nlp_verdict_label = tk.Label(
            self.tab_nlp, text="Threat Level: Ready", font=("Arial", 12, "bold"),
            fg=COLOR_GREEN, bg=COLOR_CARD
        )
        self.nlp_verdict_label.pack(anchor="w", pady=(10, 4))

        self.nlp_results_text = scrolledtext.ScrolledText(
            self.tab_nlp, height=7, bg=COLOR_INPUT, fg=COLOR_TEXT,
            font=("Consolas", 10), insertbackground=COLOR_TEXT, relief="flat"
        )
        self.nlp_results_text.pack(fill="both", expand=True)

    def _build_vault_tab(self):
        top_bar = tk.Frame(self.tab_vault, bg=COLOR_CARD)
        top_bar.pack(fill="x", pady=(0, 10))

        lbl = tk.Label(top_bar, text="AES-256 / DPAPI Encrypted Vault Audit Log:",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(side="left")

        refresh_btn = tk.Button(top_bar, text="Refresh Vault", font=("Arial", 9, "bold"),
                                bg="#F6F3ED", fg=COLOR_TEXT, relief="flat", padx=10,
                                command=self._refresh_vault_table)
        refresh_btn.pack(side="right", padx=5)

        self.vault_tree = ttk.Treeview(
            self.tab_vault,
            columns=("time", "url", "verdict", "risk", "latency", "source"),
            show="headings", height=12
        )
        self.vault_tree.heading("time", text="Timestamp")
        self.vault_tree.heading("url", text="Target URL (Decrypted)")
        self.vault_tree.heading("verdict", text="Verdict")
        self.vault_tree.heading("risk", text="Risk Score")
        self.vault_tree.heading("latency", text="Latency")
        self.vault_tree.heading("source", text="Source")

        self.vault_tree.column("time", width=140)
        self.vault_tree.column("url", width=340)
        self.vault_tree.column("verdict", width=140)
        self.vault_tree.column("risk", width=80)
        self.vault_tree.column("latency", width=70)
        self.vault_tree.column("source", width=90)

        self.vault_tree.pack(fill="both", expand=True)
        self._refresh_vault_table()

    def _build_csv_tab(self):
        top_bar = tk.Frame(self.tab_csv, bg=COLOR_CARD)
        top_bar.pack(fill="x", pady=(0, 10))

        lbl = tk.Label(top_bar, text="CSV Dataset Batch Scam Inspector (data/veridex_dataset.csv):",
                       font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD)
        lbl.pack(side="left")

        btn_box = tk.Frame(top_bar, bg=COLOR_CARD)
        btn_box.pack(side="right")

        scan_csv_btn = tk.Button(btn_box, text="Scan Entire CSV", font=("Arial", 9, "bold"),
                                 bg="#241E19", fg="white", activebackground="#3C342C",
                                 relief="flat", padx=10, pady=4,
                                 command=self._run_desktop_csv_scan)
        scan_csv_btn.pack(side="left", padx=4)

        retrain_btn = tk.Button(btn_box, text="Retrain from CSV", font=("Arial", 9, "bold"),
                                bg="#F6F3ED", fg=COLOR_BRAND, relief="flat", padx=10, pady=4,
                                command=self._retrain_from_csv_click)
        retrain_btn.pack(side="left", padx=4)

        self.csv_stats_label = tk.Label(
            self.tab_csv, text="Ready. Click 'Scan Entire CSV' to run on-device batch detection.",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_CARD
        )
        self.csv_stats_label.pack(anchor="w", pady=(0, 8))

        self.csv_tree = ttk.Treeview(
            self.tab_csv,
            columns=("row", "url", "verdict", "risk", "category", "factors"),
            show="headings", height=12
        )
        self.csv_tree.heading("row", text="#")
        self.csv_tree.heading("url", text="Target URL (from CSV)")
        self.csv_tree.heading("verdict", text="Verdict")
        self.csv_tree.heading("risk", text="Risk Score")
        self.csv_tree.heading("category", text="Category")
        self.csv_tree.heading("factors", text="Key Indicators")

        self.csv_tree.column("row", width=40)
        self.csv_tree.column("url", width=300)
        self.csv_tree.column("verdict", width=140)
        self.csv_tree.column("risk", width=80)
        self.csv_tree.column("category", width=120)
        self.csv_tree.column("factors", width=200)

        self.csv_tree.pack(fill="both", expand=True)

    def _run_desktop_csv_scan(self):
        from core.csv_detector import scan_csv_dataset
        for item in self.csv_tree.get_children():
            self.csv_tree.delete(item)

        try:
            summary = scan_csv_dataset(save_output=True)
            for r in summary["all_results"]:
                verdict_str = f"[!] {r['verdict']}" if r["is_scam"] else f"[OK] {r['verdict']}"
                factors_str = "; ".join(r["risk_factors"][:1]) if r["risk_factors"] else "Clean"
                self.csv_tree.insert("", "end", values=(
                    r["row_index"], r["url"], verdict_str,
                    f"{r['risk_score']}%", r["type_badge"], factors_str
                ))

            self.csv_stats_label.config(
                text=f"Batch Scan Complete! Total Rows: {summary['total_scanned']} | Scams Detected: {summary['threats_found']} | Safe Verified: {summary['safe_found']} | Scam Ratio: {summary['threat_ratio_percent']}%",
                fg=COLOR_GREEN
            )
            self._refresh_vault_table()
        except Exception as e:
            messagebox.showerror("Scan Error", f"Failed to scan CSV dataset: {e}")

    def _retrain_from_csv_click(self):
        from core.trainer import train_and_export_model
        try:
            metrics = train_and_export_model()
            engine._load_model()
            messagebox.showinfo(
                "Retrain Complete",
                f"Model successfully retrained from CSV dataset!\n\nAccuracy: {metrics['accuracy']}%\nPrecision: {metrics['precision']}%\nRecall: {metrics['recall']}%\nF1-Score: {metrics['f1_score']}%\n\nExported to ONNX runtime."
            )
            self._refresh_vault_table()
        except Exception as e:
            messagebox.showerror("Retraining Error", f"Failed to retrain model: {e}")

    def _build_footer(self):
        footer_frame = tk.Frame(self.root, bg=COLOR_BG, padx=20, pady=8)
        footer_frame.pack(fill="x", side="bottom")

        stats = threat_db.get_vault_statistics()
        self.footer_label = tk.Label(
            footer_frame,
            text=f"Total Local Scans: {stats['total_scans']} | Threats Blocked: {stats['threats_blocked']} | Average Latency: {stats['avg_latency_ms']} ms",
            font=("Arial", 9), fg=COLOR_MUTED, bg=COLOR_BG
        )
        self.footer_label.pack(side="left")

    def _load_preset(self, url: str):
        self.url_entry.delete(0, tk.END)
        self.url_entry.insert(0, url)
        self._scan_url_click()

    def _scan_url_click(self):
        url = self.url_entry.get().strip()
        if not url:
            messagebox.showwarning("Input Error", "Please provide a valid URL to scan.")
            return

        res = engine.inspect_url(url)
        threat_db.log_scan(res, source="DESKTOP_UI")

        # Update UI
        color = COLOR_RED if res["is_threat"] else COLOR_GREEN
        cat = res.get("classification", {}).get("category", "General Web")
        cat_badge = res.get("classification", {}).get("type_badge", "WEB")
        self.verdict_label.config(
            text=f"[{cat_badge}] {res['verdict']} (Risk: {res['risk_score']}%)",
            fg=color
        )
        self.meta_label.config(
            text=f"Category: {cat} | Latency: {res['latency_ms']} ms | Engine: {res['engine']} | 100% Offline"
        )

        # Legitimate Website Recommendation handling
        sugg = res.get("legitimate_website_suggestion")
        if sugg:
            self.replica_official_url = sugg.get("official_url")
            brand = sugg.get("spoofed_brand", "Verified Brand")
            domain = sugg.get("official_domain", "")
            self.replica_title.config(
                text=f"Authentic Official Website Identified: {brand} ({domain})"
            )
            self.replica_desc.config(
                text=f"The inspected link is an unauthorized replica or phishing imitation.\nUse the verified authentic website: {self.replica_official_url}"
            )
            self.replica_frame.pack(fill="x", pady=(0, 10), after=self.verdict_frame)
        else:
            self.replica_official_url = None
            self.replica_frame.pack_forget()

        # XAI
        self.xai_text.delete("1.0", tk.END)
        self.xai_text.insert(tk.END, "=== EXPLAINABLE AI RISK BREAKDOWN ===\n\n")
        for f in res["risk_factors"]:
            symbol = "[-]" if res["is_threat"] else "[+]"
            self.xai_text.insert(tk.END, f"{symbol} {f}\n")

        self._refresh_vault_table()

    def _open_suggested_official_url(self):
        if self.replica_official_url:
            webbrowser.open(self.replica_official_url)

    def _scan_nlp_click(self):
        text = self.nlp_entry.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Input Error", "Please enter text to analyze.")
            return

        res = nlp_analyzer.analyze_text(text)
        color = COLOR_RED if res["threat_level"] in ("CRITICAL", "SUSPICIOUS") else COLOR_GREEN
        self.nlp_verdict_label.config(
            text=f"Threat Level: {res['threat_level']} (Manipulation Score: {res['risk_score']}%)",
            fg=color
        )

        self.nlp_results_text.delete("1.0", tk.END)
        self.nlp_results_text.insert(tk.END, f"Summary: {res['summary']}\n\n")
        self.nlp_results_text.insert(tk.END, "=== DETECTED MANIPULATION CUES ===\n")
        for cue in res["detected_cues"]:
            self.nlp_results_text.insert(
                tk.END,
                f"\n[+] {cue['category']} (+{cue['category_risk']}%)\n    Desc: {cue['description']}\n    Matches: {', '.join(cue['matched_tokens'])}\n"
            )

    def _refresh_vault_table(self):
        for item in self.vault_tree.get_children():
            self.vault_tree.delete(item)

        scans = threat_db.get_recent_scans(50)
        for s in scans:
            self.vault_tree.insert("", "end", values=(
                s["timestamp"], s["url"], s["verdict"],
                f"{s['risk_score']}%", f"{s['latency_ms']}ms", s["source"]
            ))

        stats = threat_db.get_vault_statistics()
        if hasattr(self, "footer_label"):
            self.footer_label.config(
                text=f"Total Local Scans: {stats['total_scans']} | Threats Blocked: {stats['threats_blocked']} | Average Latency: {stats['avg_latency_ms']} ms"
            )

    def _on_clipboard_threat(self, result: dict):
        # Called when clipboard interceptor detects a threat
        self.root.after(0, lambda: self._handle_clipboard_event(result))

    def _handle_clipboard_event(self, result: dict):
        self._refresh_vault_table()
        messagebox.showwarning(
            "VeriDex AI — Threat Intercepted",
            f"Alert! Dangerous link intercepted from clipboard:\n\n{result['url']}\n\nVerdict: {result['verdict']}\nRisk: {result['risk_score']}%\n\nThreat logged to your DPAPI encrypted vault."
        )

if __name__ == "__main__":
    root = tk.Tk()
    app = VeridexDesktopApp(root)
    root.mainloop()
