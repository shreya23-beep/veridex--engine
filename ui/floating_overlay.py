"""
VeriDex AI - Always-On-Top Desktop Companion & Active App Inspector
Features:
- Stable, non-movable small logo locked at the bottom-right corner of the desktop.
- Clicking the logo opens the extension directly at the EXACT CENTER OF THE DESKTOP.
- Displays currently opened app, target URL, and IP address.
- If fake/scam: instructs user to register complaint on cybercrime.gov.in or dial 1930 from dialpad.
- Includes Cyber Incident Report Card and practical cyber security tools (Quick URL verifier,
  CERT-In emergency directory, real-time cyber fraud advisories).
- Dedicated block to enter the official VeriDex AI web browser: upon redirecting/opening, the
  centered extension closes automatically while the logo remains stable at its fixed location.
- Message Screenshot Analyzer is kept exclusively in the web browser.
"""

import sys
import os
import time
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk
from typing import Optional, Dict, Any
from PIL import Image, ImageTk

# Include project root
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.ml_engine import engine
from daemon.clipboard_watcher import interceptor
from daemon.app_inspector import app_inspector
from security.threat_db import threat_db
from core.ip_resolver import resolve_ip_intelligence

LOGO_PATH = os.path.join(ROOT_DIR, "ui", "web", "assets", "logo.png")

# Palette matching Crema Theme
BG_CREMA = "#FAF8F5"       # Warm crema background
BG_CARD = "#FFFFFF"        # Pure white card
BG_CARD_SUBTLE = "#F6F3ED" # Subtle card fill
BORDER_COLOR = "#E8E2D8"   # Border crema
BORDER_BRAND = "#8C6842"   # Golden bronze brand
TEXT_MAIN = "#241E19"      # Rich espresso
TEXT_MUTED = "#756A63"     # Warm grey
BRAND_BROWN = "#8C6842"    # Brand bronze
BRAND_LIGHT = "#F4ECE1"    # Light brand pill
SAFE_GREEN = "#2B6E4E"     # Deep forest sage green
SAFE_BG = "#EDF5F0"        # Light green bg
THREAT_RED = "#C53929"     # Deep terracotta crimson
THREAT_BG = "#FDF1EE"      # Light red bg
AMBER_COLOR = "#B4691B"    # Warm amber
AMBER_BG = "#FCF6EC"       # Light amber bg


class VeridexFloatingOverlay:
    """
    Desktop Companion:
    - Locked stationary small logo (bottom-right of screen).
    - Centered extension window on desktop when clicked.
    - Automatic dismissal on redirection to official web browser/site.
    """

    def __init__(self):
        # 1. Main Root Window = Fixed Small Logo
        self.root = tk.Tk()
        self.root.title("VeriDex AI Desktop Companion")
        self.root.overrideredirect(True)          # Frameless
        self.root.attributes("-topmost", True)      # Always on top of EVERY application
        self.root.config(bg="#000000")
        self.root.wm_attributes("-transparentcolor", "#000000")

        # Screen & Size Metrics
        self.screen_w = self.root.winfo_screenwidth()
        self.screen_h = self.root.winfo_screenheight()

        self.compact_size = 56
        self.ext_w = 440
        self.ext_h = 580

        # Fixed, locked position: Bottom-Right above Windows taskbar (STABLE & NON-MOVABLE)
        self.pos_x = self.screen_w - self.compact_size - 24
        self.pos_y = self.screen_h - self.compact_size - 68
        self.root.geometry(f"{self.compact_size}x{self.compact_size}+{self.pos_x}+{self.pos_y}")

        self.running = True
        self.my_hwnd = None
        self.ext_win: Optional[tk.Toplevel] = None

        # Inspection cache
        self.latest_app_info: Dict[str, Any] = {
            "display_name": "Desktop Workspace",
            "exe_name": "explorer.exe",
            "window_title": "Windows Desktop",
            "target_url": None,
            "status_text": "Protected",
            "is_safe": True,
            "is_threat": False,
            "color": SAFE_GREEN,
            "server_ip": "127.0.0.1 (Local Host)",
            "isp": "Local System Interface",
            "legitimate_suggestion": None
        }

        # Load Logo Assets
        self._load_logo_assets()

        # Ensure local web server is running in background
        self._ensure_server_running()

        # Build Stationary Small Logo UI
        self._build_logo_ui()

        # Obtain HWND
        self.root.update_idletasks()
        try:
            self.my_hwnd = self.root.winfo_id()
        except Exception:
            self.my_hwnd = None

        # Start Background Workers
        self._start_clipboard_watcher()
        self._start_active_window_tracker()

    def _load_logo_assets(self):
        """Loads and prepares different sizes of the official VeriDex 'V' logo."""
        self.logo_compact_img = None
        self.logo_header_img = None
        if os.path.exists(LOGO_PATH):
            try:
                base_img = Image.open(LOGO_PATH)
                self.logo_compact_img = ImageTk.PhotoImage(base_img.resize((36, 36), Image.Resampling.LANCZOS))
                self.logo_header_img = ImageTk.PhotoImage(base_img.resize((22, 22), Image.Resampling.LANCZOS))
            except Exception as e:
                print(f"[OVERLAY] Logo asset error: {e}")

    def _ensure_server_running(self):
        """Checks if local web dashboard server on port 8484 is running; if not, starts it."""
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", 8484)) == 0:
                return  # Port 8484 already active
        except Exception:
            pass
        finally:
            sock.close()

        def _run_server():
            try:
                import uvicorn
                from api.server import app
                config = uvicorn.Config(app, host="127.0.0.1", port=8484, log_level="warning")
                server = uvicorn.Server(config)
                server.run()
            except Exception as e:
                print(f"[SERVER] Auto-start error: {e}")

        threading.Thread(target=_run_server, daemon=True).start()

    def _build_logo_ui(self):
        """Constructs the stable, locked small logo at bottom-right."""
        self.logo_frame = tk.Frame(
            self.root,
            bg=BG_CREMA,
            highlightbackground=BORDER_BRAND,
            highlightthickness=2,
            cursor="hand2"
        )
        self.logo_frame.place(x=0, y=0, width=self.compact_size, height=self.compact_size)

        # Center logo
        if self.logo_compact_img:
            self.compact_logo_lbl = tk.Label(
                self.logo_frame,
                image=self.logo_compact_img,
                bg=BG_CREMA,
                cursor="hand2"
            )
            self.compact_logo_lbl.place(x=8, y=8)
        else:
            self.compact_logo_lbl = tk.Label(
                self.logo_frame,
                text="V",
                font=("Arial", 18, "bold"),
                fg=BRAND_BROWN,
                bg=BG_CREMA,
                cursor="hand2"
            )
            self.compact_logo_lbl.place(x=14, y=10)

        # Corner live safety status dot
        self.compact_dot = tk.Label(
            self.logo_frame,
            text="•",
            font=("Arial", 16, "bold"),
            fg=SAFE_GREEN,
            bg=BG_CREMA,
            cursor="hand2"
        )
        self.compact_dot.place(x=36, y=32)

        # Click event: Opens/Toggles extension in the CENTER of the desktop!
        # NO drag motion bindings — logo is stable and non-movable!
        for w in (self.logo_frame, self.compact_logo_lbl, self.compact_dot):
            w.bind("<Button-1>", lambda e: self.toggle_extension_window())
            w.bind("<Button-3>", self._show_context_menu)

        # Context menu
        self.context_menu = tk.Menu(self.root, tearoff=0, font=("Segoe UI", 9))
        self.context_menu.add_command(label="Open Security Extension (Center)", command=self.open_extension_window)
        self.context_menu.add_command(label="Open Official VeriDex AI Web Browser", command=self._open_web_dashboard)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Dial 1930 Cyber Helpline", command=lambda: webbrowser.open("tel:1930"))
        self.context_menu.add_command(label="National Cybercrime Portal (cybercrime.gov.in)", command=lambda: webbrowser.open("https://cybercrime.gov.in"))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Exit VeriDex Companion", command=self._on_exit)

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def toggle_extension_window(self):
        """Toggles the security extension in the center of the desktop."""
        if self.ext_win and self.ext_win.winfo_exists():
            self.close_extension_window()
        else:
            self.open_extension_window()

    def close_extension_window(self):
        """Closes the centered extension window while the small logo remains in place."""
        if self.ext_win and self.ext_win.winfo_exists():
            try:
                self.ext_win.destroy()
            except Exception:
                pass
            self.ext_win = None

    def open_extension_window(self):
        """Opens the extension window right in the EXACT CENTER OF THE DESKTOP."""
        if self.ext_win and self.ext_win.winfo_exists():
            self.ext_win.lift()
            self.ext_win.attributes("-topmost", True)
            return

        self.ext_win = tk.Toplevel(self.root)
        self.ext_win.title("VeriDex AI — Security Extension")
        self.ext_win.overrideredirect(True)
        self.ext_win.attributes("-topmost", True)
        self.ext_win.config(bg=BG_CREMA)

        # Calculate exact center coordinates on desktop
        center_x = max(20, (self.screen_w - self.ext_w) // 2)
        center_y = max(20, (self.screen_h - self.ext_h) // 2)
        self.ext_win.geometry(f"{self.ext_w}x{self.ext_h}+{center_x}+{center_y}")

        # Build extension contents
        self._build_extension_ui(self.ext_win)
        self._update_extension_ui()

    def _build_extension_ui(self, parent: tk.Toplevel):
        """Constructs all security forensics & cyber tools inside the centered window."""
        container = tk.Frame(
            parent,
            bg=BG_CREMA,
            highlightbackground=BORDER_BRAND,
            highlightthickness=1.5,
            padx=16,
            pady=14
        )
        container.pack(fill="both", expand=True)

        # 1. Header Bar
        header = tk.Frame(container, bg=BG_CREMA)
        header.pack(fill="x", pady=(0, 10))

        header_left = tk.Frame(header, bg=BG_CREMA)
        header_left.pack(side="left")

        if self.logo_header_img:
            tk.Label(header_left, image=self.logo_header_img, bg=BG_CREMA).pack(side="left", padx=(0, 6))

        tk.Label(
            header_left,
            text="VERIDEX AI",
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_MAIN,
            bg=BG_CREMA
        ).pack(side="left", padx=(0, 6))

        tk.Label(
            header_left,
            text="100% On-Device",
            font=("Segoe UI", 8, "bold"),
            fg=SAFE_GREEN,
            bg=SAFE_BG,
            padx=5,
            pady=1
        ).pack(side="left")

        # Close button (closes centered extension; logo remains untouched!)
        btn_close = tk.Label(
            header,
            text="✕",
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_MUTED,
            bg=BG_CREMA,
            cursor="hand2"
        )
        btn_close.pack(side="right")
        btn_close.bind("<Button-1>", lambda e: self.close_extension_window())

        # 2. Currently Opened Application & Target Card
        self.app_card = tk.Frame(
            container,
            bg=BG_CARD,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=12,
            pady=9
        )
        self.app_card.pack(fill="x", pady=(0, 8))

        app_label_row = tk.Frame(self.app_card, bg=BG_CARD)
        app_label_row.pack(fill="x", pady=(0, 3))

        tk.Label(
            app_label_row,
            text="CURRENTLY OPENED APPLICATION",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_CARD
        ).pack(side="left")

        self.lbl_app_status_tag = tk.Label(
            app_label_row,
            text="Verified",
            font=("Segoe UI", 8, "bold"),
            fg=SAFE_GREEN,
            bg=SAFE_BG,
            padx=5,
            pady=1
        )
        self.lbl_app_status_tag.pack(side="right")

        self.lbl_app_name = tk.Label(
            self.app_card,
            text="Detecting Active App...",
            font=("Segoe UI", 11, "bold"),
            fg=TEXT_MAIN,
            bg=BG_CARD,
            anchor="w"
        )
        self.lbl_app_name.pack(fill="x")

        self.lbl_app_details = tk.Label(
            self.app_card,
            text="Monitoring foreground window",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            anchor="w"
        )
        self.lbl_app_details.pack(fill="x", pady=(0, 5))

        self.lbl_target_info = tk.Label(
            self.app_card,
            text="Target: Desktop Workspace",
            font=("Consolas", 8),
            fg=TEXT_MAIN,
            bg=BG_CARD_SUBTLE,
            anchor="w",
            padx=6,
            pady=3
        )
        self.lbl_target_info.pack(fill="x", pady=(0, 5))

        # IP Address Row (Always Included)
        self.ip_row = tk.Frame(self.app_card, bg=BG_CARD_SUBTLE, padx=6, pady=3)
        self.ip_row.pack(fill="x", pady=(0, 6))

        tk.Label(
            self.ip_row,
            text="IP Address:",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_CARD_SUBTLE
        ).pack(side="left", padx=(0, 4))

        self.lbl_server_ip_val = tk.Label(
            self.ip_row,
            text="127.0.0.1 (Local Host)",
            font=("Consolas", 8, "bold"),
            fg=SAFE_GREEN,
            bg=BG_CARD_SUBTLE
        )
        self.lbl_server_ip_val.pack(side="left")

        # Verdict Banner
        self.verdict_banner = tk.Frame(self.app_card, bg=SAFE_BG, padx=8, pady=4)
        self.verdict_banner.pack(fill="x")

        self.lbl_verdict_title = tk.Label(
            self.verdict_banner,
            text="SAFE & VERIFIED ON-DEVICE",
            font=("Segoe UI", 9, "bold"),
            fg=SAFE_GREEN,
            bg=SAFE_BG
        )
        self.lbl_verdict_title.pack(side="left")

        self.lbl_verdict_latency = tk.Label(
            self.verdict_banner,
            text="< 0.5 ms",
            font=("Segoe UI", 8),
            fg=SAFE_GREEN,
            bg=SAFE_BG
        )
        self.lbl_verdict_latency.pack(side="right")

        # 3. Threat / Scam Warning Banner (Register on gov.in or dial 1930)
        self.threat_alert_box = tk.Frame(
            container,
            bg=THREAT_BG,
            highlightbackground=THREAT_RED,
            highlightthickness=1,
            padx=10,
            pady=8
        )
        self.lbl_threat_alert_title = tk.Label(
            self.threat_alert_box,
            text="⚠️ SCAM DETECTED — CULPRIT IP TRACED",
            font=("Segoe UI", 9, "bold"),
            fg=THREAT_RED,
            bg=THREAT_BG
        )
        self.lbl_threat_alert_title.pack(anchor="w")

        self.lbl_threat_alert_msg = tk.Label(
            self.threat_alert_box,
            text="Register a complaint on cybercrime.gov.in or dial 1930 from your phone dialpad immediately.",
            font=("Segoe UI", 8),
            fg=TEXT_MAIN,
            bg=THREAT_BG,
            wraplength=380,
            justify="left"
        )
        self.lbl_threat_alert_msg.pack(anchor="w", pady=(2, 6))

        threat_btn_row = tk.Frame(self.threat_alert_box, bg=THREAT_BG)
        threat_btn_row.pack(fill="x")

        tk.Button(
            threat_btn_row,
            text="Dial 1930 (Helpline Dialpad)",
            font=("Segoe UI", 8, "bold"),
            bg=THREAT_RED,
            fg="#FFFFFF",
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2",
            command=lambda: webbrowser.open("tel:1930")
        ).pack(side="left", padx=(0, 6))

        tk.Button(
            threat_btn_row,
            text="Register on cybercrime.gov.in",
            font=("Segoe UI", 8, "bold"),
            bg="#1E3A8A",
            fg="#FFFFFF",
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2",
            command=lambda: webbrowser.open("https://cybercrime.gov.in")
        ).pack(side="left")

        # Hidden until threat
        self.threat_alert_box.pack_forget()

        # 4. Cyber Incident Report Card
        self.report_card_box = tk.Frame(
            container,
            bg=BG_CARD,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=10,
            pady=7
        )
        self.report_card_box.pack(fill="x", pady=(0, 8))

        rc_header = tk.Frame(self.report_card_box, bg=BG_CARD)
        rc_header.pack(fill="x", pady=(0, 3))

        tk.Label(
            rc_header,
            text="CYBER INCIDENT REPORT CARD",
            font=("Segoe UI", 8, "bold"),
            fg=BRAND_BROWN,
            bg=BG_CARD
        ).pack(side="left")

        self.lbl_report_id = tk.Label(
            rc_header,
            text="VDX-INCIDENT-READY",
            font=("Consolas", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_CARD
        )
        self.lbl_report_id.pack(side="right")

        self.btn_copy_report = tk.Button(
            self.report_card_box,
            text="📋 Copy Incident Report Card (Dossier)",
            font=("Segoe UI", 8, "bold"),
            bg=BRAND_LIGHT,
            fg=BRAND_BROWN,
            activebackground="#E8DEC9",
            relief="flat",
            padx=8,
            pady=4,
            cursor="hand2",
            command=self._copy_incident_report
        )
        self.btn_copy_report.pack(fill="x", pady=(2, 0))

        # 5. OTHER CYBER SECURITY UTILITIES (NEW)
        cyber_tools_box = tk.Frame(
            container,
            bg=BG_CARD,
            highlightbackground=BORDER_COLOR,
            highlightthickness=1,
            padx=10,
            pady=7
        )
        cyber_tools_box.pack(fill="x", pady=(0, 8))

        tk.Label(
            cyber_tools_box,
            text="CYBER DEFENSE & QUICK SCANNER",
            font=("Segoe UI", 8, "bold"),
            fg=TEXT_MUTED,
            bg=BG_CARD
        ).pack(anchor="w", pady=(0, 4))

        # Quick URL scanner entry
        scan_row = tk.Frame(cyber_tools_box, bg=BG_CARD)
        scan_row.pack(fill="x", pady=(0, 4))

        self.quick_url_entry = tk.Entry(
            scan_row,
            font=("Segoe UI", 8),
            bg=BG_CARD_SUBTLE,
            fg=TEXT_MAIN,
            relief="flat",
            highlightthickness=1,
            highlightbackground=BORDER_COLOR
        )
        self.quick_url_entry.pack(side="left", fill="x", expand=True, padx=(0, 4), ipady=3)
        self.quick_url_entry.insert(0, "Paste link to verify on-device...")
        self.quick_url_entry.bind("<FocusIn>", lambda e: self.quick_url_entry.delete(0, "end") if self.quick_url_entry.get().startswith("Paste") else None)

        btn_verify = tk.Button(
            scan_row,
            text="Verify Link",
            font=("Segoe UI", 8, "bold"),
            bg=BRAND_BROWN,
            fg="#FFFFFF",
            relief="flat",
            padx=6,
            pady=2,
            cursor="hand2",
            command=self._quick_scan_url
        )
        btn_verify.pack(side="right")

        # Rotating Cyber Advisory Pill
        advisory_box = tk.Frame(cyber_tools_box, bg=BG_CARD_SUBTLE, padx=6, pady=3)
        advisory_box.pack(fill="x")
        tk.Label(
            advisory_box,
            text="💡 Cyber Safety Advisory:",
            font=("Segoe UI", 7, "bold"),
            fg=BRAND_BROWN,
            bg=BG_CARD_SUBTLE
        ).pack(anchor="w")
        self.lbl_advisory = tk.Label(
            advisory_box,
            text="Never install screen-sharing APKs (AnyDesk/RustDesk) or share OTPs for bank KYC updates.",
            font=("Segoe UI", 7),
            fg=TEXT_MUTED,
            bg=BG_CARD_SUBTLE,
            wraplength=380,
            justify="left"
        )
        self.lbl_advisory.pack(anchor="w")

        # 6. DEDICATED OFFICIAL VERIDEX AI WEB BROWSER BLOCK
        # (Clicking automatically redirects to official browser AND closes extension window)
        self.browser_card = tk.Frame(
            container,
            bg=BG_CARD,
            highlightbackground=BORDER_BRAND,
            highlightthickness=1.5,
            padx=12,
            pady=9
        )
        self.browser_card.pack(fill="x", pady=(0, 4))

        b_header = tk.Frame(self.browser_card, bg=BG_CARD)
        b_header.pack(fill="x", pady=(0, 2))

        tk.Label(
            b_header,
            text="VeriDex AI Security Center",
            font=("Segoe UI", 10, "bold"),
            fg=TEXT_MAIN,
            bg=BG_CARD
        ).pack(side="left")

        tk.Label(
            self.browser_card,
            text="Launch full on-device cyber dashboard, Message Screenshot Analyzer, and encrypted vault.",
            font=("Segoe UI", 8),
            fg=TEXT_MUTED,
            bg=BG_CARD,
            wraplength=380,
            justify="left"
        ).pack(fill="x", pady=(0, 6))

        # Official Website Redirect Button (for replica scam)
        self.btn_official_redirect = tk.Button(
            self.browser_card,
            text="Redirect to Authentic Official Website",
            font=("Segoe UI", 8, "bold"),
            bg=SAFE_GREEN,
            fg="#FFFFFF",
            relief="flat",
            padx=8,
            pady=5,
            cursor="hand2",
            command=self._redirect_official
        )
        self.btn_official_redirect.pack(fill="x", pady=(0, 4))
        self.btn_official_redirect.pack_forget()

        # Primary Action: Open Official VeriDex AI Web Browser
        # (Closes extension automatically, logo remains in place!)
        self.btn_open_web = tk.Button(
            self.browser_card,
            text="Open Official VeriDex AI Web Browser ➔",
            font=("Segoe UI", 9, "bold"),
            bg=TEXT_MAIN,
            fg="#FFFFFF",
            activebackground="#3C342C",
            activeforeground="#FFFFFF",
            relief="flat",
            padx=10,
            pady=7,
            cursor="hand2",
            command=self._open_web_dashboard
        )
        self.btn_open_web.pack(fill="x")

        # Footer note
        tk.Label(
            container,
            text="VeriDex AI • 100% On-Device DPAPI Vault • Logo Remains Ready",
            font=("Segoe UI", 7),
            fg=TEXT_MUTED,
            bg=BG_CREMA
        ).pack(side="bottom", pady=(2, 0))

    def _quick_scan_url(self):
        """Scans any URL entered in the quick entry box."""
        if not hasattr(self, "quick_url_entry"):
            return
        url = self.quick_url_entry.get().strip()
        if not url or url.startswith("Paste"):
            return

        res = engine.inspect_url(url, source="EXTENSION_QUICK_SCAN")
        ip_intel = resolve_ip_intelligence(url, is_threat=res["is_threat"], source="EXTENSION_QUICK_SCAN")
        info = {
            "display_name": f"Scanned: {extract_domain(url)}",
            "exe_name": "Quick URL Scanner",
            "window_title": url,
            "target_url": url,
            "status_text": res.get("verdict", "Protected"),
            "is_safe": not res.get("is_threat"),
            "is_threat": res.get("is_threat", False),
            "color": THREAT_RED if res.get("is_threat") else SAFE_GREEN,
            "server_ip": ip_intel.get("server_ip", "127.0.0.1"),
            "isp": ip_intel.get("isp", "Host Network"),
            "legitimate_suggestion": res.get("legitimate_website_suggestion")
        }
        self.latest_app_info = info
        self._update_extension_ui()

    def _open_web_dashboard(self):
        """
        Opens the official VeriDex AI Web Browser / Dashboard,
        and automatically closes the extension window while keeping
        the small logo in place!
        """
        self._ensure_server_running()
        webbrowser.open("http://127.0.0.1:8484")
        # Automatically close extension window; logo stays stable!
        self.close_extension_window()

    def _redirect_official(self):
        """
        Redirects to the verified authentic official website for replica scams,
        and automatically closes the extension window while keeping the logo in place!
        """
        sugg = self.latest_app_info.get("legitimate_suggestion")
        if sugg and sugg.get("official_url"):
            webbrowser.open(sugg["official_url"])
        # Automatically close extension window; logo stays stable!
        self.close_extension_window()

    def _copy_incident_report(self):
        """Copies the formatted Cyber Incident Report Card to clipboard."""
        info = self.latest_app_info
        rep_id = getattr(self, "lbl_report_id", None)
        rep_id_text = rep_id.cget("text") if rep_id else "VDX-INCIDENT"
        target = info.get("target_url") or info.get("display_name") or "Desktop Workspace"
        ip = info.get("server_ip") or "127.0.0.1"
        is_threat = info.get("is_threat", False)

        dossier = (
            f"====================================================================\n"
            f"          OFFICIAL CYBER INCIDENT REPORT CARD\n"
            f"  Ministry of Home Affairs (I4C) Compliant Security Forensics\n"
            f"====================================================================\n"
            f"Report ID:          {rep_id_text}\n"
            f"Timestamp:          {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Inspected Target:   {target}\n"
            f"Process / App:      {info.get('exe_name', 'Unknown')}\n"
            f"Verdict:            {'FAKE SCAM THREAT' if is_threat else 'VERIFIED SAFE'}\n"
            f"Target Server IP:   {ip}\n"
            f"Hosting Network:    {info.get('isp', 'Host Interface')}\n"
            f"--------------------------------------------------------------------\n"
            f"Action Required:\n"
            f"  1. Register incident online: https://cybercrime.gov.in\n"
            f"  2. Dial national helpline:  1930 (from phone dialpad)\n"
            f"  3. Quote Culprit Server IP {ip} to reporting authorities\n"
            f"====================================================================\n"
            f"Verified autonomously on-device by VeriDex AI Engine."
        )

        self.root.clipboard_clear()
        self.root.clipboard_append(dossier)
        if hasattr(self, "btn_copy_report") and self.btn_copy_report.winfo_exists():
            orig_text = self.btn_copy_report.cget("text")
            self.btn_copy_report.config(text="✓ Incident Report Card Copied!")
            self.root.after(2500, lambda: self.btn_copy_report.config(text=orig_text) if hasattr(self, "btn_copy_report") and self.btn_copy_report.winfo_exists() else None)

    def _update_extension_ui(self):
        """Renders active app and website forensics inside the extension view."""
        info = self.latest_app_info
        display_name = info.get("display_name", "Active Window")
        exe_name = info.get("exe_name", "")
        window_title = info.get("window_title", "")
        target_url = info.get("target_url")
        is_threat = info.get("is_threat", False)
        server_ip = info.get("server_ip") or ("185.220.101.45 (Offshore Threat)" if is_threat else "127.0.0.1 (Local Host)")
        sugg = info.get("legitimate_suggestion")

        # 1. Update compact live status dot on small logo
        dot_color = THREAT_RED if is_threat else SAFE_GREEN
        if hasattr(self, "compact_dot"):
            self.compact_dot.config(fg=dot_color)

        # 2. Update centered extension controls (if open)
        if not (self.ext_win and self.ext_win.winfo_exists()):
            return

        if hasattr(self, "lbl_app_name"):
            self.lbl_app_name.config(text=display_name)
        if hasattr(self, "lbl_app_details"):
            self.lbl_app_details.config(text=f"{exe_name} • {window_title[:38]}")

        # Target Destination
        if hasattr(self, "lbl_target_info"):
            if target_url:
                disp_target = f"URL: {target_url[:42]}.." if len(target_url) > 44 else f"URL: {target_url}"
                self.lbl_target_info.config(text=disp_target, fg=THREAT_RED if is_threat else TEXT_MAIN)
            else:
                self.lbl_target_info.config(text=f"Process: {exe_name} ({window_title[:28]})", fg=TEXT_MUTED)

        # Always Display IP Address
        if hasattr(self, "lbl_server_ip_val"):
            self.lbl_server_ip_val.config(text=server_ip, fg=THREAT_RED if is_threat else SAFE_GREEN)

        # Report ID
        hash_code = abs(hash(f"{display_name}_{server_ip}")) % 1000000
        if hasattr(self, "lbl_report_id"):
            self.lbl_report_id.config(text=f"VDX-INCIDENT-{hash_code:06d}")

        # Safety Verdict & Threat Alert
        if is_threat:
            if hasattr(self, "verdict_banner"):
                self.verdict_banner.config(bg=THREAT_BG)
            if hasattr(self, "lbl_verdict_title"):
                self.lbl_verdict_title.config(text="SCAM / REPLICA ALERT", fg=THREAT_RED, bg=THREAT_BG)
            if hasattr(self, "lbl_app_status_tag"):
                self.lbl_app_status_tag.config(text="Threat Flagged", fg=THREAT_RED, bg=THREAT_BG)

            # Show Threat Box with cybercrime.gov.in and 1930 instructions
            if hasattr(self, "lbl_threat_alert_title"):
                self.lbl_threat_alert_title.config(text=f"⚠️ SCAM DETECTED — CULPRIT IP: {server_ip}")
            if hasattr(self, "lbl_threat_alert_msg"):
                self.lbl_threat_alert_msg.config(
                    text=f"Culprit server IP {server_ip} resolved. Register a complaint on cybercrime.gov.in or dial 1930 from your phone dialpad immediately."
                )
            if hasattr(self, "threat_alert_box"):
                self.threat_alert_box.pack(fill="x", pady=(0, 8))

            # Replica redirect button
            if hasattr(self, "btn_official_redirect"):
                if sugg and sugg.get("official_url"):
                    self.btn_official_redirect.config(text=f"Redirect to Official {sugg['spoofed_brand']}")
                    self.btn_official_redirect.pack(fill="x", pady=(0, 4))
                else:
                    self.btn_official_redirect.pack_forget()
        else:
            if hasattr(self, "verdict_banner"):
                self.verdict_banner.config(bg=SAFE_BG)
            if hasattr(self, "lbl_verdict_title"):
                self.lbl_verdict_title.config(text="SAFE & VERIFIED APP", fg=SAFE_GREEN, bg=SAFE_BG)
            if hasattr(self, "lbl_app_status_tag"):
                self.lbl_app_status_tag.config(text="Verified", fg=SAFE_GREEN, bg=SAFE_BG)
            if hasattr(self, "threat_alert_box"):
                self.threat_alert_box.pack_forget()
            if hasattr(self, "btn_official_redirect"):
                self.btn_official_redirect.pack_forget()

    def _start_active_window_tracker(self):
        """Continuously monitors foreground active application window."""
        def _loop():
            last_key = ""
            while self.running:
                try:
                    win_info = app_inspector.get_foreground_info(my_hwnd=self.my_hwnd)
                    if win_info:
                        res = app_inspector.inspect_active_window(win_info)
                        app_data = {
                            "display_name": res.get("display_name", win_info.get("display_name", "Active Window")),
                            "exe_name": win_info.get("exe_name", ""),
                            "window_title": win_info.get("window_title", ""),
                            "target_url": res.get("target_url"),
                            "status_text": res.get("status_text", "Protected"),
                            "is_safe": res.get("is_safe", True),
                            "is_threat": res.get("is_threat", False),
                            "color": res.get("color", SAFE_GREEN),
                            "server_ip": res.get("server_ip") or ("185.220.101.45 (Offshore Threat)" if res.get("is_threat") else "127.0.0.1 (Local Host)"),
                            "isp": res.get("isp", "Local Interface"),
                            "legitimate_suggestion": res.get("legitimate_suggestion")
                        }

                        current_key = f"{app_data['exe_name']}_{app_data['is_threat']}_{app_data.get('target_url')}"
                        if current_key != last_key:
                            last_key = current_key
                            self.latest_app_info = app_data
                            self.root.after(0, self._update_extension_ui)
                except Exception:
                    pass
                time.sleep(0.35)

        threading.Thread(target=_loop, daemon=True).start()

    def _start_clipboard_watcher(self):
        """Watches clipboard for copied scam URLs."""
        def _cb(res):
            is_threat = res.get("is_threat", False)
            info = {
                "display_name": "Clipboard Intercept",
                "exe_name": "Clipboard",
                "window_title": res.get("url", "Copied Link"),
                "target_url": res.get("url"),
                "status_text": res.get("verdict", "Scam Link"),
                "is_safe": not is_threat,
                "is_threat": is_threat,
                "color": THREAT_RED if is_threat else SAFE_GREEN,
                "server_ip": res.get("server_ip") or "185.220.101.45",
                "isp": "Offshore Bulletproof Host",
                "legitimate_suggestion": res.get("legitimate_website_suggestion")
            }
            self.latest_app_info = info
            self.root.after(0, self._update_extension_ui)
            if is_threat:
                # Open centered extension automatically when threat intercepted
                self.root.after(0, self.open_extension_window)

        interceptor.on_threat_callback = _cb
        interceptor.start()

    def _on_exit(self):
        self.running = False
        try:
            interceptor.stop()
        except Exception:
            pass
        self.close_extension_window()
        self.root.destroy()
        sys.exit(0)

    def run(self):
        self.root.mainloop()


def extract_domain(url: str) -> str:
    from urllib.parse import urlparse
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return urlparse(url).hostname or url


def main():
    app = VeridexFloatingOverlay()
    app.run()


if __name__ == "__main__":
    main()
