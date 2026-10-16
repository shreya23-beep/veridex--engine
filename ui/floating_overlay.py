"""
VeriDex AI - Always-On-Top Universal Desktop Floating Widget
Floats seamlessly across EVERY opened application (Chrome, Edge, Word, WhatsApp, etc.),
displaying the official VeriDex AI 'V' logo and live on-device scam protection status.
"""

import sys
import os
import time
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk
from PIL import Image, ImageTk

# Include project root
ROOT_DIR = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, ROOT_DIR)

from core.ml_engine import engine
from daemon.clipboard_watcher import interceptor
from security.threat_db import threat_db

LOGO_PATH = os.path.join(ROOT_DIR, "ui", "web", "assets", "logo.png")

# Palette matching Crema Theme
BG_PILL_NORMAL = "#241E19"    # Rich espresso
BG_PILL_SAFE = "#1E3A2F"      # Deep forest sage
BG_PILL_THREAT = "#5C1D18"    # Deep terracotta crimson
TEXT_WHITE = "#FAF8F5"        # Warm cream white
ACCENT_GREEN = "#22c55e"      # Bright safe green
ACCENT_RED = "#ef4444"        # Bright threat red
ACCENT_AMBER = "#f59e0b"      # Amber scanning

class VeridexFloatingOverlay:
    """
    Frameless, always-on-top desktop overlay pill displaying the VeriDex AI logo
    and real-time protection state across all Windows applications.
    """

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("VeriDex AI Floating Companion")
        self.root.overrideredirect(True)          # Frameless
        self.root.attributes("-topmost", True)      # Always on top of EVERY application
        self.root.attributes("-alpha", 0.94)        # Sleek translucency
        self.root.config(bg="#000000")
        self.root.wm_attributes("-transparentcolor", "#000000") # Transparent corners

        # Dimensions & screen positioning
        self.width = 240
        self.height = 42
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        
        # Position at bottom-right corner, above Windows taskbar
        self.pos_x = screen_w - self.width - 24
        self.pos_y = screen_h - self.height - 65
        self.root.geometry(f"{self.width}x{self.height}+{self.pos_x}+{self.pos_y}")

        # Dragging state
        self._drag_start_x = 0
        self._drag_start_y = 0

        self.last_result = None
        self.reset_timer = None

        self._build_ui()
        self._bind_events()
        self._start_clipboard_watcher()

    def _build_ui(self):
        # Outer Pill Frame
        self.container = tk.Frame(
            self.root,
            bg=BG_PILL_NORMAL,
            highlightbackground="#8C6842",
            highlightthickness=1,
            cursor="hand2"
        )
        self.container.pack(fill="both", expand=True)

        # Load and resize official VeriDex 'V' Logo
        self.logo_img = None
        if os.path.exists(LOGO_PATH):
            try:
                pil_img = Image.open(LOGO_PATH).resize((26, 26), Image.Resampling.LANCZOS)
                self.logo_img = ImageTk.PhotoImage(pil_img)
            except Exception as e:
                print(f"[OVERLAY] Logo load error: {e}")

        # Content Layout
        self.content_frame = tk.Frame(self.container, bg=BG_PILL_NORMAL)
        self.content_frame.pack(fill="both", expand=True, padx=8, pady=4)

        # Logo Label
        if self.logo_img:
            self.logo_lbl = tk.Label(self.content_frame, image=self.logo_img, bg=BG_PILL_NORMAL)
            self.logo_lbl.pack(side="left", padx=(2, 6))
        else:
            self.logo_lbl = tk.Label(self.content_frame, text="V", font=("Arial", 12, "bold"), fg="#8C6842", bg=BG_PILL_NORMAL)
            self.logo_lbl.pack(side="left", padx=(2, 6))

        # Status Dot
        self.status_dot = tk.Label(self.content_frame, text="•", font=("Arial", 16, "bold"), fg=ACCENT_GREEN, bg=BG_PILL_NORMAL)
        self.status_dot.pack(side="left", padx=(0, 4))

        # Main Text
        self.status_text = tk.Label(
            self.content_frame,
            text="VeriDex AI: Protected",
            font=("Segoe UI", 9, "bold"),
            fg=TEXT_WHITE,
            bg=BG_PILL_NORMAL
        )
        self.status_text.pack(side="left", padx=2)

    def _bind_events(self):
        # Allow user to drag the pill anywhere on screen
        for widget in (self.root, self.container, self.content_frame, self.status_text, self.status_dot, self.logo_lbl):
            widget.bind("<Button-1>", self._on_drag_start)
            widget.bind("<B1-Motion>", self._on_drag_motion)
            widget.bind("<Double-Button-1>", self._open_web_dashboard)
            widget.bind("<Button-3>", self._show_context_menu)

        # Right click menu
        self.context_menu = tk.Menu(self.root, tearoff=0, font=("Segoe UI", 9))
        self.context_menu.add_command(label="Open Web Cyber-Dashboard", command=self._open_web_dashboard)
        self.context_menu.add_command(label="Scan Current Clipboard URL", command=self._scan_clipboard_now)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Reset Position to Bottom-Right", command=self._reset_position)
        self.context_menu.add_command(label="Exit VeriDex Overlay", command=self._on_exit)

    def _on_drag_start(self, event):
        self._drag_start_x = event.x
        self._drag_start_y = event.y

    def _on_drag_motion(self, event):
        x = self.root.winfo_x() + (event.x - self._drag_start_x)
        y = self.root.winfo_y() + (event.y - self._drag_start_y)
        self.root.geometry(f"+{x}+{y}")

    def _show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def _reset_position(self):
        screen_w = self.root.winfo_screenwidth()
        screen_h = self.root.winfo_screenheight()
        self.pos_x = screen_w - self.width - 24
        self.pos_y = screen_h - self.height - 65
        self.root.geometry(f"{self.width}x{self.height}+{self.pos_x}+{self.pos_y}")

    def _open_web_dashboard(self, event=None):
        webbrowser.open("http://127.0.0.1:8484")

    def _scan_clipboard_now(self):
        text = interceptor._get_clipboard_text()
        if text:
            interceptor.check_text(text)
        else:
            self.set_state("VeriDex AI: Clipboard Empty", color=ACCENT_AMBER, bg=BG_PILL_NORMAL, duration=2.5)

    def set_state(self, text: str, color: str = ACCENT_GREEN, bg: str = BG_PILL_NORMAL, duration: float = 0):
        def _update():
            self.status_text.config(text=text, bg=bg)
            self.status_dot.config(fg=color, bg=bg)
            self.logo_lbl.config(bg=bg)
            self.content_frame.config(bg=bg)
            self.container.config(bg=bg)

            # Auto revert to default state
            if duration > 0:
                if self.reset_timer:
                    self.reset_timer.cancel()
                self.reset_timer = threading.Timer(duration, lambda: self.root.after(0, self._set_default_state))
                self.reset_timer.start()

        self.root.after(0, _update)

    def _set_default_state(self):
        self.set_state("VeriDex AI: Protected", color=ACCENT_GREEN, bg=BG_PILL_NORMAL)

    def _on_threat_detected(self, result: dict):
        url = result.get("url", "")
        verdict = result.get("verdict", "THREAT DETECTED")
        spoofed = result.get("typosquat_details", {}).get("spoofed_brand") or ""
        suggestion = result.get("legitimate_website_suggestion")

        if suggestion:
            label = f"VeriDex: Fake {suggestion['spoofed_brand']}!"
            bg = BG_PILL_THREAT
            self.set_state(label, color=ACCENT_RED, bg=bg, duration=10.0)
            self._show_threat_popup(result)
        elif result.get("is_threat"):
            self.set_state("VeriDex AI: Phishing Scam!", color=ACCENT_RED, bg=BG_PILL_THREAT, duration=8.0)
            self._show_threat_popup(result)
        else:
            self.set_state("VeriDex AI: Safe & Verified", color=ACCENT_GREEN, bg=BG_PILL_SAFE, duration=3.5)

    def _show_threat_popup(self, result: dict):
        def _popup():
            top = tk.Toplevel(self.root)
            top.title("VeriDex AI — Threat Intercepted")
            top.attributes("-topmost", True)
            top.geometry("440x260")
            top.config(bg="#FAF8F5")
            top.resizable(False, False)

            # Center popup near widget
            x = max(100, self.root.winfo_x() - 100)
            y = max(100, self.root.winfo_y() - 280)
            top.geometry(f"+{x}+{y}")

            pad = tk.Frame(top, bg="#FAF8F5", padx=16, pady=14)
            pad.pack(fill="both", expand=True)

            tk.Label(pad, text="SECURITY THREAT BLOCKED", font=("Segoe UI", 11, "bold"), fg="#C53929", bg="#FAF8F5").pack(anchor="w")
            tk.Label(pad, text=f"Target: {result.get('url')}", font=("Consolas", 9), fg="#241E19", bg="#FAF8F5", wraplength=400, justify="left").pack(anchor="w", pady=(4, 6))

            reasons = "; ".join(result.get("risk_factors", [])[:2])
            tk.Label(pad, text=reasons, font=("Segoe UI", 9), fg="#756A63", bg="#FAF8F5", wraplength=400, justify="left").pack(anchor="w", pady=(0, 10))

            btn_frame = tk.Frame(pad, bg="#FAF8F5")
            btn_frame.pack(fill="x", pady=8)

            sugg = result.get("legitimate_website_suggestion")
            if sugg and sugg.get("official_url"):
                tk.Button(
                    btn_frame,
                    text=f"Redirect to Official {sugg['spoofed_brand']}",
                    font=("Segoe UI", 9, "bold"),
                    bg="#241E19",
                    fg="#FFFFFF",
                    activebackground="#3C342C",
                    relief="flat",
                    padx=10,
                    pady=6,
                    command=lambda: [webbrowser.open(sugg['official_url']), top.destroy()]
                ).pack(side="left", padx=(0, 6))

            tk.Button(
                btn_frame,
                text="Dismiss",
                font=("Segoe UI", 9),
                bg="#EDE7DC",
                fg="#241E19",
                relief="flat",
                padx=10,
                pady=6,
                command=top.destroy
            ).pack(side="left")

        self.root.after(0, _popup)

    def _start_clipboard_watcher(self):
        # Hook clipboard interceptor callback
        def _cb(res):
            self._on_threat_detected(res)

        interceptor.on_threat_callback = _cb
        interceptor.start()

    def _on_exit(self):
        try:
            interceptor.stop()
        except Exception:
            pass
        self.root.destroy()
        sys.exit(0)

    def run(self):
        self.root.mainloop()

def main():
    app = VeridexFloatingOverlay()
    app.run()

if __name__ == "__main__":
    main()
