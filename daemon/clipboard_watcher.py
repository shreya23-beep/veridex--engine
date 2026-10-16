"""
VeriDex AI - Real-Time Clipboard & OS Event Interceptor
Monitors system clipboard for newly copied links in real-time,
executing instant on-device ML inspection and raising contextual alerts.
"""

import time
import re
import threading
from typing import Callable, Optional
from core.ml_engine import engine
from security.threat_db import threat_db

# Windows notification capability
HAS_NOTIFY = False
try:
    from win10toast import ToastNotifier
    toaster = ToastNotifier()
    HAS_NOTIFY = True
except Exception:
    HAS_NOTIFY = False

URL_REGEX = re.compile(
    r"^(?:http[s]?://|www\.)[^\s\"'<>]+",
    re.IGNORECASE
)

class ClipboardInterceptor:
    """
    Background daemon that hooks into clipboard events to inspect URLs silently.
    """

    def __init__(self, on_threat_callback: Optional[Callable] = None):
        self.running = False
        self.last_clipboard = ""
        self.on_threat_callback = on_threat_callback
        self.thread = None

    def _get_clipboard_text(self) -> str:
        """Reads current clipboard text safely using ctypes or win32."""
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                data = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT).decode("utf-8", errors="ignore")
            else:
                data = ""
            win32clipboard.CloseClipboard()
            return data.strip()
        except Exception:
            return ""

    def _notify_user(self, title: str, message: str):
        """Shows Windows notification or console alert."""
        print(f"\n[ALERT NOTIFICATION] {title}: {message}")
        if HAS_NOTIFY:
            try:
                toaster.show_toast(title, message, duration=5, threaded=True)
            except Exception:
                pass

    def check_text(self, text: str):
        """Inspects text if it matches a URL pattern."""
        if not text or text == self.last_clipboard:
            return
        self.last_clipboard = text

        match = URL_REGEX.match(text)
        if match:
            url = match.group(0)
            print(f"[INTERCEPTOR] New URL detected in clipboard: {url}")
            result = engine.inspect_url(url)
            
            # Record in vault
            threat_db.log_scan(result, source="CLIPBOARD_WATCHER")

            if result["is_threat"]:
                reasons = "; ".join(result["risk_factors"][:2])
                self._notify_user(
                    "VeriDex AI Scam Alert",
                    f"Warning! Copied link flagged as {result['verdict']}.\n{reasons}"
                )
                if self.on_threat_callback:
                    self.on_threat_callback(result)
            else:
                print(f"[INTERCEPTOR] URL verified safe ({result['latency_ms']} ms): {url}")

    def loop(self):
        """Main polling loop running in background."""
        print("[INTERCEPTOR] VeriDex Clipboard Interceptor active. Watching for copied URLs...")
        while self.running:
            try:
                text = self._get_clipboard_text()
                if text:
                    self.check_text(text)
            except Exception as e:
                pass
            time.sleep(0.5)

    def start(self):
        """Starts background interceptor thread."""
        if not self.running:
            self.running = True
            self.thread = threading.Thread(target=self.loop, daemon=True)
            self.thread.start()

    def stop(self):
        """Stops the interceptor."""
        self.running = False

interceptor = ClipboardInterceptor()
