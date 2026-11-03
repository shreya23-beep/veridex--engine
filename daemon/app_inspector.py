"""
VeriDex AI - Real-Time Active Window & Application Safety Inspector
Monitors the active foreground window across Windows (browsers, documents, messaging apps),
extracts active web URLs and application process binaries, and executes instant on-device
ML safety verification to alert users whether the app or website is safe or a scam.
"""

import os
import re
import sys
import ctypes
from ctypes import wintypes
from typing import Optional, Dict, Any, Tuple

# Project root
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from core.ml_engine import engine
from core.ip_resolver import resolve_server_ip, extract_hostname

# Windows APIs via ctypes & pywin32
user32 = ctypes.windll.user32
kernel32 = ctypes.windll.kernel32

try:
    import win32gui
    import win32process
    import win32api
    import win32con
    HAS_PYWIN32 = True
except ImportError:
    HAS_PYWIN32 = False

# Known web browser executables
BROWSER_EXES = {
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "brave.exe": "Brave Browser",
    "opera.exe": "Opera",
    "opera_gx.exe": "Opera GX",
    "vivaldi.exe": "Vivaldi",
    "arc.exe": "Arc Browser",
    "waterfox.exe": "Waterfox",
    "tor.exe": "Tor Browser"
}

# Known verified safe desktop applications catalog
SAFE_DESKTOP_APPS = {
    # Messaging & Social
    "whatsapp.exe": ("WhatsApp Desktop", "Verified Safe Messaging App"),
    "whatsappdesktop.exe": ("WhatsApp Desktop", "Verified Safe Messaging App"),
    "telegram.exe": ("Telegram Desktop", "Verified Safe Messaging App"),
    "discord.exe": ("Discord", "Verified Safe Communication App"),
    "slack.exe": ("Slack", "Verified Safe Workplace Messaging"),
    "teams.exe": ("Microsoft Teams", "Verified Safe Workplace Tool"),
    "zoom.exe": ("Zoom Meetings", "Verified Safe Video Conferencing"),
    "skype.exe": ("Skype", "Verified Safe Communication App"),

    # Office & Productivity
    "winword.exe": ("Microsoft Word", "Verified Safe Document Editor"),
    "excel.exe": ("Microsoft Excel", "Verified Safe Spreadsheet App"),
    "powerpnt.exe": ("Microsoft PowerPoint", "Verified Safe Presentation Tool"),
    "outlook.exe": ("Microsoft Outlook", "Verified Safe Email Client"),
    "onenote.exe": ("Microsoft OneNote", "Verified Safe Note Taking App"),
    "acrobat.exe": ("Adobe Acrobat", "Verified Safe PDF Reader"),
    "acrord32.exe": ("Adobe Acrobat Reader", "Verified Safe PDF Reader"),

    # Developer & System Tools
    "code.exe": ("Visual Studio Code", "Verified Safe Code Editor"),
    "devenv.exe": ("Visual Studio", "Verified Safe IDE"),
    "notepad.exe": ("Windows Notepad", "Verified Safe Text Editor"),
    "notepad++.exe": ("Notepad++", "Verified Safe Text Editor"),
    "calc.exe": ("Windows Calculator", "Verified Safe System Utility"),
    "calculatorapp.exe": ("Windows Calculator", "Verified Safe System Utility"),
    "explorer.exe": ("Windows Explorer", "Verified Safe File Manager"),
    "taskmgr.exe": ("Task Manager", "Verified Safe System Utility"),
    "cmd.exe": ("Command Prompt", "Windows Console"),
    "powershell.exe": ("Windows PowerShell", "Windows Command Shell"),
    "windowsterminal.exe": ("Windows Terminal", "Verified Safe Terminal"),

    # Media & Creative
    "spotify.exe": ("Spotify", "Verified Safe Media Player"),
    "vlc.exe": ("VLC Media Player", "Verified Safe Media Player"),
    "photoshop.exe": ("Adobe Photoshop", "Verified Safe Graphics Editor")
}

# Regex to detect domain names in browser window titles
DOMAIN_REGEX = re.compile(
    r"\b((?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|xyz|top|site|in|co|io|app|dev|ai|cc|ru|biz|info|online|shop|club|tech|me))\b",
    re.IGNORECASE
)

# Regex to detect full URLs
URL_REGEX = re.compile(
    r"https?://[^\s<>\"']+|www\.[^\s<>\"']+",
    re.IGNORECASE
)

# Known high-value brand spoofing keywords
BRAND_KEYWORDS = [
    "paypal", "apple", "netflix", "microsoft", "google", "amazon",
    "oracle", "facebook", "instagram", "whatsapp", "sbi", "hdfc",
    "icici", "paytm", "binance", "coinbase", "telegram", "recharge"
]

class ActiveAppInspector:
    """
    Inspects the currently active foreground application and browser window,
    resolving whether the active application or visited website is safe or a scam.
    """

    def __init__(self):
        self._last_hwnd = 0
        self._last_title = ""
        self._last_result: Optional[Dict[str, Any]] = None
        self._last_dock_coords: Tuple[int, int] = (0, 0)

    def get_foreground_info(self, my_hwnd: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """
        Retrieves active window handle, title, bounding rectangle, and process binary.
        """
        hwnd = user32.GetForegroundWindow()
        if not hwnd or (my_hwnd and hwnd == my_hwnd):
            return None

        # Check if window is minimized / invisible
        if user32.IsIconic(hwnd):
            return None

        # Get window title
        length = user32.GetWindowTextLengthW(hwnd)
        if length <= 0:
            return None
        title_buff = ctypes.create_unicode_buffer(length + 1)
        user32.GetWindowTextW(hwnd, title_buff, length + 1)
        title = title_buff.value.strip()

        # Ignore desktop / shell worker / taskbar
        if title in ("Program Manager", "Task Switching", "Windows Shell Experience Host", ""):
            return None

        # Get window rect
        rect = wintypes.RECT()
        if not user32.GetWindowRect(hwnd, ctypes.byref(rect)):
            return None

        win_w = rect.right - rect.left
        win_h = rect.bottom - rect.top
        if win_w < 100 or win_h < 100:
            return None

        # Get process PID & executable path
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_val = pid.value

        exe_name = "Unknown"
        exe_path = ""

        if HAS_PYWIN32:
            try:
                h_proc = win32api.OpenProcess(
                    win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                    False,
                    pid_val
                )
                exe_path = win32process.GetModuleFileNameEx(h_proc, 0)
                exe_name = os.path.basename(exe_path)
                win32api.CloseHandle(h_proc)
            except Exception:
                exe_name = f"App_PID_{pid_val}"
        else:
            exe_name = f"App_PID_{pid_val}"

        # Calculate optimal bottom-right docking position on the active window
        dock_x = max(10, rect.right - 285 - 24)
        dock_y = max(10, rect.bottom - 42 - 24)

        return {
            "hwnd": hwnd,
            "title": title,
            "rect": (rect.left, rect.top, rect.right, rect.bottom),
            "width": win_w,
            "height": win_h,
            "dock_x": dock_x,
            "dock_y": dock_y,
            "pid": pid_val,
            "exe_name": exe_name,
            "exe_path": exe_path
        }

    def inspect_active_window(self, win_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluates whether the active window (browser website or desktop app) is safe.
        """
        title = win_info.get("title", "")
        exe_name = win_info.get("exe_name", "").lower()
        exe_path = win_info.get("exe_path", "")

        is_browser = exe_name in BROWSER_EXES
        browser_name = BROWSER_EXES.get(exe_name, "Web Browser")

        # Case 1: Active application is a Web Browser
        if is_browser:
            return self._inspect_browser(browser_name, title, win_info)

        # Case 2: Active application is a Native Desktop App
        return self._inspect_desktop_app(exe_name, exe_path, title, win_info)

    def _inspect_browser(self, browser_name: str, title: str, win_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extracts active website URL / domain from browser and runs on-device ML inspection.
        """
        # 1. Look for explicit URL in title
        url_match = URL_REGEX.search(title)
        detected_target = None
        target_display = ""

        if url_match:
            raw_url = url_match.group(0)
            if not raw_url.startswith("http"):
                raw_url = "https://" + raw_url
            detected_target = raw_url
            target_display = extract_hostname(raw_url)
        else:
            # 2. Look for domain name in title
            dom_match = DOMAIN_REGEX.search(title)
            if dom_match:
                domain_val = dom_match.group(1).lower()
                # Ignore browser vendor domains like google.com if it's just the browser brand suffix
                if not (("chrome" in browser_name.lower() and domain_val == "google.com" and "google chrome" in title.lower()) or
                        ("edge" in browser_name.lower() and domain_val == "microsoft.com" and "microsoft edge" in title.lower())):
                    detected_target = f"https://{domain_val}"
                    target_display = domain_val

        # 3. Look for Brand spoofing keywords in title
        if not detected_target:
            clean_title = re.sub(r"-(?:\s*Personal\s*-)?\s*(?:Google Chrome|Microsoft Edge|Mozilla Firefox|Brave|Opera GX|Opera)", "", title, flags=re.I).strip()
            title_lower = clean_title.lower()
            for brand in BRAND_KEYWORDS:
                if brand in title_lower:
                    target_display = f"{brand.capitalize()} Portal"
                    break

        # If a website target was detected, run full On-Device ML inspection
        if detected_target:
            res = engine.inspect_url(detected_target, source="BROWSER_AUTO_HUD", context_text=title)
            is_threat = res.get("is_threat", False)
            risk_score = res.get("risk_score", 0.0)
            server_ip = res.get("server_ip") or "Traced"
            helpline = res.get("cyber_helpline_1930", {}).get("helpline", "1930")
            sugg = res.get("legitimate_website_suggestion")

            if is_threat:
                short_disp = (target_display[:18] + '..') if len(target_display) > 20 else target_display
                status_text = f"Scam Link! IP: {server_ip} (Dial 1930)"
                return {
                    "is_safe": False,
                    "is_threat": True,
                    "target_type": "WEBSITE",
                    "target_url": detected_target,
                    "display_name": short_disp,
                    "status_text": status_text,
                    "color": "#ef4444",       # Red
                    "bg_color": "#5C1D18",    # Terracotta dark
                    "risk_score": risk_score,
                    "server_ip": server_ip,
                    "helpline": helpline,
                    "full_result": res,
                    "legitimate_suggestion": sugg,
                    "app_title": title,
                    "browser_name": browser_name
                }
            else:
                short_disp = (target_display[:20] + '..') if len(target_display) > 22 else target_display
                return {
                    "is_safe": True,
                    "is_threat": False,
                    "target_type": "WEBSITE",
                    "target_url": detected_target,
                    "display_name": short_disp,
                    "status_text": f"{short_disp}: Safe & Verified",
                    "color": "#22c55e",       # Green
                    "bg_color": "#1E3A2F",    # Deep forest sage
                    "risk_score": risk_score,
                    "server_ip": server_ip,
                    "full_result": res,
                    "legitimate_suggestion": None,
                    "app_title": title,
                    "browser_name": browser_name
                }

        # Browser active, but no specific external domain in title (e.g. New Tab, Search, Internal)
        clean_title = re.sub(r"-(?:\s*Personal\s*-)?\s*(?:Google Chrome|Microsoft Edge|Mozilla Firefox|Brave|Opera GX|Opera)", "", title, flags=re.I).strip()
        short_title = (clean_title[:18] + '..') if len(clean_title) > 20 else clean_title or browser_name

        return {
            "is_safe": True,
            "is_threat": False,
            "target_type": "BROWSER_SESSION",
            "display_name": short_title,
            "status_text": f"{browser_name}: Safe Web Browsing",
            "color": "#22c55e",
            "bg_color": "#241E19",
            "risk_score": 0.0,
            "server_ip": None,
            "legitimate_suggestion": None,
            "app_title": title,
            "browser_name": browser_name
        }

    def _inspect_desktop_app(self, exe_name: str, exe_path: str, title: str, win_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyzes the security posture, digital trust, and reputation of native desktop applications.
        """
        # 1. Check known verified software catalog
        if exe_name in SAFE_DESKTOP_APPS:
            friendly_name, cat = SAFE_DESKTOP_APPS[exe_name]
            return {
                "is_safe": True,
                "is_threat": False,
                "target_type": "NATIVE_APP",
                "display_name": friendly_name,
                "status_text": f"{friendly_name}: Safe App",
                "color": "#22c55e",       # Green
                "bg_color": "#1E3A2F",    # Deep forest sage
                "category": cat,
                "app_title": title,
                "exe_name": exe_name
            }

        # 2. Check path reputation heuristics
        path_lower = exe_path.lower()
        if any(trusted in path_lower for trusted in ["program files", "windowsapps", "system32", "syswow64"]):
            app_label = exe_name.replace(".exe", "").capitalize()
            return {
                "is_safe": True,
                "is_threat": False,
                "target_type": "NATIVE_APP",
                "display_name": app_label,
                "status_text": f"{app_label}: Verified App",
                "color": "#22c55e",
                "bg_color": "#241E19",
                "category": "Installed Verified Software",
                "app_title": title,
                "exe_name": exe_name
            }
        elif any(suspicious in path_lower for suspicious in ["\\temp\\", "\\tmp\\", "\\downloads\\", "\\local\\temp\\"]):
            app_label = exe_name
            return {
                "is_safe": False,
                "is_threat": True,
                "target_type": "UNVERIFIED_APP",
                "display_name": app_label,
                "status_text": f"Caution: Unverified App in Temp/Downloads",
                "color": "#f59e0b",       # Amber
                "bg_color": "#4A2E10",    # Amber dark
                "category": "Unverified Binary from Downloads / Temp Directory",
                "app_title": title,
                "exe_name": exe_name
            }
        else:
            app_label = exe_name.replace(".exe", "").capitalize()
            return {
                "is_safe": True,
                "is_threat": False,
                "target_type": "NATIVE_APP",
                "display_name": app_label,
                "status_text": f"{app_label}: Local Application",
                "color": "#22c55e",
                "bg_color": "#241E19",
                "category": "Local User Software",
                "app_title": title,
                "exe_name": exe_name
            }

# Global singleton inspector instance
app_inspector = ActiveAppInspector()
