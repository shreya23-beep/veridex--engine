"""
VeriDex AI - Launcher for Always-On-Top Universal Desktop Floating Widget
Keeps the VeriDex AI logo and real-time scam protection status visible
on top of every opened application on Windows (browsers, documents, messengers, etc.).
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from ui.floating_overlay import VeridexFloatingOverlay

def main():
    print("=" * 65)
    print("VERIDEX AI — UNIVERSAL DESKTOP ACTIVE WINDOW INSPECTOR")
    print("=" * 65)
    print("Mode:         Always-On-Top Auto-Docking Protection Badge")
    print("Logo:         VeriDex AI Geometric Monogram Brandmark ('V')")
    print("Behavior:     Appears on every application window you open")
    print("Inspection:   • Website URLs (Safe vs Scam / Phishing)")
    print("              • Desktop Applications (Safe vs Unverified)")
    print("              • WhatsApp Scam Link & Culprit IP Tracing")
    print("              • National Cyber Security Helpline 1930")
    print("Controls:     • Drag pill to reposition anywhere")
    print("              • Double-click to open Web Cyber-Dashboard")
    print("              • Right-click for quick settings & exit")
    print("=" * 65)
    app = VeridexFloatingOverlay()
    app.run()

if __name__ == "__main__":
    main()
