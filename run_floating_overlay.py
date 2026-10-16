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
    print("VERIDEX AI — UNIVERSAL DESKTOP FLOATING OVERLAY LAUNCHER")
    print("=" * 65)
    print("Mode:         Always-On-Top Floating Protection Pill")
    print("Logo:         VeriDex AI Geometric Monogram Brandmark")
    print("Coverage:     Floats seamlessly across ALL opened applications")
    print("Controls:     • Drag pill to reposition anywhere")
    print("              • Double-click to open Web Cyber-Dashboard")
    print("              • Right-click for quick actions & exit")
    print("=" * 65)
    app = VeridexFloatingOverlay()
    app.run()

if __name__ == "__main__":
    main()
