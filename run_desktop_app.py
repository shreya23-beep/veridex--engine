"""
VeriDex AI - Launcher for Native Windows Desktop GUI
Starts the native Windows GUI client with real-time clipboard inspection.
"""

import sys
import os
import tkinter as tk

sys.path.insert(0, os.path.dirname(__file__))

from ui.desktop_app import VeridexDesktopApp

def main():
    root = tk.Tk()
    app = VeridexDesktopApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
