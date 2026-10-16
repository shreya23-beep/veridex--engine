"""
VeriDex AI - Standalone Background Interceptor Daemon
Continuously monitors system clipboard for copied links,
inspects them on-device within < 1ms, and alerts on threats.
"""

import sys
import os
import time

sys.path.insert(0, os.path.dirname(__file__))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from daemon.clipboard_watcher import interceptor

def main():
    print("=" * 65)
    print("VERIDEX AI — BACKGROUND CLIPBOARD INTERCEPTOR ACTIVE")
    print("=" * 65)
    print("Watching clipboard for copied links... (Press Ctrl+C to terminate)")
    interceptor.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping interceptor...")
        interceptor.stop()
        print("VeriDex Interceptor stopped safely.")

if __name__ == "__main__":
    main()
