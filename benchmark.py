"""
VeriDex AI - On-Device Latency & Hardware Benchmark
Measures on-device inference speed across diverse URL structures.
"""

import sys
import os
import time
import numpy as np

sys.path.insert(0, os.path.dirname(__file__))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.ml_engine import engine

BENCHMARK_URLS = [
    "https://www.google.com/search?q=cybersecurity+defense",
    "http://paypa1-security-verification.com/login.php?user=alert",
    "https://github.com/torvalds/linux/commit/8f2c",
    "http://192.168.1.105/bankofamerica/secure-auth.html",
    "http://appleid-verify-locked-account.support.xyz/auth",
    "http://binance-airdrop-free-tokens.buzz/claim?wallet=crypto",
    "https://en.wikipedia.org/wiki/Phishing",
    "http://chase-bank-customer-support-update.top/account/verify"
]

def run_performance_test(iterations: int = 200):
    print("=" * 65)
    print("VERIDEX AI — ON-DEVICE HARDWARE INFERENCE BENCHMARK")
    print("=" * 65)
    print(f"Backend Engine:   {engine.model_type}")
    print(f"Total Iterations: {iterations}")
    print("Warm-up phase...")

    # Warm-up
    for u in BENCHMARK_URLS:
        engine.inspect_url(u)

    print("Executing benchmark runs...")
    latencies = []
    for _ in range(iterations // len(BENCHMARK_URLS)):
        for u in BENCHMARK_URLS:
            t0 = time.perf_counter()
            engine.inspect_url(u)
            latencies.append((time.perf_counter() - t0) * 1000)

    latencies = np.array(latencies)
    print("\n--- RESULTS ---")
    print(f"  • Min Latency:    {np.min(latencies):.3f} ms")
    print(f"  • Average Latency:{np.mean(latencies):.3f} ms")
    print(f"  • Median (p50):   {np.median(latencies):.3f} ms")
    print(f"  • 95th Percentile:{np.percentile(latencies, 95):.3f} ms")
    print(f"  • 99th Percentile:{np.percentile(latencies, 99):.3f} ms")
    print(f"  • Max Latency:    {np.max(latencies):.3f} ms")
    print(f"  • Throughput:     {1000 / np.mean(latencies):.0f} URLs / second on single core")
    print("=" * 65)

if __name__ == "__main__":
    run_performance_test()
