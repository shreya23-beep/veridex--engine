"""
VeriDex AI - Standalone CSV Dataset Scam Scanner Runner
Executes batch on-device scam detection across all rows in a CSV file
and produces an enriched security audit report with risk scores and categories.
"""

import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

from core.csv_detector import scan_csv_dataset, DEFAULT_CSV_PATH

def main():
    target_csv = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_CSV_PATH
    print("=" * 70)
    print("VERIDEX AI — CSV DATASET SCAM DETECTION RUNNER")
    print("=" * 70)
    print(f"Target CSV File: {target_csv}")
    print("Analyzing all rows on-device with zero-cloud inference...\n")

    summary = scan_csv_dataset(csv_path=target_csv, save_output=True)

    print("-" * 70)
    print("SCAM DETECTION RESULTS PREVIEW (First 15 Rows):")
    print("-" * 70)
    for r in summary["all_results"][:15]:
        verdict_str = "[SCAM]" if r["is_scam"] else "[SAFE]"
        print(f"[{r['row_index']:02d}] {verdict_str:8} | Risk: {r['risk_score']:5.1f}% | {r['type_badge']:16} | {r['url'][:42]}")

    print("-" * 70)
    print("BATCH SUMMARY METRICS:")
    print(f"  • Total URLs Scanned:  {summary['total_scanned']}")
    print(f"  • Threats / Scams:     {summary['threats_found']}")
    print(f"  • Safe Links:          {summary['safe_found']}")
    print(f"  • Threat Ratio:        {summary['threat_ratio_percent']}%")
    print(f"  • Enriched CSV Report: {summary['output_csv_path']}")
    print("=" * 70)

if __name__ == "__main__":
    main()
