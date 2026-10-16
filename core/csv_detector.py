"""
VeriDex AI - CSV Batch Scam Detection & Dataset Processor
Reads URLs and feature sets from CSV files, executes high-speed on-device
ML inference across all rows, and outputs enriched security audit records.
"""

import os
import csv
from typing import List, Dict, Any, Optional
from core.ml_engine import engine
from security.threat_db import threat_db

DEFAULT_CSV_PATH = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "veridex_dataset.csv"
)

def scan_csv_dataset(csv_path: str = DEFAULT_CSV_PATH, save_output: bool = True) -> Dict[str, Any]:
    """
    Reads a CSV dataset, executes on-device scam detection on every URL/row,
    and returns comprehensive metrics and row-level verdicts.
    """
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f"CSV dataset not found at: {csv_path}")

    results = []
    total_scanned = 0
    threats_found = 0
    safe_found = 0

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader):
            url = row.get("url", "").strip()
            if not url:
                continue

            # Run on-device inspection
            res = engine.inspect_url(url)
            total_scanned += 1

            is_scam = res["is_threat"]
            if is_scam:
                threats_found += 1
            else:
                safe_found += 1

            # Log to local encrypted vault
            threat_db.log_scan(res, source="CSV_BATCH_SCAN")

            sugg = res.get("legitimate_website_suggestion")
            official_url = sugg.get("official_url", "") if sugg else ""

            results.append({
                "row_index": idx + 1,
                "url": url,
                "verdict": res["verdict"],
                "risk_score": res["risk_score"],
                "is_scam": is_scam,
                "category": res.get("classification", {}).get("category", "General Web"),
                "type_badge": res.get("classification", {}).get("type_badge", "WEB"),
                "suggested_official_url": official_url,
                "latency_ms": res["latency_ms"],
                "risk_factors": res["risk_factors"]
            })

    output_csv_path = None
    if save_output:
        base_dir = os.path.dirname(csv_path)
        output_csv_path = os.path.join(base_dir, "veridex_scam_detection_results.csv")
        with open(output_csv_path, mode="w", newline="", encoding="utf-8") as out_f:
            writer = csv.writer(out_f)
            writer.writerow([
                "row_index", "url", "is_scam", "verdict", "risk_score",
                "category", "type_badge", "suggested_official_url", "latency_ms", "risk_factors"
            ])
            for r in results:
                writer.writerow([
                    r["row_index"], r["url"], "SCAM" if r["is_scam"] else "SAFE",
                    r["verdict"], f"{r['risk_score']}%", r["category"],
                    r["type_badge"], r["suggested_official_url"], f"{r['latency_ms']}ms",
                    " | ".join(r["risk_factors"][:2])
                ])

    return {
        "total_scanned": total_scanned,
        "threats_found": threats_found,
        "safe_found": safe_found,
        "threat_ratio_percent": round((threats_found / max(total_scanned, 1)) * 100, 2),
        "output_csv_path": output_csv_path,
        "sample_results": results[:20],
        "all_results": results
    }

if __name__ == "__main__":
    import json
    summary = scan_csv_dataset()
    print("=" * 65)
    print("VERIDEX AI — CSV SCAM DETECTION SUMMARY")
    print("=" * 65)
    print(f"Total Rows Scanned:  {summary['total_scanned']}")
    print(f"Scams / Threats:     {summary['threats_found']}")
    print(f"Safe Sites:          {summary['safe_found']}")
    print(f"Threat Ratio:        {summary['threat_ratio_percent']}%")
    print(f"Saved Output CSV to: {summary['output_csv_path']}")
    print("=" * 65)
