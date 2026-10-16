"""
VeriDex AI - Local Encrypted Threat Database
Manages SQLite storage for threat telemetry, user whitelists, and scan audits
with AES-256 encrypted fields for zero-cloud privacy compliance.
"""

import os
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Any, Optional
from .crypto_vault import vault_crypto

DB_FILE_NAME = "veridex_vault.db"

class ThreatDatabase:
    """
    On-device encrypted database for threat logs and security policies.
    """

    def __init__(self, data_dir: str = None):
        if data_dir is None:
            data_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data")
        os.makedirs(data_dir, exist_ok=True)
        self.db_path = os.path.join(data_dir, DB_FILE_NAME)
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        """Creates schemas for audit logs, policies, and metrics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Encrypted Threat Vault Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                url_hash TEXT NOT NULL,
                encrypted_url TEXT NOT NULL,
                verdict TEXT NOT NULL,
                risk_score REAL NOT NULL,
                latency_ms REAL NOT NULL,
                is_threat INTEGER NOT NULL,
                risk_factors_json TEXT NOT NULL,
                typosquat_brand TEXT,
                source TEXT DEFAULT 'MANUAL'
            );
            """)

            # Custom Local Whitelist (Trusted domains)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_whitelist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                notes TEXT
            );
            """)

            # Custom Local Blacklist (Immediate Block)
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                pattern TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                notes TEXT
            );
            """)

            conn.commit()

    def log_scan(self, inspection_result: Dict[str, Any], source: str = "MANUAL") -> int:
        """
        Stores scan results in the vault. Encrypts the URL using AES-256.
        """
        raw_url = inspection_result.get("url", "")
        url_hash = vault_crypto.hash_identifier(raw_url)
        encrypted_url = vault_crypto.encrypt(raw_url)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        typosquat_brand = None
        typo_details = inspection_result.get("typosquat_details", {})
        if typo_details and typo_details.get("is_typosquat"):
            typosquat_brand = typo_details.get("spoofed_brand")

        factors_json = json.dumps(inspection_result.get("risk_factors", []))

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            INSERT INTO threat_logs (
                timestamp, url_hash, encrypted_url, verdict, risk_score,
                latency_ms, is_threat, risk_factors_json, typosquat_brand, source
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                timestamp,
                url_hash,
                encrypted_url,
                inspection_result.get("verdict", "UNKNOWN"),
                inspection_result.get("risk_score", 0.0),
                inspection_result.get("latency_ms", 0.0),
                1 if inspection_result.get("is_threat") else 0,
                factors_json,
                typosquat_brand,
                source
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_scans(self, limit: int = 50) -> List[Dict[str, Any]]:
        """
        Retrieves recent scan logs, decrypting the URL locally in memory.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
            SELECT id, timestamp, encrypted_url, verdict, risk_score,
                   latency_ms, is_threat, risk_factors_json, typosquat_brand, source
            FROM threat_logs
            ORDER BY id DESC
            LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()

        results = []
        for r in rows:
            decrypted_url = vault_crypto.decrypt(r[2])
            factors = []
            try:
                factors = json.loads(r[7])
            except Exception:
                pass

            results.append({
                "id": r[0],
                "timestamp": r[1],
                "url": decrypted_url,
                "verdict": r[3],
                "risk_score": r[4],
                "latency_ms": r[5],
                "is_threat": bool(r[6]),
                "risk_factors": factors,
                "typosquat_brand": r[8],
                "source": r[9]
            })
        return results

    def get_vault_statistics(self) -> Dict[str, Any]:
        """Calculates dashboard summary metrics."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM threat_logs")
            total_scans = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_logs WHERE is_threat = 1")
            threats_blocked = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_logs WHERE typosquat_brand IS NOT NULL")
            typosquats_detected = cursor.fetchone()[0]

            cursor.execute("SELECT AVG(latency_ms) FROM threat_logs")
            avg_latency = cursor.fetchone()[0] or 0.0

            cursor.execute("SELECT COUNT(*) FROM user_whitelist")
            whitelist_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM user_blacklist")
            blacklist_count = cursor.fetchone()[0]

        return {
            "total_scans": total_scans,
            "threats_blocked": threats_blocked,
            "typosquats_detected": typosquats_detected,
            "avg_latency_ms": round(float(avg_latency), 2),
            "whitelist_count": whitelist_count,
            "blacklist_count": blacklist_count,
            "privacy_mode": "100% On-Device DPAPI / AES-256 Vault"
        }

    def add_whitelist(self, domain: str, notes: str = "") -> bool:
        """Adds trusted domain to on-device whitelist."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO user_whitelist (domain, added_at, notes) VALUES (?, ?, ?)",
                    (domain.lower().strip(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), notes)
                )
                conn.commit()
                return True
        except Exception:
            return False

    def add_blacklist(self, pattern: str, notes: str = "") -> bool:
        """Adds custom threat signature to on-device blacklist."""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT OR REPLACE INTO user_blacklist (pattern, added_at, notes) VALUES (?, ?, ?)",
                    (pattern.lower().strip(), datetime.now().strftime("%Y-%m-%d %H:%M:%S"), notes)
                )
                conn.commit()
                return True
        except Exception:
            return False

    def get_whitelist(self) -> List[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT domain FROM user_whitelist")
            return [r[0] for r in cursor.fetchall()]

    def get_blacklist(self) -> List[str]:
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT pattern FROM user_blacklist")
            return [r[0] for r in cursor.fetchall()]

    def clear_vault(self):
        """Clears threat logs."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM threat_logs")
            conn.commit()

threat_db = ThreatDatabase()
