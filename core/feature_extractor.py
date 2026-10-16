"""
VeriDex AI - Universal URL Feature Extractor
Extracts 26 lexical, structural, statistical, behavioral, and risk features
from ANY arbitrary URL (blogs, educational sites, forums, news, e-commerce,
file downloads, generic portals, or brand impersonations) for zero-cloud ML inference.
"""

import math
import re
from urllib.parse import urlparse
from .typosquat_detector import analyze_typosquatting, extract_domain_parts

# High-abuse TLDs frequently used in automated disposable scam campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "ru", "cc", "buzz", "club", "tk", "ml",
    "ga", "cf", "gq", "click", "rest", "support", "monster", "icu",
    "cam", "fit", "surf", "live", "vip", "link", "shop", "kim",
    "loan", "racing", "science", "download", "stream", "cfd", "sbs"
}

# Trusted generic and high-reputation TLDs
TRUSTED_TLDS = {
    "com", "org", "net", "edu", "gov", "mil", "int", "ac.uk", "gov.in", "edu.in", "in", "us", "io", "tv", "co.in"
}

# Common URL Shorteners used to mask true destinations
SHORTENER_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.co", "cutt.ly", "is.gd", "rb.gy",
    "shorturl.at", "ow.ly", "buff.ly", "goo.gl", "tiny.cc", "bc.vc",
    "adf.ly", "clck.ru", "rebrand.ly", "snip.ly"
}

# Free dynamic DNS and tunneling hosts frequently abused for disposable phishing
FREE_HOSTING_OR_TUNNELS = {
    "ngrok.io", "duckdns.org", "000webhostapp.com", "glitch.me",
    "pages.dev", "firebaseapp.com", "weebly.com", "wixsite.com",
    "workers.dev", "azurewebsites.net", "herokuapp.com", "surge.sh",
    "netlify.app", "github.io"
}

# Generic authentication & credential harvesting keywords (no brand required)
AUTH_KEYWORDS = [
    "login", "signin", "sign-in", "auth", "portal", "verify", "verification",
    "account", "banking", "password", "reset-password", "session",
    "credentials", "confirm", "security-check", "authenticate", "unlock",
    "billing", "update-card", "re-activate", "identity"
]

# Generic scam, urgency, and financial lure keywords (no brand required)
SCAM_KEYWORDS = [
    "scam", "scams", "phish", "phishing", "fraud", "fake", "drainer", "stealer",
    "malware", "trojan", "ransomware", "spyware", "spoof", "free", "prize",
    "winner", "lottery", "airdrop", "claim", "reward", "bonus", "urgent",
    "suspended", "frozen", "legal-notice", "gift-card", "crypto-giveaway",
    "hack", "exploit", "unlimited", "cash-bonus", "congratulations",
    "wallet-seed", "survey-reward", "payout"
]

# Explicit threat indicators inside hostname/domain
BLATANT_THREAT_KEYWORDS = [
    "scam", "phish", "phishing", "fraud", "drainer", "stealer",
    "malware", "trojan", "ransomware", "fake-login", "stealer"
]

# Executable or dangerous payload extensions
EXECUTABLE_EXTENSIONS = [
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".msi", ".iso", ".apk",
    ".dmg", ".jar", ".ps1", ".hta", ".wsf", ".pif"
]

FEATURE_COLUMNS = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "subdomain_count",
    "entropy_domain",
    "entropy_path",
    "count_digits_domain",
    "ratio_digits_domain",
    "count_hyphens_domain",
    "count_dots_url",
    "count_special_chars",
    "has_at_symbol",
    "has_double_slash",
    "has_ip_address",
    "is_https",
    "is_suspicious_tld",
    "is_trusted_tld",
    "auth_keyword_count",
    "scam_keyword_count",
    "typosquat_score",
    "is_punycode",
    "is_url_shortener",
    "has_executable_payload",
    "is_free_hosting_or_tunnel",
    "has_non_standard_port"
]

def shannon_entropy(data: str) -> float:
    """Calculates Shannon entropy to detect algorithmic randomness (DGA)."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    frequencies = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)

def is_ip_address(hostname: str) -> int:
    """Checks if hostname is an IPv4 or IPv6 address."""
    ipv4_pattern = r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
    return 1 if re.match(ipv4_pattern, hostname) else 0

def extract_features(url: str) -> dict:
    """
    Extracts 26 numerical features suitable for universal URL inspection.
    """
    raw_url = url.strip()
    if not raw_url.startswith(("http://", "https://")):
        processed_url = "http://" + raw_url
    else:
        processed_url = raw_url

    parsed = urlparse(processed_url)
    hostname = (parsed.hostname or parsed.netloc or "").lower()
    path = (parsed.path or "").lower()
    query = (parsed.query or "").lower()
    full_lower = raw_url.lower()

    domain_parts = extract_domain_parts(raw_url)
    domain_name = domain_parts["domain_name"]
    tld = domain_parts["tld"].lower()
    subdomains = domain_parts["subdomains"]

    # Typosquat analysis
    typosquat_info = analyze_typosquatting(raw_url)
    typosquat_score = typosquat_info["confidence"]

    # Digits, hyphens, dots
    digits_in_domain = sum(c.isdigit() for c in hostname)
    ratio_digits = round(digits_in_domain / max(len(hostname), 1), 4)
    hyphens_in_domain = hostname.count("-")
    dots_in_url = raw_url.count(".")

    # Special characters
    special_chars = sum(raw_url.count(c) for c in ['@', '?', '=', '&', '%', '$', '!', '~', '*', '+', ';'])
    has_at = 1 if "@" in raw_url else 0
    has_double_slash = 1 if "//" in path else 0
    is_ip = is_ip_address(hostname)
    is_https = 1 if raw_url.lower().startswith("https://") else 0

    # TLD checks
    is_suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0
    is_trusted_tld = 1 if (tld in TRUSTED_TLDS or any(t.endswith("." + tld) for t in TRUSTED_TLDS)) else 0

    # Generic Keyword Counts (No company name required)
    def _match_kw(kw: str, text: str) -> bool:
        if len(kw) <= 4:
            return bool(re.search(r'(^|[^a-z0-9])' + re.escape(kw) + r'([^a-z0-9]|$)', text))
        return kw in text

    auth_kw_count = sum(1 for kw in AUTH_KEYWORDS if _match_kw(kw, full_lower))
    scam_kw_count = sum(1 for kw in SCAM_KEYWORDS if _match_kw(kw, full_lower))

    # Shorteners & Free hosting / Reverse tunnels
    is_shortener = 1 if any(hostname == s or hostname.endswith("." + s) for s in SHORTENER_DOMAINS) else 0
    is_free_host = 1 if any(hostname.endswith(fh) for fh in FREE_HOSTING_OR_TUNNELS) else 0

    # Executable payload detection
    has_exec = 1 if any(path.endswith(ext) or (ext + "?" in raw_url) for ext in EXECUTABLE_EXTENSIONS) else 0

    # Non-standard port (e.g. :8080, :1337, :4444)
    has_custom_port = 0
    if parsed.port and parsed.port not in (80, 443):
        has_custom_port = 1

    # Entropies
    entropy_dom = shannon_entropy(hostname)
    entropy_pth = shannon_entropy(path)

    features = {
        "url_length": len(raw_url),
        "domain_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "subdomain_count": len(subdomains),
        "entropy_domain": entropy_dom,
        "entropy_path": entropy_pth,
        "count_digits_domain": digits_in_domain,
        "ratio_digits_domain": ratio_digits,
        "count_hyphens_domain": hyphens_in_domain,
        "count_dots_url": dots_in_url,
        "count_special_chars": special_chars,
        "has_at_symbol": has_at,
        "has_double_slash": has_double_slash,
        "has_ip_address": is_ip,
        "is_https": is_https,
        "is_suspicious_tld": is_suspicious_tld,
        "is_trusted_tld": is_trusted_tld,
        "auth_keyword_count": auth_kw_count,
        "scam_keyword_count": scam_kw_count,
        "typosquat_score": typosquat_score,
        "is_punycode": 1 if typosquat_info["is_punycode"] else 0,
        "is_url_shortener": is_shortener,
        "has_executable_payload": has_exec,
        "is_free_hosting_or_tunnel": is_free_host,
        "has_non_standard_port": has_custom_port
    }

    return features

def features_to_vector(features: dict) -> list:
    """Converts feature dict to ordered array for model ingestion."""
    return [features[col] for col in FEATURE_COLUMNS]

def classify_url_category(url: str, features: dict, typosquat: dict) -> dict:
    """
    Classifies the website category and architectural intent across any arbitrary URL.
    """
    parsed = urlparse("http://" + url if not url.startswith(("http://", "https://")) else url)
    hostname = (parsed.hostname or parsed.netloc or "").lower()
    path = (parsed.path or "").lower()

    # Blatant threat keywords check
    domain_part = hostname.split(".")[0] if "." in hostname else hostname
    matched_blatant = [kw for kw in BLATANT_THREAT_KEYWORDS if (kw in hostname or kw in domain_part)]
    if matched_blatant:
        return {
            "category": "Explicit Scam / Fraud Threat Domain",
            "type_badge": "SCAM_DOMAIN",
            "description": f"Domain explicitly identifies as or contains fraud/scam keyword ('{matched_blatant[0]}').",
            "risk_nature": "CONFIRMED_THREAT"
        }

    if typosquat.get("is_typosquat"):
        return {
            "category": "Brand Impersonation / Typosquatting",
            "type_badge": "IMPERSONATION",
            "description": f"URL attempts to spoof legitimate brand '{typosquat.get('spoofed_brand')}'.",
            "risk_nature": "PHISHING"
        }

    if features.get("has_executable_payload") == 1:
        return {
            "category": "Executable / Direct Binary Download",
            "type_badge": "PAYLOAD_DELIVERY",
            "description": "URL links directly to an executable binary (.exe, .bat, .apk, .msi, etc.).",
            "risk_nature": "MALWARE_RISK"
        }

    if features.get("has_ip_address") == 1:
        return {
            "category": "Bare IP Address Host",
            "type_badge": "RAW_IP",
            "description": "Site is hosted on a bare numeric IP without registered domain DNS.",
            "risk_nature": "SUSPICIOUS"
        }

    if features.get("is_url_shortener") == 1:
        return {
            "category": "URL Redirection Shortener",
            "type_badge": "SHORTENER",
            "description": "Obfuscates final landing destination using a public shortener.",
            "risk_nature": "REVIEW_DESTINATION"
        }

    if features.get("is_free_hosting_or_tunnel") == 1:
        return {
            "category": "Dynamic DNS / Tunnel Service",
            "type_badge": "TUNNEL_HOST",
            "description": "Hosted on free or tunnel infrastructure (e.g. ngrok, duckdns, glitch).",
            "risk_nature": "UNVERIFIED_HOST"
        }

    institutional_tlds = {"edu", "gov", "mil", "int", "ac.uk", "gov.in", "edu.in"}
    domain_suffix = hostname.split(".")[-1] if "." in hostname else ""
    if domain_suffix in institutional_tlds or any(hostname.endswith("." + it) for it in institutional_tlds):
        return {
            "category": "Academic, Educational or Government Portal",
            "type_badge": "TRUSTED_INSTITUTION",
            "description": "Domain belongs to a verified institutional TLD (.edu, .gov, etc.).",
            "risk_nature": "HIGH_CREDIBILITY"
        }

    if features.get("auth_keyword_count", 0) >= 2 or (features.get("auth_keyword_count", 0) >= 1 and (features.get("is_suspicious_tld") == 1 or features.get("is_https") == 0)):
        return {
            "category": "Generic Credential Harvesting Portal",
            "type_badge": "GENERIC_PHISHING",
            "description": "Generic authentication and account verification cues detected on unverified destination.",
            "risk_nature": "HIGH_RISK"
        }

    if features.get("scam_keyword_count", 0) >= 1:
        return {
            "category": "Social Engineering / Financial Lure",
            "type_badge": "SCAM_LURE",
            "description": "Contains artificial urgency, reward, prize, or giveaway manipulation cues.",
            "risk_nature": "SCAM_RISK"
        }

    return {
        "category": "Standard Web Page / Content",
        "type_badge": "GENERAL_WEB",
        "description": "General web article, blog, portfolio, forum, or documentation page.",
        "risk_nature": "STANDARD"
    }
