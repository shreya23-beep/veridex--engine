"""
VeriDex AI - On-Device NLP & Manipulation Cue Analyzer
Scans email bodies, SMS, social engineering messages, and webpage text
for psychological persuasion tactics, artificial urgency, authority coercion,
and credential harvesting indicators without transmitting data to external servers.
"""

import re
from typing import Dict, List, Any

MANIPULATION_CATEGORIES = {
    "URGENCY_PRESSURE": {
        "weight": 0.25,
        "patterns": [
            r"\b(immediately|act now|urgent|critical|within\s+\d+\s*(hours?|mins?|minutes?)|limited time|before it's too late)\b",
            r"\b(last warning|final notice|expires soon|immediate attention|account will be (deleted|suspended|terminated))\b",
            r"\b(24 hours|deadline|action required promptly|don't delay|countdown)\b"
        ],
        "description": "Artificial urgency designed to panic the victim into bypassing critical thinking."
    },
    "FEAR_AND_PENALTY": {
        "weight": 0.30,
        "patterns": [
            r"\b(account\s+(?:is\s+|has\s+been\s+|was\s+|will\s+be\s+)?(?:suspended|frozen|locked|restricted|compromised|terminated)|unauthorized\s+access|security\s+breach)\b",
            r"\b(fraudulent\s+activity|legal\s+(?:action|arrest|notice)|law\s+enforcement|police|court\s+summons|arrest\s*(?:warrant)?|penalt(?:y|ies)|fine)\b",
            r"\b(financial\s+loss|security\s+alert|suspicious\s+sign-in|identity\s+theft)\b"
        ],
        "description": "Fear and intimidation tactic threatening financial loss, legal penalties, or account loss."
    },
    "FINANCIAL_GREED_AND_PRIZES": {
        "weight": 0.25,
        "patterns": [
            r"\b(congratulations|winner|you have won|lottery|crypto airdrop|free\s+(?:gift|money|bitcoin|usdt|tokens))\b",
            r"\b(exclusive reward|claim your prize|payout|unclaimed funds|double your investment|cash bonus)\b",
            r"\b(100% guaranteed return|risk-free profits|instant transfer)\b"
        ],
        "description": "Lures offering unrealistic monetary rewards, lotteries, or cryptocurrency airdrops."
    },
    "CREDENTIAL_HARVESTING": {
        "weight": 0.35,
        "patterns": [
            r"\b(enter\s+(?:your\s+)?password|confirm\s+(?:your\s+)?pin|verify\s+(?:your\s+)?identity|provide\s+ssn|social\s+security)\b",
            r"\b(credit\s+card\s+number|cvv|expiration\s+date|banking\s+credentials|seed\s+phrase|private\s+key|recovery\s+phrase)\b",
            r"\b(one-time\s+password|otp|authenticator\s+code|2fa\s+code|login\s+credentials)\b"
        ],
        "description": "Direct attempts to harvest sensitive credentials, banking details, or crypto keys."
    },
    "FALSE_TECH_SUPPORT": {
        "weight": 0.25,
        "patterns": [
            r"\b(virus\s+detected|trojan\s+found|firewall\s+breached|call\s+toll-free|call\s+support|helpdesk\s+helpline)\b",
            r"\b(certified\s+technician|download\s+anydesk|install\s+teamviewer|allow\s+remote\s+access|fix\s+your\s+pc)\b",
            r"\b(microsoft\s+support\s+alert|windows\s+defender\s+warning)\b"
        ],
        "description": "Impersonation of technical support urging installation of remote administration tools."
    }
}

class ManipulationCueAnalyzer:
    """
    On-device NLP tokenizer and rule-based semantic parser for manipulation cues.
    Provides fast (< 2ms) detection of psychological engineering.
    """

    def __init__(self):
        self.compiled_rules = {}
        for category, data in MANIPULATION_CATEGORIES.items():
            self.compiled_rules[category] = [
                re.compile(p, re.IGNORECASE) for p in data["patterns"]
            ]

    def tokenize(self, text: str) -> List[str]:
        """Simple, efficient local tokenizer splitting text into clean words."""
        cleaned = re.sub(r"[^a-zA-Z0-9\s]", " ", text.lower())
        return [w for w in cleaned.split() if len(w) > 1]

    def analyze_text(self, text: str) -> Dict[str, Any]:
        """
        Analyzes raw message/page content and returns manipulation cues and risk score.
        """
        if not text or not text.strip():
            return {
                "risk_score": 0.0,
                "threat_level": "CLEAN",
                "detected_cues": [],
                "summary": "No text content provided."
            }

        detected_cues = []
        total_risk_score = 0.0

        for category, regex_list in self.compiled_rules.items():
            matches = []
            for regex in regex_list:
                found = regex.findall(text)
                if found:
                    for item in found:
                        if isinstance(item, tuple):
                            matches.append(item[0])
                        else:
                            matches.append(item)
            
            if matches:
                category_meta = MANIPULATION_CATEGORIES[category]
                matched_samples = list(set(matches))[:3]
                cue_weight = category_meta["weight"]
                
                # Diminishing returns on repeated hits in same category
                hit_severity = min(len(matches) * 0.5, 1.0)
                category_score = cue_weight * hit_severity
                total_risk_score += category_score

                detected_cues.append({
                    "category": category,
                    "description": category_meta["description"],
                    "matched_tokens": matched_samples,
                    "hit_count": len(matches),
                    "category_risk": round(category_score * 100, 1)
                })

        # Multi-vector synergy: combinations of urgency, fear, and credential harvesting are high-confidence attacks
        if len(detected_cues) >= 3:
            total_risk_score += 0.25
        elif len(detected_cues) >= 2:
            total_risk_score += 0.15

        normalized_score = min(round(total_risk_score * 100, 1), 100.0)

        if normalized_score >= 70:
            threat_level = "CRITICAL"
            summary = "High probability of AI-crafted social engineering or phishing extortion."
        elif normalized_score >= 40:
            threat_level = "SUSPICIOUS"
            summary = "Contains multiple psychological manipulation cues commonly seen in scams."
        elif normalized_score >= 15:
            threat_level = "LOW_RISK"
            summary = "Contains mild marketing or urgency phrases; review with standard caution."
        else:
            threat_level = "CLEAN"
            summary = "No noticeable social engineering manipulation patterns detected."

        return {
            "risk_score": normalized_score,
            "threat_level": threat_level,
            "detected_cues": detected_cues,
            "summary": summary,
            "token_count": len(self.tokenize(text))
        }

# Global instance for low memory footprint
nlp_analyzer = ManipulationCueAnalyzer()
