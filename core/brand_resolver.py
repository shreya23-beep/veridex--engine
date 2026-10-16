"""
VeriDex AI - Legitimate Brand Resolver & Safe Navigation Advisor
Maps deceptive replica/phishing domains to their verified, authentic official websites,
protecting users from spoofed portals and offering safe one-click navigation.
"""

from typing import Optional, Dict, Any
from urllib.parse import urlparse

OFFICIAL_BRAND_REGISTRY: Dict[str, Dict[str, str]] = {
    "paypal": {
        "brand_name": "PayPal",
        "legal_entity": "PayPal, Inc.",
        "official_domain": "paypal.com",
        "official_url": "https://www.paypal.com",
        "login_url": "https://www.paypal.com/signin",
        "category": "Banking & Digital Payments"
    },
    "apple": {
        "brand_name": "Apple",
        "legal_entity": "Apple Inc.",
        "official_domain": "apple.com",
        "official_url": "https://www.apple.com",
        "login_url": "https://appleid.apple.com",
        "category": "Consumer Technology & Cloud"
    },
    "google": {
        "brand_name": "Google",
        "legal_entity": "Google LLC / Alphabet",
        "official_domain": "google.com",
        "official_url": "https://www.google.com",
        "login_url": "https://accounts.google.com",
        "category": "Search & Cloud Services"
    },
    "microsoft": {
        "brand_name": "Microsoft",
        "legal_entity": "Microsoft Corporation",
        "official_domain": "microsoft.com",
        "official_url": "https://www.microsoft.com",
        "login_url": "https://login.microsoftonline.com",
        "category": "Operating Systems & Office Software"
    },
    "amazon": {
        "brand_name": "Amazon",
        "legal_entity": "Amazon.com, Inc.",
        "official_domain": "amazon.com",
        "official_url": "https://www.amazon.com",
        "login_url": "https://www.amazon.com/ap/signin",
        "category": "E-Commerce & Cloud Services"
    },
    "netflix": {
        "brand_name": "Netflix",
        "legal_entity": "Netflix, Inc.",
        "official_domain": "netflix.com",
        "official_url": "https://www.netflix.com",
        "login_url": "https://www.netflix.com/login",
        "category": "Streaming Entertainment"
    },
    "chase": {
        "brand_name": "Chase Bank",
        "legal_entity": "JPMorgan Chase Bank, N.A.",
        "official_domain": "chase.com",
        "official_url": "https://www.chase.com",
        "login_url": "https://www.chase.com",
        "category": "Retail & Commercial Banking"
    },
    "bankofamerica": {
        "brand_name": "Bank of America",
        "legal_entity": "Bank of America Corporation",
        "official_domain": "bankofamerica.com",
        "official_url": "https://www.bankofamerica.com",
        "login_url": "https://www.bankofamerica.com",
        "category": "Retail & Commercial Banking"
    },
    "wellsfargo": {
        "brand_name": "Wells Fargo",
        "legal_entity": "Wells Fargo & Company",
        "official_domain": "wellsfargo.com",
        "official_url": "https://www.wellsfargo.com",
        "login_url": "https://www.wellsfargo.com",
        "category": "Retail & Commercial Banking"
    },
    "citibank": {
        "brand_name": "Citibank",
        "legal_entity": "Citigroup Inc.",
        "official_domain": "citi.com",
        "official_url": "https://www.citi.com",
        "login_url": "https://www.citi.com",
        "category": "Retail & Commercial Banking"
    },
    "binance": {
        "brand_name": "Binance",
        "legal_entity": "Binance Holdings Ltd.",
        "official_domain": "binance.com",
        "official_url": "https://www.binance.com",
        "login_url": "https://accounts.binance.com",
        "category": "Cryptocurrency Exchange"
    },
    "coinbase": {
        "brand_name": "Coinbase",
        "legal_entity": "Coinbase Global, Inc.",
        "official_domain": "coinbase.com",
        "official_url": "https://www.coinbase.com",
        "login_url": "https://www.coinbase.com/signin",
        "category": "Cryptocurrency Exchange"
    },
    "metamask": {
        "brand_name": "MetaMask",
        "legal_entity": "Consensys Software Inc.",
        "official_domain": "metamask.io",
        "official_url": "https://metamask.io",
        "login_url": "https://metamask.io",
        "category": "Web3 & Crypto Wallet"
    },
    "ledger": {
        "brand_name": "Ledger",
        "legal_entity": "Ledger SAS",
        "official_domain": "ledger.com",
        "official_url": "https://www.ledger.com",
        "login_url": "https://www.ledger.com",
        "category": "Hardware Wallets & Security"
    },
    "steam": {
        "brand_name": "Steam",
        "legal_entity": "Valve Corporation",
        "official_domain": "steampowered.com",
        "official_url": "https://store.steampowered.com",
        "login_url": "https://store.steampowered.com/login",
        "category": "Gaming & Software Store"
    },
    "dhl": {
        "brand_name": "DHL Express",
        "legal_entity": "Deutsche Post DHL Group",
        "official_domain": "dhl.com",
        "official_url": "https://www.dhl.com",
        "login_url": "https://www.dhl.com",
        "category": "Logistics & Shipping"
    },
    "fedex": {
        "brand_name": "FedEx",
        "legal_entity": "FedEx Corporation",
        "official_domain": "fedex.com",
        "official_url": "https://www.fedex.com",
        "login_url": "https://www.fedex.com",
        "category": "Logistics & Shipping"
    },
    "ups": {
        "brand_name": "UPS",
        "legal_entity": "United Parcel Service, Inc.",
        "official_domain": "ups.com",
        "official_url": "https://www.ups.com",
        "login_url": "https://www.ups.com",
        "category": "Logistics & Shipping"
    },
    "usps": {
        "brand_name": "USPS",
        "legal_entity": "United States Postal Service",
        "official_domain": "usps.com",
        "official_url": "https://www.usps.com",
        "login_url": "https://www.usps.com",
        "category": "Postal & Package Delivery"
    },
    "irs": {
        "brand_name": "IRS",
        "legal_entity": "Internal Revenue Service (US Gov)",
        "official_domain": "irs.gov",
        "official_url": "https://www.irs.gov",
        "login_url": "https://www.irs.gov",
        "category": "Government & Taxation"
    },
    "facebook": {
        "brand_name": "Facebook",
        "legal_entity": "Meta Platforms, Inc.",
        "official_domain": "facebook.com",
        "official_url": "https://www.facebook.com",
        "login_url": "https://www.facebook.com/login",
        "category": "Social Media Platform"
    },
    "instagram": {
        "brand_name": "Instagram",
        "legal_entity": "Meta Platforms, Inc.",
        "official_domain": "instagram.com",
        "official_url": "https://www.instagram.com",
        "login_url": "https://www.instagram.com/accounts/login",
        "category": "Social Media Platform"
    },
    "twitter": {
        "brand_name": "X (Twitter)",
        "legal_entity": "X Corp.",
        "official_domain": "x.com",
        "official_url": "https://x.com",
        "login_url": "https://x.com/i/flow/login",
        "category": "Social Media Platform"
    },
    "linkedin": {
        "brand_name": "LinkedIn",
        "legal_entity": "LinkedIn Corporation (Microsoft)",
        "official_domain": "linkedin.com",
        "official_url": "https://www.linkedin.com",
        "login_url": "https://www.linkedin.com/login",
        "category": "Professional Networking"
    },
    "dropbox": {
        "brand_name": "Dropbox",
        "legal_entity": "Dropbox, Inc.",
        "official_domain": "dropbox.com",
        "official_url": "https://www.dropbox.com",
        "login_url": "https://www.dropbox.com/login",
        "category": "Cloud File Storage"
    },
    "adobe": {
        "brand_name": "Adobe",
        "legal_entity": "Adobe Inc.",
        "official_domain": "adobe.com",
        "official_url": "https://www.adobe.com",
        "login_url": "https://auth.services.adobe.com",
        "category": "Creative & Productivity Software"
    },
    "whatsapp": {
        "brand_name": "WhatsApp",
        "legal_entity": "WhatsApp LLC (Meta)",
        "official_domain": "whatsapp.com",
        "official_url": "https://web.whatsapp.com",
        "login_url": "https://web.whatsapp.com",
        "category": "Encrypted Messaging"
    },
    "telegram": {
        "brand_name": "Telegram",
        "legal_entity": "Telegram FZ-LLC",
        "official_domain": "telegram.org",
        "official_url": "https://web.telegram.org",
        "login_url": "https://web.telegram.org",
        "category": "Instant Messaging"
    },
    "spotify": {
        "brand_name": "Spotify",
        "legal_entity": "Spotify Technology S.A.",
        "official_domain": "spotify.com",
        "official_url": "https://www.spotify.com",
        "login_url": "https://accounts.spotify.com/login",
        "category": "Audio Streaming"
    },
    "walmart": {
        "brand_name": "Walmart",
        "legal_entity": "Walmart Inc.",
        "official_domain": "walmart.com",
        "official_url": "https://www.walmart.com",
        "login_url": "https://www.walmart.com/account/login",
        "category": "Retail & Supermarkets"
    },
    "target": {
        "brand_name": "Target",
        "legal_entity": "Target Brands, Inc.",
        "official_domain": "target.com",
        "official_url": "https://www.target.com",
        "login_url": "https://www.target.com/login",
        "category": "Retail & Supermarkets"
    },
    "ebay": {
        "brand_name": "eBay",
        "legal_entity": "eBay Inc.",
        "official_domain": "ebay.com",
        "official_url": "https://www.ebay.com",
        "login_url": "https://signin.ebay.com",
        "category": "Online Marketplace"
    },
    "discord": {
        "brand_name": "Discord",
        "legal_entity": "Discord Inc.",
        "official_domain": "discord.com",
        "official_url": "https://discord.com",
        "login_url": "https://discord.com/login",
        "category": "Voice & Chat Community"
    },
    "github": {
        "brand_name": "GitHub",
        "legal_entity": "GitHub, Inc. (Microsoft)",
        "official_domain": "github.com",
        "official_url": "https://github.com",
        "login_url": "https://github.com/login",
        "category": "Developer Platform & Code Hosting"
    },
    "gitlab": {
        "brand_name": "GitLab",
        "legal_entity": "GitLab Inc.",
        "official_domain": "gitlab.com",
        "official_url": "https://gitlab.com",
        "login_url": "https://gitlab.com/users/sign_in",
        "category": "DevOps & Code Hosting"
    },
    "stripe": {
        "brand_name": "Stripe",
        "legal_entity": "Stripe, Inc.",
        "official_domain": "stripe.com",
        "official_url": "https://stripe.com",
        "login_url": "https://dashboard.stripe.com/login",
        "category": "Online Payment Processing"
    },
    "roblox": {
        "brand_name": "Roblox",
        "legal_entity": "Roblox Corporation",
        "official_domain": "roblox.com",
        "official_url": "https://www.roblox.com",
        "login_url": "https://www.roblox.com/login",
        "category": "Online Gaming Platform"
    },
    "oracle": {
        "brand_name": "Oracle",
        "legal_entity": "Oracle Corporation",
        "official_domain": "oracle.com",
        "official_url": "https://www.oracle.com",
        "login_url": "https://login.oracle.com",
        "category": "Enterprise Cloud & Database Technology"
    },
    "shopify": {
        "brand_name": "Shopify",
        "legal_entity": "Shopify Inc.",
        "official_domain": "shopify.com",
        "official_url": "https://www.shopify.com",
        "login_url": "https://accounts.shopify.com/login",
        "category": "E-Commerce Platform"
    },
    "flipkart": {
        "brand_name": "Flipkart",
        "legal_entity": "Flipkart Internet Private Limited",
        "official_domain": "flipkart.com",
        "official_url": "https://www.flipkart.com",
        "login_url": "https://www.flipkart.com/account/login",
        "category": "E-Commerce Marketplace"
    },
    "sbi": {
        "brand_name": "State Bank of India",
        "legal_entity": "State Bank of India",
        "official_domain": "onlinesbi.sbi",
        "official_url": "https://www.onlinesbi.sbi",
        "login_url": "https://retail.onlinesbi.sbi/retail/login.htm",
        "category": "Retail Banking"
    },
    "hdfcbank": {
        "brand_name": "HDFC Bank",
        "legal_entity": "HDFC Bank Limited",
        "official_domain": "hdfcbank.com",
        "official_url": "https://www.hdfcbank.com",
        "login_url": "https://netbanking.hdfcbank.com/netbanking/",
        "category": "Retail Banking"
    },
    "icicibank": {
        "brand_name": "ICICI Bank",
        "legal_entity": "ICICI Bank Limited",
        "official_domain": "icicibank.com",
        "official_url": "https://www.icicibank.com",
        "login_url": "https://infinity.icicibank.com",
        "category": "Retail Banking"
    },
    "axisbank": {
        "brand_name": "Axis Bank",
        "legal_entity": "Axis Bank Limited",
        "official_domain": "axisbank.com",
        "official_url": "https://www.axisbank.com",
        "login_url": "https://omni.axisbank.co.in/axisretail/login",
        "category": "Retail Banking"
    },
    "paytm": {
        "brand_name": "Paytm",
        "legal_entity": "One97 Communications Limited",
        "official_domain": "paytm.com",
        "official_url": "https://paytm.com",
        "login_url": "https://paytm.com",
        "category": "Digital Payments & Financial Services"
    },
    "phonepe": {
        "brand_name": "PhonePe",
        "legal_entity": "PhonePe Private Limited",
        "official_domain": "phonepe.com",
        "official_url": "https://www.phonepe.com",
        "login_url": "https://www.phonepe.com",
        "category": "Digital Payments"
    },
    "irctc": {
        "brand_name": "IRCTC",
        "legal_entity": "Indian Railway Catering and Tourism Corporation",
        "official_domain": "irctc.co.in",
        "official_url": "https://www.irctc.co.in",
        "login_url": "https://www.irctc.co.in/nget/train-search",
        "category": "Travel & Transportation"
    }
}

def resolve_legitimate_website(
    url: str,
    spoofed_brand: Optional[str] = None
) -> Optional[Dict[str, Any]]:
    """
    Given a suspicious or replica URL, determines which legitimate organization
    is being impersonated and provides the verified authentic portal URL.
    """
    raw_lower = url.lower().strip()
    parsed = urlparse("http://" + raw_lower if not raw_lower.startswith(("http://", "https://")) else raw_lower)
    hostname = (parsed.hostname or parsed.netloc or "").lower()

    target_key = None

    # 1. Use spoofed brand detected by typosquatting engine if present
    if spoofed_brand and spoofed_brand.lower() in OFFICIAL_BRAND_REGISTRY:
        target_key = spoofed_brand.lower()
    else:
        # 2. Check hostname and path for known brand tokens
        for brand_key in OFFICIAL_BRAND_REGISTRY.keys():
            if brand_key in hostname or f"-{brand_key}-" in hostname or f"{brand_key}id" in hostname or f"{brand_key}-" in hostname:
                target_key = brand_key
                break

    if not target_key:
        return None

    brand_data = OFFICIAL_BRAND_REGISTRY[target_key]

    # Don't suggest redirection if user is ALREADY on the genuine official domain!
    official_domain = brand_data["official_domain"]
    if hostname == official_domain or hostname.endswith("." + official_domain):
        return None

    return {
        "has_suggestion": True,
        "is_impersonation": True,
        "spoofed_brand": brand_data["brand_name"],
        "legal_entity": brand_data["legal_entity"],
        "category": brand_data["category"],
        "official_domain": brand_data["official_domain"],
        "official_url": brand_data["official_url"],
        "official_login_url": brand_data["login_url"],
        "warning_message": (
            f"WARNING: The target URL appears to be an unauthorized replica impersonating {brand_data['brand_name']}. "
            f"Never enter credentials, passwords, or personal data on this site."
        ),
        "safe_action": f"Navigate safely to the official verified {brand_data['brand_name']} website instead."
    }
