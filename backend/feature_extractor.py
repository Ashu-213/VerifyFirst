"""
feature_extractor.py — Extract URL features for ML model and scoring.
"""

import re
import ipaddress
from urllib.parse import urlparse


# Keywords that are suspicious in general contexts
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "bank", "update", "secure", "account",
    "signin", "password", "credential", "confirm", "billing",
    "support", "suspended", "unusual", "validate", "authenticate"
]

# Brand names that are suspicious when combined with other keywords
# or when appearing in subdomains/paths (not root domain)
BRAND_KEYWORDS = [
    "paypal", "ebay", "amazon", "apple", "microsoft", "google",
    "facebook", "netflix", "instagram", "twitter"
]


def extract_features(url: str) -> dict:
    """
    Returns a dictionary of features extracted from the URL.
    Used both by the ML model (as ordered list) and the scorer (by name).
    """
    try:
        parsed = urlparse(url)
    except Exception:
        parsed = None

    features = {}

    # 1. URL length
    features["url_length"] = len(url)

    # 2. Dot count
    features["dot_count"] = url.count(".")

    # 3. Hyphen count
    features["hyphen_count"] = url.count("-")

    # 4. IP address usage
    features["has_ip"] = _has_ip_address(url)

    # 5. Suspicious keyword count
    url_lower = url.lower()
    keywords_found = []
    
    # Check general suspicious keywords
    for kw in SUSPICIOUS_KEYWORDS:
        if kw in url_lower:
            keywords_found.append(kw)
    
    # Check brand keywords - only flag if NOT the actual brand's root domain
    if parsed and parsed.hostname:
        root_domain = _get_root_domain(parsed.hostname)
        for brand in BRAND_KEYWORDS:
            # Only flag brand names if they appear in suspicious contexts:
            # - In subdomain (e.g., paypal.evil.com)
            # - In path (e.g., evil.com/paypal-login)
            # - NOT if it's the actual brand domain (e.g., paypal.com, microsoft.com)
            if brand in url_lower and brand != root_domain:
                keywords_found.append(brand)
    
    features["suspicious_keyword_count"] = len(keywords_found)
    features["suspicious_keywords_found"] = keywords_found

    # 6. HTTPS usage
    if parsed:
        features["uses_https"] = 1 if parsed.scheme == "https" else 0
    else:
        features["uses_https"] = 0

    # 7. Subdomain depth
    features["subdomain_depth"] = _subdomain_depth(parsed)

    # 8. Path length
    if parsed and parsed.path:
        features["path_length"] = len(parsed.path)
    else:
        features["path_length"] = 0

    # 9. Query string length
    if parsed and parsed.query:
        features["query_length"] = len(parsed.query)
    else:
        features["query_length"] = 0

    # 10. @ symbol in URL (classic phishing trick)
    features["has_at_symbol"] = 1 if "@" in url else 0

    # 11. Double slash redirect
    features["has_double_slash"] = 1 if "//" in url[7:] else 0

    # 12. Hexadecimal encoding
    features["has_hex_encoding"] = 1 if re.search(r"%[0-9a-fA-F]{2}", url) else 0

    # 13. Number of subdomains containing digits
    features["subdomain_has_digits"] = _subdomain_has_digits(parsed)

    # 14. URL entropy (randomness indicator)
    features["url_entropy"] = _entropy(url)

    return features


def features_to_vector(features: dict) -> list:
    """
    Returns a fixed-length ordered list for ML model input.
    Order MUST match training order in train_model.py.
    """
    return [
        features["url_length"],
        features["dot_count"],
        features["hyphen_count"],
        features["has_ip"],
        features["suspicious_keyword_count"],
        features["uses_https"],
        features["subdomain_depth"],
        features["path_length"],
        features["query_length"],
        features["has_at_symbol"],
        features["has_double_slash"],
        features["has_hex_encoding"],
        features["subdomain_has_digits"],
        features["url_entropy"],
    ]


FEATURE_NAMES = [
    "url_length",
    "dot_count",
    "hyphen_count",
    "has_ip",
    "suspicious_keyword_count",
    "uses_https",
    "subdomain_depth",
    "path_length",
    "query_length",
    "has_at_symbol",
    "has_double_slash",
    "has_hex_encoding",
    "subdomain_has_digits",
    "url_entropy",
]


# ── helpers ────────────────────────────────────────────────────────────────────

def _has_ip_address(url: str) -> int:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        ipaddress.ip_address(host)
        return 1
    except ValueError:
        return 0


def _subdomain_depth(parsed) -> int:
    if not parsed or not parsed.hostname:
        return 0
    parts = parsed.hostname.split(".")
    # e.g. www.evil.legit.com → 4 parts → depth 2 (subtract root + tld + domain)
    return max(0, len(parts) - 2)


def _get_root_domain(hostname: str) -> str:
    """Extract root domain from hostname (e.g., 'github' from 'www.github.com')."""
    if not hostname:
        return ""
    parts = hostname.split(".")
    if len(parts) >= 2:
        # Return second-to-last part (domain name without TLD)
        return parts[-2]
    return hostname


def _subdomain_has_digits(parsed) -> int:
    if not parsed or not parsed.hostname:
        return 0
    parts = parsed.hostname.split(".")
    # Check subdomains only (all but last two parts)
    subdomains = parts[:-2]
    return 1 if any(re.search(r"\d", part) for part in subdomains) else 0


def _entropy(text: str) -> float:
    import math
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    n = len(text)
    return -sum((count / n) * math.log2(count / n) for count in freq.values())
