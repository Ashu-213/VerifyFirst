"""
reputation.py — Local URL reputation check using real phishing blacklist.
Loads 10,000+ real phishing URLs from Kaggle dataset.
No internet API calls. Loaded once at startup.
"""

import csv
import os
import hashlib
from urllib.parse import urlparse

# Demo phishing URLs for testing (optional - blacklist CSV has real data)
DEMO_PHISHING_URLS = {
    "http://test-phishing-demo.local/account/update",
}

# Normalized demo domains
DEMO_PHISHING_DOMAINS = {
    "test-phishing-demo.local",
}

_BLACKLIST: set = set()
_BLACKLIST_DOMAINS: set = set()


def load_blacklist(csv_path: str) -> None:
    """Load PhishTank CSV into memory at startup."""
    global _BLACKLIST, _BLACKLIST_DOMAINS

    # Always add demo URLs
    _BLACKLIST = set(DEMO_PHISHING_URLS)
    _BLACKLIST_DOMAINS = set(DEMO_PHISHING_DOMAINS)

    if not os.path.exists(csv_path):
        print(f"[REPUTATION] CSV not found at {csv_path}, using demo list only.")
        return

    try:
        count = 0
        with open(csv_path, newline="", encoding="utf-8", errors="replace") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Support both 'url' and 'phish_url' column names
                url = row.get("url") or row.get("phish_url") or ""
                url = url.strip()
                if url:
                    _BLACKLIST.add(url)
                    domain = _extract_domain(url)
                    if domain:
                        _BLACKLIST_DOMAINS.add(domain)
                    count += 1
        print(f"[REPUTATION] Loaded {count} entries from {csv_path}")
    except Exception as e:
        print(f"[REPUTATION] Error loading CSV: {e}")


def is_blacklisted(url: str) -> bool:
    """Check if URL or its domain is in the blacklist."""
    # Exact URL match
    if url in _BLACKLIST:
        return True

    # Normalize and try again
    normalized = _normalize_url(url)
    if normalized in _BLACKLIST:
        return True

    # Domain match
    domain = _extract_domain(url)
    if domain and domain in _BLACKLIST_DOMAINS:
        return True

    return False


def is_demo_phishing(url: str) -> bool:
    """Returns True if this is one of the hardcoded demo phishing URLs."""
    if url in DEMO_PHISHING_URLS:
        return True
    domain = _extract_domain(url)
    return domain in DEMO_PHISHING_DOMAINS


# ── helpers ────────────────────────────────────────────────────────────────────

def _normalize_url(url: str) -> str:
    url = url.strip().rstrip("/")
    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]
    return url.lower()


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        return parsed.hostname or ""
    except Exception:
        return ""
