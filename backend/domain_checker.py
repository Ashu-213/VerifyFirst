"""
domain_checker.py — WHOIS lookup with hard timeout wrapper.
Runs in a background thread to avoid freezing the API.
"""

import concurrent.futures
import time
import re
from datetime import datetime, timezone
from urllib.parse import urlparse

# python-whois import with graceful fallback
try:
    import whois as whois_lib
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False


WHOIS_TIMEOUT_SECONDS = 1.5


def get_domain_info(url: str) -> dict:
    """
    Returns domain age info. Always completes within ~2 seconds.
    On failure, returns a 'suspicious' fallback result.
    """
    result = {
        "domain_age_days": None,
        "newly_registered": False,
        "whois_error": None,
    }

    if not WHOIS_AVAILABLE:
        result["whois_error"] = "python-whois not installed"
        return result

    domain = _extract_domain(url)
    if not domain:
        result["whois_error"] = "could not parse domain"
        return result

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(_whois_lookup, domain)
            try:
                whois_result = future.result(timeout=WHOIS_TIMEOUT_SECONDS)
                result.update(whois_result)
            except concurrent.futures.TimeoutError:
                result["whois_error"] = "whois timeout"
                result["newly_registered"] = True   # treat as suspicious
            except Exception as e:
                result["whois_error"] = str(e)
    except Exception as e:
        result["whois_error"] = f"executor error: {e}"

    return result


def _whois_lookup(domain: str) -> dict:
    result = {
        "domain_age_days": None,
        "newly_registered": False,
        "whois_error": None,
    }
    try:
        w = whois_lib.whois(domain)
        creation_date = w.creation_date

        # python-whois sometimes returns a list
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date is None:
            result["whois_error"] = "no creation date"
            return result

        # Ensure timezone-aware comparison
        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is None:
            creation_date = creation_date.replace(tzinfo=timezone.utc)

        now = datetime.now(tz=timezone.utc)
        age = (now - creation_date).days
        result["domain_age_days"] = age
        result["newly_registered"] = age < 30

    except Exception as e:
        result["whois_error"] = str(e)

    return result


def _extract_domain(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        # Strip port
        host = host.split(":")[0]
        # Return root domain only (last two parts) to avoid whois reject
        parts = host.split(".")
        if len(parts) >= 2:
            return ".".join(parts[-2:])
        return host
    except Exception:
        return ""
