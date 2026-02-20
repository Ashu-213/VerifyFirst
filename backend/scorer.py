"""
scorer.py — Rule-based + ML hybrid scoring engine.
"""

from feature_extractor import extract_features, features_to_vector
from reputation import is_blacklisted, is_demo_phishing
import pickle
import os
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")

_model = None


def load_model():
    global _model
    if not os.path.exists(MODEL_PATH):
        print("[SCORER] WARNING: model.pkl not found. Run train_model.py first.")
        _model = None
        return
    try:
        with open(MODEL_PATH, "rb") as f:
            _model = pickle.load(f)
        print("[SCORER] Model loaded successfully.")
    except Exception as e:
        print(f"[SCORER] Failed to load model: {e}")
        _model = None


def analyze(url: str, domain_info: dict) -> dict:
    """
    Runs full scoring pipeline. Returns:
    {
        "risk_score": int (0–100),
        "category": "safe" | "suspicious" | "dangerous",
        "reasons": [str]
    }
    """
    reasons = []
    score = 0

    # ── 1. Blacklist / Demo check (highest priority) ──────────────────────────
    if is_demo_phishing(url):
        score += 70
        reasons.append("URL matches known phishing demo pattern")
    elif is_blacklisted(url):
        score += 70
        reasons.append("URL found in phishing blacklist")

    # ── 2. Feature extraction ─────────────────────────────────────────────────
    features = extract_features(url)

    # ── 3. Domain age check ───────────────────────────────────────────────────
    age = domain_info.get("domain_age_days")
    newly = domain_info.get("newly_registered", False)
    whois_err = domain_info.get("whois_error")

    if newly or (age is not None and age < 7):
        score += 20
        reasons.append(f"Domain very recently registered ({age} days old)")
    elif newly or (age is not None and age < 30):
        score += 10
        reasons.append(f"Domain recently registered ({age} days old)")
    elif whois_err and "timeout" in str(whois_err).lower():
        score += 10
        reasons.append("WHOIS lookup timed out — domain suspicious")

    # ── 4. Suspicious keywords ────────────────────────────────────────────────
    kw_count = features["suspicious_keyword_count"]
    kw_found = features["suspicious_keywords_found"]
    if kw_count > 0:
        keyword_score = min(kw_count * 5, 10)
        score += keyword_score
        reasons.append(f"Suspicious keywords detected: {', '.join(kw_found[:5])}")

    # ── 5. IP address as host ─────────────────────────────────────────────────
    if features["has_ip"]:
        score += 15
        reasons.append("URL uses raw IP address instead of domain name")

    # ── 6. No HTTPS ───────────────────────────────────────────────────────────
    if not features["uses_https"]:
        score += 5
        reasons.append("Connection is not encrypted (HTTP, not HTTPS)")

    # ── 7. Excessive subdomains ───────────────────────────────────────────────
    if features["subdomain_depth"] > 3:
        score += 10
        reasons.append(f"Unusually deep subdomain structure ({features['subdomain_depth']} levels)")

    # ── 8. @ symbol ───────────────────────────────────────────────────────────
    if features["has_at_symbol"]:
        score += 15
        reasons.append("URL contains '@' symbol — classic phishing trick")

    # ── 9. Very long URL ──────────────────────────────────────────────────────
    if features["url_length"] > 100:
        score += 5
        reasons.append(f"URL is unusually long ({features['url_length']} characters)")

    # ── 10. ML model probability ─────────────────────────────────────────────
    ml_contribution = 0
    if _model is not None:
        try:
            vector = features_to_vector(features)
            prob = _model.predict_proba([vector])[0]
            # prob[1] = probability of phishing class
            phishing_prob = float(prob[1]) if len(prob) > 1 else float(prob[0])
            ml_contribution = int(phishing_prob * 40)   # max 40 points
            if ml_contribution >= 15:
                reasons.append(f"ML model indicates elevated phishing probability ({phishing_prob:.0%})")
            score += ml_contribution
        except Exception as e:
            reasons.append(f"ML model skipped: {e}")

    # ── Clamp ─────────────────────────────────────────────────────────────────
    score = max(0, min(100, score))

    # ── Categorize ────────────────────────────────────────────────────────────
    if score >= 70:
        category = "dangerous"
    elif score >= 50:
        category = "suspicious"
    else:
        category = "safe"

    # ── Console log ───────────────────────────────────────────────────────────
    tag = {"safe": "[SAFE]", "suspicious": "[SUSPICIOUS]", "dangerous": "[BLOCKED]"}[category]
    print(f"{tag} {url} (score={score})")

    if not reasons:
        reasons.append("No suspicious signals detected")

    return {
        "risk_score": score,
        "category": category,
        "reasons": reasons,
    }
