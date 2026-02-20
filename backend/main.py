"""
main.py — VerifyFirst FastAPI backend server.

Run:
    python main.py

Endpoints:
    GET  /health        → {"status": "ok"}
    POST /analyze       → {"url": "..."} → {risk_score, category, reasons}
    GET  /stats         → analysis statistics
"""

import asyncio
import os
import sys
import time
from contextlib import asynccontextmanager

import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel

# ── Local imports ──────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(__file__))

from cache import cache
from database import init_db, log_result, get_stats
from domain_checker import get_domain_info
from reputation import load_blacklist
from scorer import analyze, load_model

CSV_PATH = os.path.join(os.path.dirname(__file__), "phishing_urls.csv")

ANALYSIS_TIMEOUT = 2.0   # seconds — hard ceiling per request


# ── Lifespan ───────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    print("=" * 60)
    print("  VerifyFirst — Real-Time Phishing Prevention")
    print("=" * 60)
    init_db()
    load_blacklist(CSV_PATH)
    load_model()
    print("[SERVER] Ready on http://127.0.0.1:8000")
    print("=" * 60)
    yield
    print("[SERVER] Shutting down.")


app = FastAPI(title="VerifyFirst API", version="1.0.0", lifespan=lifespan)

# Allow requests from Chrome extension (chrome-extension://)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)


# ── Models ─────────────────────────────────────────────────────────────────────

class AnalyzeRequest(BaseModel):
    url: str


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "cache_size": cache.size()}


@app.get("/stats")
async def stats():
    return get_stats()


@app.post("/analyze")
async def analyze_url(req: AnalyzeRequest, request: Request):
    url = req.url.strip()
    start = time.monotonic()

    # ── Validate ──────────────────────────────────────────────────────────────
    if not url:
        return JSONResponse(
            status_code=400,
            content={"error": "url is required"},
        )

    if not (url.startswith("http://") or url.startswith("https://")):
        return JSONResponse(
            content={
                "risk_score": 0,
                "category": "safe",
                "reasons": ["Non-HTTP protocol — not analyzed"],
            }
        )

    # ── Cache hit ─────────────────────────────────────────────────────────────
    cached = cache.get(url)
    if cached:
        cached["cached"] = True
        return JSONResponse(content=cached)

    # ── Full analysis with hard timeout ───────────────────────────────────────
    try:
        result = await asyncio.wait_for(
            _run_analysis(url),
            timeout=ANALYSIS_TIMEOUT,
        )
    except asyncio.TimeoutError:
        print(f"[TIMEOUT] Analysis exceeded {ANALYSIS_TIMEOUT}s for {url}")
        result = {
            "risk_score": 40,
            "category": "suspicious",
            "reasons": ["Analysis timed out — treating as suspicious for safety"],
        }
    except Exception as e:
        print(f"[ERROR] Analysis failed for {url}: {e}")
        result = {
            "risk_score": 40,
            "category": "suspicious",
            "reasons": [f"Analysis error — treating as suspicious: {str(e)[:100]}"],
        }

    elapsed = time.monotonic() - start
    result["elapsed_ms"] = round(elapsed * 1000)
    result["cached"] = False

    cache.set(url, result)

    # Log to DB asynchronously (don't block response)
    asyncio.create_task(_log_async(url, result))

    return JSONResponse(content=result)


async def _run_analysis(url: str) -> dict:
    """Run domain check + scoring concurrently."""
    loop = asyncio.get_event_loop()

    # WHOIS runs in a thread executor (blocking I/O)
    domain_info = await loop.run_in_executor(None, get_domain_info, url)

    # Scoring is CPU-bound but fast enough inline
    result = await loop.run_in_executor(None, analyze, url, domain_info)

    # Enrich result with domain info
    result["domain_age_days"] = domain_info.get("domain_age_days")
    result["newly_registered"] = domain_info.get("newly_registered", False)

    return result


async def _log_async(url: str, result: dict):
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, log_result, url, result)


# ── Entry point ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="127.0.0.1",
        port=8000,
        reload=False,
        log_level="warning",
    )
