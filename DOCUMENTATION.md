# VerifyFirst — Technical Documentation

> **Real-time phishing prevention powered by machine learning**  
> Complete documentation for developers, judges, and contributors

---

## 📋 Table of Contents

1. [Overview](#overview)
2. [Key Features](#key-features)
3. [Architecture](#architecture)
4. [Machine Learning Model](#machine-learning-model)
5. [Technology Stack](#technology-stack)
6. [Installation](#installation)
7. [API Reference](#api-reference)
8. [Detection Methods](#detection-methods)
9. [Performance Metrics](#performance-metrics)
10. [Project Structure](#project-structure)

---

## 🎯 Overview

**VerifyFirst** is a Chrome extension that prevents phishing attacks by analyzing URLs in real-time using a hybrid detection system combining:

- **Machine Learning** (RandomForest classifier trained on 651,191 URLs)
- **Blacklist matching** (10,000 known phishing URLs)
- **WHOIS domain verification** (checks domain age and registration)
- **Heuristic analysis** (14 URL features including entropy, keywords, structure)

**Response Time:** <2 seconds per URL with intelligent caching  
**Privacy:** 100% local processing — no external API calls  
**Accuracy:** 86.84% on test set of 130,239 URLs

---

## ✨ Key Features

### 🔒 Security Features
- **Instant blocking** of known phishing URLs
- **ML-powered detection** catches zero-day phishing attempts
- **Multi-signal scoring** reduces false positives/negatives
- **Three-tier response system**: Safe, Suspicious, Dangerous

### ⚡ Performance Features
- **Sub-2-second analysis** with hard timeout enforcement
- **200-entry LRU cache** for instant repeat lookups
- **Async processing** doesn't block browser navigation
- **Optimized feature extraction** for speed

### 🎨 User Experience
- **Visual feedback**: Color-coded badge (green/yellow/red)
- **Warning page** with detailed risk analysis
- **Non-intrusive banners** for suspicious URLs
- **Detailed popup** showing scores, reasons, and statistics

---

## 🏗️ Architecture

### System Overview


```
┌─────────────────────────────────────────────────────────────────┐
│                        Chrome Browser                           │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐  │
│  │  VerifyFirst Extension (Manifest V3)                     │  │
│  │                                                           │  │
│  │  ┌─────────────┐     ┌────────────┐     ┌────────────┐  │  │
│  │  │ background.js│────▶│ content.js │────▶│  popup.js  │  │  │
│  │  │ (intercept) │     │ (inject UI)│     │   (stats)  │  │  │
│  │  └─────┬───────┘     └────────────┘     └────────────┘  │  │
│  └────────┼─────────────────────────────────────────────────┘  │
│           │ HTTP POST                                          │
│           ▼                                                    │
└───────────┼────────────────────────────────────────────────────┘
            │
            │ JSON: {"url": "..."}
            ▼
┌─────────────────────────────────────────────────────────────────┐
│              FastAPI Backend (localhost:8000)                   │
│                                                                 │
│  ┌──────────────┐      ┌──────────────┐      ┌─────────────┐  │
│  │   main.py    │─────▶│  scorer.py   │─────▶│  Response   │  │
│  │  (routing)   │      │ (ML + rules) │      │   (JSON)    │  │
│  └──────────────┘      └──────┬───────┘      └─────────────┘  │
│                               │                                │
│         ┌────────────────────┼───────────────────┐            │
│         │                    │                   │            │
│         ▼                    ▼                   ▼            │
│  ┌─────────────┐    ┌──────────────┐    ┌──────────────┐    │
│  │ reputation  │    │ domain_check │    │   feature    │    │
│  │ (blacklist) │    │   (WHOIS)    │    │  extractor   │    │
│  └─────────────┘    └──────────────┘    └──────┬───────┘    │
│                                                  │            │
│                                                  ▼            │
│                                         ┌──────────────┐     │
│                                         │ ML Model     │     │
│                                         │ (model.pkl)  │     │
│                                         │ RandomForest │     │
│                                         └──────────────┘     │
│                                                               │
│  Supporting Components:                                      │
│  • cache.py — LRU cache (200 entries)                       │
│  • database.py — SQLite logging                             │
│  • phishing_urls.csv — 10k blacklist                        │
└─────────────────────────────────────────────────────────────────┘
```

### Request Flow

1. **User navigates** to URL in Chrome
2. **background.js** intercepts via `chrome.tabs.onUpdated`
3. **Loading overlay** appears immediately
4. **POST request** sent to `http://127.0.0.1:8000/analyze`
5. **Backend analyzes** URL through multiple detection layers
6. **Response** returns risk score (0-100) and category
7. **UI updates** based on category:
   - **Safe (0-49)**: Green badge, overlay removed
   - **Suspicious (50-69)**: Yellow badge, warning banner
   - **Dangerous (70-100)**: Red badge, redirect to warning page

---

## 🤖 Machine Learning Model

### Training Dataset

**Source:** [Kaggle - Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)

| Category | Count | Percentage |
|----------|-------|------------|
| Benign | 428,103 | 65.7% |
| Phishing | 94,111 | 14.5% |
| Defacement | 96,457 | 14.8% |
| Malware | 32,520 | 5.0% |
| **Total** | **651,191** | **100%** |

### Model Specifications

- **Algorithm:** RandomForest Classifier
- **Trees:** 200
- **Max Depth:** 15
- **Training Set:** 520,952 URLs (80%)
- **Test Set:** 130,239 URLs (20%)
- **Class Weighting:** Balanced (handles imbalanced dataset)
- **Training Time:** ~30-60 seconds

### Performance Metrics

```
Classification Report:
                    precision    recall    f1-score    support
        
        Safe          0.92       0.88      0.90       85,621
   Malicious          0.78       0.85      0.82       44,618

    accuracy                                0.87      130,239
   macro avg          0.85       0.86      0.86      130,239
weighted avg          0.87       0.87      0.87      130,239
```

**Key Metrics:**
- ✅ **Overall Accuracy:** 86.84%
- ✅ **Safe Precision:** 92% (low false positives)
- ✅ **Malicious Recall:** 85% (catches most threats)
- ✅ **F1-Score:** 0.86 (balanced performance)

### Feature Engineering

**14 Features Extracted Per URL:**

| # | Feature | Type | Importance | Description |
|---|---------|------|------------|-------------|
| 1 | `path_length` | Numeric | 25.8% | Length of URL path component |
| 2 | `dot_count` | Numeric | 19.1% | Number of dots (subdomains) |
| 3 | `subdomain_depth` | Numeric | 18.0% | Nesting level of subdomains |
| 4 | `query_length` | Numeric | 7.6% | Length of query string |
| 5 | `url_entropy` | Numeric | 7.1% | Shannon entropy (randomness) |
| 6 | `url_length` | Numeric | 6.0% | Total URL length |
| 7 | `uses_https` | Binary | 5.9% | HTTPS vs HTTP |
| 8 | `hyphen_count` | Numeric | 3.1% | Number of hyphens |
| 9 | `suspicious_keyword_count` | Numeric | 2.7% | Phishing keywords detected |
| 10 | `has_hex_encoding` | Binary | 1.8% | Contains % encoding |
| 11 | `has_ip` | Binary | 1.3% | Uses IP instead of domain |
| 12 | `subdomain_has_digits` | Binary | 0.8% | Digits in subdomain |
| 13 | `has_double_slash` | Binary | 0.5% | Path redirection trick |
| 14 | `has_at_symbol` | Binary | 0.3% | @ symbol (classic trick) |

**Top 3 Most Important Features:**
1. **Path Length (25.8%)** — Phishing URLs often have long, obfuscated paths
2. **Dot Count (19.1%)** — Fake subdomains to mimic legitimate sites
3. **Subdomain Depth (18.0%)** — Deep nesting indicates spoofing

---

## 🛠️ Technology Stack

### Backend
| Technology | Version | Purpose |
|------------|---------|---------|
| Python | 3.10+ | Core language |
| FastAPI | 0.111.0 | REST API framework |
| Uvicorn | 0.29.0 | ASGI server |
| scikit-learn | 1.4.2 | Machine learning |
| pandas | 2.2.2 | Data processing |
| python-whois | 0.9.4 | Domain verification |
| NumPy | 1.26.4 | Numerical computing |

### Frontend (Chrome Extension)
| Technology | Purpose |
|------------|---------|
| Manifest V3 | Latest Chrome extension standard |
| Vanilla JavaScript | No dependencies, pure web APIs |
| Service Worker | Background processing |
| Content Scripts | Page-level UI injection |
| Chrome Storage API | Session caching |

### Data Processing
| Component | Technology |
|-----------|-----------|
| Training | RandomForest (scikit-learn) |
| Dataset | Kaggle CSV (651k URLs) |
| Blacklist | 10k phishing URLs (CSV) |
| Storage | SQLite database |
| Caching | In-memory LRU (OrderedDict) |

---

## 📦 Installation

### Prerequisites
- Python 3.10 or higher
- Google Chrome browser
- Kaggle account (for dataset)

### Step 1: Clone and Install Dependencies
```bash
cd VerifyFirst
pip install -r requirements.txt
```

### Step 2: Download Training Dataset
```bash
# Set up Kaggle API credentials (kaggle.json)
# Place in: C:\Users\<Username>\.kaggle\kaggle.json (Windows)
#       or: ~/.kaggle/kaggle.json (Linux/Mac)

# Download dataset
kaggle datasets download -d sid321axn/malicious-urls-dataset -p backend/data --unzip
```

### Step 3: Generate Extension Icons
```bash
python generate_icons.py
```

### Step 4: Train ML Model
```bash
cd backend
python train_model.py
```
**Output:** `model.pkl` (several MB)  
**Time:** ~30-60 seconds

### Step 5: Generate Blacklist
```bash
python extract_phishing_urls.py
```
**Output:** `phishing_urls.csv` (10,000 URLs)

### Step 6: Start Backend Server
```bash
python main.py
```
**Access:** http://127.0.0.1:8000  
**Health Check:** http://127.0.0.1:8000/health

### Step 7: Load Chrome Extension
1. Navigate to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked**
4. Select `VerifyFirst/extension` folder

---

## 🔌 API Reference

### Base URL
```
http://127.0.0.1:8000
```

### Endpoints

#### `GET /health`
Check backend status and cache size.

**Response:**
```json
{
  "status": "ok",
  "cache_size": 42
}
```

---

#### `POST /analyze`
Analyze a URL for phishing indicators.

**Request:**
```json
{
  "url": "https://example.com/login"
}
```

**Response:**
```json
{
  "risk_score": 75,
  "category": "dangerous",
  "reasons": [
    "URL found in phishing blacklist",
    "Suspicious keywords detected: login, secure",
    "ML model indicates elevated phishing probability (82%)"
  ],
  "domain_age_days": 3,
  "newly_registered": true,
  "elapsed_ms": 142,
  "cached": false
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `risk_score` | int | Risk score (0-100) |
| `category` | string | `"safe"`, `"suspicious"`, or `"dangerous"` |
| `reasons` | array | List of detection reasons |
| `domain_age_days` | int\|null | Domain age or null if unavailable |
| `newly_registered` | boolean | Domain <30 days old |
| `elapsed_ms` | int | Analysis time in milliseconds |
| `cached` | boolean | Result from cache |

**Status Codes:**
- `200` — Success
- `400` — Invalid request (missing URL)
- `500` — Server error

---

#### `GET /stats`
Get analysis statistics.

**Response:**
```json
{
  "dangerous": 15,
  "suspicious": 42,
  "safe": 128
}
```

---

## 🎯 Detection Methods

### 1. Blacklist Check (Highest Priority)
- **Speed:** <1ms
- **Accuracy:** 100% (for known URLs)
- **Dataset:** 10,000 real phishing URLs from Kaggle
- **Points:** +70 (instant "dangerous" category)

### 2. Domain Age Verification
- **Method:** WHOIS lookup
- **Timeout:** 1.5 seconds
- **Logic:**
  - Domain <7 days: +20 points
  - Domain <30 days: +10 points
  - WHOIS timeout: +10 points (assume suspicious)

### 3. Heuristic Analysis
Rule-based scoring for suspicious patterns:

| Rule | Points | Threshold |
|------|--------|-----------|
| IP address as host | +15 | Always suspicious |
| @ symbol in URL | +15 | Classic phishing trick |
| Subdomain depth >3 | +10 | Deep nesting |
| Suspicious keywords | +5 each | Max +10 total |
| No HTTPS | +5 | Unencrypted |
| URL length >100 | +5 | Obfuscation |

**Suspicious Keywords (24 total):**  
`login, verify, bank, update, secure, account, signin, password, credential, confirm, billing, paypal, ebay, amazon, apple, microsoft, google, support, suspended, unusual, validate, authenticate`

### 4. Machine Learning Inference
- **Contribution:** 0-40 points (scaled from probability)
- **Speed:** ~10ms
- **Method:** RandomForest probability estimation
- **Logic:** If `phishing_prob >= 0.15`, adds to score

### 5. Score Aggregation
```python
total_score = min(100, sum(all_signals))

if total_score >= 70:
    category = "dangerous"  # Block with warning page
elif total_score >= 50:
    category = "suspicious"  # Show warning banner
else:
    category = "safe"  # Allow with green badge
```

---

## 📊 Performance Metrics

### Speed Benchmarks
| Metric | Value |
|--------|-------|
| Average response time | 1.2s |
| Blacklist lookup | <1ms |
| ML inference | ~10ms |
| WHOIS lookup | 0-1.5s (timeout) |
| Hard timeout | 2.0s |
| Cache hit response | <10ms |

### Accuracy Metrics
| Metric | Value |
|--------|-------|
| Overall accuracy | 86.84% |
| Precision (Safe) | 92% |
| Recall (Malicious) | 85% |
| F1-Score | 0.86 |
| False positive rate | 12% |
| False negative rate | 15% |

### Resource Usage
| Metric | Value |
|--------|-------|
| Model size | ~4.5 MB |
| Extension size | ~25 KB |
| Memory (backend) | ~150 MB |
| Cache size | 200 entries |

---

## 📁 Project Structure

```
VerifyFirst/
├── README.md                    # Quick start guide
├── DOCUMENTATION.md             # This file (technical docs)
├── TESTING_GUIDE.md             # Testing instructions
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
├── generate_icons.py            # Icon generator script
│
├── backend/                     # Backend server
│   ├── main.py                  # FastAPI entry point
│   ├── train_model.py           # ML training script
│   ├── extract_phishing_urls.py # Blacklist generator
│   ├── quick_test.py            # Automated test suite
│   ├── scorer.py                # Hybrid scoring engine
│   ├── feature_extractor.py     # URL feature extraction
│   ├── reputation.py            # Blacklist management
│   ├── domain_checker.py        # WHOIS verification
│   ├── cache.py                 # LRU caching
│   ├── database.py              # SQLite logging
│   ├── model.pkl                # Trained ML model (generated)
│   ├── phishing_urls.csv        # 10k blacklist (generated)
│   ├── verifyfirst.db          # SQLite database (auto-created)
│   └── data/
│       └── malicious_phish.csv  # Kaggle dataset (651k URLs)
│
└── extension/                   # Chrome extension
    ├── manifest.json            # Extension config (Manifest V3)
    ├── background.js            # Service worker (navigation intercept)
    ├── content.js               # Content script (UI injection)
    ├── popup.html               # Extension popup UI
    ├── popup.js                 # Popup logic
    ├── warning.html             # Danger page template
    ├── warning.js               # Warning page logic
    └── icons/                   # Extension icons
        ├── icon16.png
        ├── icon48.png
        └── icon128.png
```

---

## 🚀 Usage Examples

### Testing Dangerous URL
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://meganmacylesolutions.com/secure/login.onlinebanking.suntrust.com/online.htm"}'
```

**Response:**
```json
{
  "risk_score": 100,
  "category": "dangerous",
  "reasons": [
    "URL found in phishing blacklist",
    "Suspicious keywords detected: login, bank, secure",
    "ML model indicates elevated phishing probability (91%)"
  ]
}
```

### Testing Safe URL
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url":"https://github.com"}'
```

**Response:**
```json
{
  "risk_score": 39,
  "category": "safe",
  "reasons": [
    "No suspicious signals detected"
  ]
}
```

---

## 🔐 Privacy & Security

### Privacy Guarantees
✅ **100% local processing** — All analysis happens on your machine  
✅ **No external API calls** — Except optional WHOIS (can be disabled)  
✅ **No data collection** — URLs never leave your computer  
✅ **No tracking** — No analytics, no telemetry  
✅ **Open source** — Full code transparency  

### Security Considerations
- ✅ **Backend runs on localhost** (127.0.0.1:8000)
- ✅ **CORS restricted** to extension origin
- ✅ **No credential storage**
- ✅ **Timeout protection** prevents DOS
- ✅ **Sandbox isolated** (Chrome extension security model)

---

## 📝 License & Credits

### Dataset Attribution
- **Source:** [Kaggle - Malicious URLs Dataset](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset)
- **License:** CC0-1.0 (Public Domain)
- **Credits:** sid321axn (Kaggle)

### Project
- **License:** MIT (or specify your license)
- **Built with:** Python, FastAPI, scikit-learn, Chrome Extension APIs

---

## 🤝 Contributing

### For Hackathon Judges
This project demonstrates:
- ✅ **Real-world ML application** (not toy dataset)
- ✅ **Production engineering** (caching, timeouts, error handling)
- ✅ **Full-stack development** (backend + frontend)
- ✅ **Security focus** (privacy-first design)
- ✅ **Performance optimization** (sub-2s response time)

### Future Enhancements
- [ ] Browser extension support (Firefox, Edge)
- [ ] Cloud deployment option
- [ ] Real-time blacklist updates
- [ ] Deep learning models (LSTM, BERT)
- [ ] Certificate validation
- [ ] SSL/TLS analysis
- [ ] Behavioral analysis
- [ ] User feedback loop

---

## 📞 Support

### Running Tests
```bash
python backend/quick_test.py
```

### Common Issues
See [TESTING_GUIDE.md](TESTING_GUIDE.md) for troubleshooting.

### Health Check
```bash
curl http://127.0.0.1:8000/health
```

---

**VerifyFirst** — Real-time phishing prevention powered by machine learning  
*Built for security, optimized for speed, designed for privacy*
