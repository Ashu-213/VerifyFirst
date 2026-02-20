# VerifyFirst

Real-time phishing detection using ML trained on **651k real URLs**. Runs 100% locally, blocks malicious sites before they load.

**Stats:**
- ✅ 86.84% ML accuracy (RandomForest on Kaggle dataset)
- ✅ <2s analysis time
- ✅ 10k phishing URL blacklist
- ✅ Zero external API calls (privacy-first)

📖 **[Full Technical Documentation](DOCUMENTATION.md)** — Architecture, API, troubleshooting

---

## Quick Setup (5 minutes)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Setup Dataset Files

**Download the dataset from Kaggle:**

🔗 **Dataset:** https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

**Option 1: Download via Browser**
1. Visit the Kaggle dataset link above
2. Click **Download** (you may need to create a free Kaggle account)
3. Extract the downloaded zip file
4. Copy `malicious_phish.csv` to `backend/data/malicious_phish.csv`

**Option 2: Download via Kaggle CLI**
1. Get API key: https://www.kaggle.com/settings → API → Create Token
2. Place `kaggle.json` at: `C:\Users\<You>\.kaggle\kaggle.json` (Windows) or `~/.kaggle/` (Mac/Linux)
3. Run:
   ```bash
   kaggle datasets download -d sid321axn/malicious-urls-dataset -p backend/data --unzip
   ```

**Verify setup:**
```bash
# Should exist: backend/data/malicious_phish.csv (651k URLs)
```

### 3. Generate Icons, Blacklist & Train Model
```bash
python generate_icons.py
cd backend
python extract_phishing_urls.py
python train_model.py
```
*Creates phishing URL blacklist (10k URLs) and trains model (~60 seconds, 86.84% accuracy)*

### 4. Start Backend
```bash
python main.py
```
*Keep this running. Server: http://127.0.0.1:8000*

### 5. Load Chrome Extension
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** → Select `extension/` folder

### 6. Test It
- **Safe:** https://github.com, https://microsoft.com, https://google.com
- **Dangerous:** https://meganmacylesolutions.com/secure/login.onlinebanking.suntrust.com/online.htm  
- **Suspicious:** http://account-verify-secure.example.com/login, http://paypal-support-center.tk/verify

---

## How It Works

```
URL → Blacklist (10k phishing URLs)
    → Domain Age (WHOIS)
    → ML Model (14 features, RandomForest)
    → Heuristics (IP usage, keywords)
    → Score: 0-100

0-49:   Safe ✅
50-69:  Suspicious 🟡 (warning banner)
70-100: Dangerous 🔴 (blocked)
```

**Detection speed:** Cache hit <10ms | New URL ~1.2s avg

---

## Project Structure

```
backend/
├── main.py              FastAPI server
├── train_model.py       ML trainer (Kaggle dataset)
├── scorer.py            Multi-signal scoring
├── feature_extractor.py 14 URL features
├── domain_checker.py    WHOIS lookup
├── reputation.py        Blacklist manager
├── phishing_urls.csv    10k known phishing URLs
└── data/malicious_phish.csv  651k URLs from Kaggle

extension/
├── background.js        Navigation interceptor
├── content.js           UI injection
├── popup.html/js        Extension popup
├── warning.html/js      Block page
└── manifest.json        Chrome MV3 config
```

---

## Tech Stack

**Backend:** Python, FastAPI, scikit-learn, pandas  
**Frontend:** Chrome Extension (Manifest V3), Vanilla JS  
**Dataset:** [Kaggle Malicious URLs](https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset) (651k URLs, CC0 license)  
**ML Model:** RandomForest (200 trees, 86.84% accuracy)

---

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Backend offline | Run `python backend/main.py` |
| `model.pkl` not found | Run `python backend/train_model.py` |
| Dataset missing | Download from Kaggle (see step 2) |
| `phishing_urls.csv` not found | Run `python backend/extract_phishing_urls.py` |
| Extension not working | Check `chrome://extensions` for errors |

**See [DOCUMENTATION.md](DOCUMENTATION.md) for API reference, advanced config, and detailed guides.**
